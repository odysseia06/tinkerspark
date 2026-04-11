//! Generic fallback analyzer for unknown binary files.
//!
//! Runs a suite of heuristic passes (magic detection, string extraction,
//! entropy analysis, chunk detection, TLV detection) and produces suggested
//! structure. All output is advisory — never authoritative parsing.

pub mod chunks;
pub mod confidence;
pub mod entropy;
pub mod magic;
pub mod strings;
pub mod tlv;

use tinkerspark_core_analyze::{
    AnalysisNode, AnalysisReport, AnalyzeError, Analyzer, AnalyzerConfidence, FieldView,
};
use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::{ByteRange, Diagnostic, FileHandle, NodeId, Severity};

/// Maximum bytes to read for generic analysis (1 MiB).
const MAX_ANALYSIS_SIZE: u64 = 1024 * 1024;

/// User-selectable sensitivity for the generic analyzer.
///
/// Trades off between noise (false positives) and coverage (recall) when
/// inspecting unknown binary formats. Each variant maps to a different set of
/// thresholds for the underlying heuristic passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sensitivity {
    /// Stricter thresholds, fewer candidates, less noise. Best when you want
    /// only high-signal hits and are happy to miss weaker patterns.
    Conservative,
    /// Default thresholds — the historical out-of-the-box behavior.
    #[default]
    Balanced,
    /// Loosest thresholds, surfaces weaker candidates and shorter chains. Best
    /// for exploring genuinely unknown blobs where any signal helps.
    Aggressive,
}

impl Sensitivity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Conservative => "Conservative",
            Self::Balanced => "Balanced",
            Self::Aggressive => "Aggressive",
        }
    }

    /// Parse a label produced by [`Sensitivity::label`] back into a variant.
    /// Unknown labels fall back to [`Sensitivity::Balanced`] so persisted
    /// session data from older builds remains forward-compatible.
    pub fn from_label(s: &str) -> Self {
        match s {
            "Conservative" => Self::Conservative,
            "Aggressive" => Self::Aggressive,
            _ => Self::Balanced,
        }
    }

    /// All sensitivity variants in display order. Useful for UI iteration.
    pub fn all() -> [Self; 3] {
        [Self::Conservative, Self::Balanced, Self::Aggressive]
    }

    pub fn tunables(&self) -> Tunables {
        match self {
            Self::Conservative => Tunables {
                min_string_len: 6,
                max_strings: 100,
                string_group_gap: 16,
                min_padding_size: 16,
                min_record_count: 6,
                length_prefix_scan_window: 16,
                min_tlv_chain_len: 3,
                max_tlv_chains: 3,
                confidence_warn_threshold: 0.5,
                min_utf8_chars: 6,
                min_kv_pairs: 3,
                min_encoded_section_len: 32,
            },
            Self::Balanced => Tunables {
                min_string_len: 4,
                max_strings: 200,
                string_group_gap: 32,
                min_padding_size: 8,
                min_record_count: 4,
                length_prefix_scan_window: 64,
                min_tlv_chain_len: 2,
                max_tlv_chains: 5,
                confidence_warn_threshold: 0.4,
                min_utf8_chars: 4,
                min_kv_pairs: 2,
                min_encoded_section_len: 16,
            },
            Self::Aggressive => Tunables {
                min_string_len: 3,
                max_strings: 500,
                string_group_gap: 64,
                min_padding_size: 4,
                min_record_count: 3,
                length_prefix_scan_window: 128,
                min_tlv_chain_len: 2,
                max_tlv_chains: 10,
                confidence_warn_threshold: 0.3,
                min_utf8_chars: 3,
                min_kv_pairs: 1,
                min_encoded_section_len: 8,
            },
        }
    }
}

/// Concrete thresholds applied to a single analysis run.
///
/// Built from a [`Sensitivity`] level via [`Sensitivity::tunables`]. Stored
/// as plain fields rather than methods so the individual passes can read
/// exactly what they need without crossing module boundaries.
#[derive(Debug, Clone, Copy)]
pub struct Tunables {
    pub min_string_len: usize,
    pub max_strings: usize,
    pub string_group_gap: u64,
    pub min_padding_size: usize,
    pub min_record_count: usize,
    pub length_prefix_scan_window: usize,
    pub min_tlv_chain_len: usize,
    pub max_tlv_chains: usize,
    pub confidence_warn_threshold: f64,
    /// Minimum codepoint count for a UTF-8 string to be reported.
    pub min_utf8_chars: usize,
    /// Minimum number of detected key-value pairs needed to surface the
    /// "Key-Value Patterns" node. Below this, the noise isn't worth a node.
    pub min_kv_pairs: usize,
    /// Minimum character length for a string to qualify as a hex/base64
    /// encoded section.
    pub min_encoded_section_len: usize,
}

/// Generic fallback analyzer that provides heuristic structural analysis
/// for any binary file.
///
/// Designed to run at the lowest confidence so that any dedicated analyzer
/// always wins. Produces suggested structure, never authoritative parsing.
#[derive(Debug, Clone, Copy, Default)]
pub struct GenericAnalyzer {
    mode: Sensitivity,
}

impl GenericAnalyzer {
    /// Create a generic analyzer with the default ([`Sensitivity::Balanced`]) mode.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a generic analyzer pinned to a specific sensitivity mode.
    pub fn with_mode(mode: Sensitivity) -> Self {
        Self { mode }
    }

    pub fn mode(&self) -> Sensitivity {
        self.mode
    }
}

impl Analyzer for GenericAnalyzer {
    fn id(&self) -> &str {
        "generic"
    }

    fn can_analyze(&self, _handle: &FileHandle, _src: &dyn ByteSource) -> AnalyzerConfidence {
        // Always willing to analyze, but at the lowest possible confidence
        // so dedicated analyzers always take priority.
        AnalyzerConfidence::Low
    }

    fn analyze(
        &self,
        handle: &FileHandle,
        src: &dyn ByteSource,
    ) -> Result<AnalysisReport, AnalyzeError> {
        let tunables = self.mode.tunables();
        let file_len = src.len();
        let read_len = file_len.min(MAX_ANALYSIS_SIZE);
        let data = src.read_range(ByteRange::new(0, read_len))?;

        let mut root_nodes = Vec::new();
        let mut report_diagnostics = Vec::new();

        // Note if we're only analyzing a prefix.
        if read_len < file_len {
            report_diagnostics.push(Diagnostic {
                severity: Severity::Info,
                message: format!(
                    "Generic analysis covers first {} of {} bytes. \
                     Patterns beyond this range are not detected.",
                    format_size(read_len),
                    format_size(file_len),
                ),
                range: None,
            });
        }

        report_diagnostics.push(Diagnostic {
            severity: Severity::Info,
            message: format!(
                "Generic analysis produces suggested structure, not authoritative parsing \
                 (sensitivity: {}).",
                self.mode.label()
            ),
            range: None,
        });

        // ── Pass 1: Magic/signature detection ──
        let signatures = magic::detect_signatures(&data);
        if !signatures.is_empty() {
            let mut children = Vec::new();
            for sig in &signatures {
                children.push(AnalysisNode {
                    id: NodeId::new(),
                    label: format!("Signature: {}", sig.name),
                    kind: "signature".into(),
                    range: sig.range(),
                    children: Vec::new(),
                    fields: vec![
                        FieldView {
                            name: "Format".into(),
                            value: sig.name.to_string(),
                            range: Some(sig.range()),
                        },
                        FieldView {
                            name: "Offset".into(),
                            value: format!("0x{:X}", sig.offset),
                            range: Some(sig.range()),
                        },
                    ],
                    diagnostics: Vec::new(),
                });
            }
            root_nodes.push(AnalysisNode {
                id: NodeId::new(),
                label: format!("Detected Signatures ({})", signatures.len()),
                kind: "signatures".into(),
                range: ByteRange::new(0, read_len),
                children,
                fields: Vec::new(),
                diagnostics: Vec::new(),
            });
        }

        // ── Pass 2: String extraction ──
        let all_strings =
            strings::extract_strings(&data, 0, tunables.min_string_len, tunables.max_strings);
        if !all_strings.is_empty() {
            let groups = strings::group_strings(&all_strings, tunables.string_group_gap);
            let mut children = Vec::new();

            for (group_offset, group_length, indices) in &groups {
                let group_strings: Vec<&strings::StringRegion> =
                    indices.iter().map(|&i| &all_strings[i]).collect();
                let mut string_children = Vec::new();
                for s in &group_strings {
                    string_children.push(AnalysisNode {
                        id: NodeId::new(),
                        label: format!("\"{}\"", truncate_display(&s.content, 60)),
                        kind: "string".into(),
                        range: s.range(),
                        children: Vec::new(),
                        fields: vec![FieldView {
                            name: "Length".into(),
                            value: format!("{} bytes", s.length),
                            range: Some(s.range()),
                        }],
                        diagnostics: Vec::new(),
                    });
                }
                children.push(AnalysisNode {
                    id: NodeId::new(),
                    label: format!("String group ({} strings)", group_strings.len()),
                    kind: "string_group".into(),
                    range: ByteRange::new(*group_offset, *group_length),
                    children: string_children,
                    fields: Vec::new(),
                    diagnostics: Vec::new(),
                });
            }

            root_nodes.push(AnalysisNode {
                id: NodeId::new(),
                label: format!("Embedded Strings ({} found)", all_strings.len()),
                kind: "strings".into(),
                range: ByteRange::new(0, read_len),
                children,
                fields: vec![FieldView {
                    name: "Total strings".into(),
                    value: all_strings.len().to_string(),
                    range: None,
                }],
                diagnostics: Vec::new(),
            });
        }

        // ── Pass 2b: UTF-8 string extraction ──
        // Surfaces non-ASCII text runs that the byte-printable scanner above
        // misses (e.g. CJK, accented Latin, Cyrillic).
        let utf8_strings =
            strings::extract_utf8_strings(&data, 0, tunables.min_utf8_chars, tunables.max_strings);
        if !utf8_strings.is_empty() {
            let children: Vec<_> = utf8_strings
                .iter()
                .map(|s| AnalysisNode {
                    id: NodeId::new(),
                    label: format!("\"{}\"", truncate_display(&s.content, 60)),
                    kind: "utf8_string".into(),
                    range: s.range(),
                    children: Vec::new(),
                    fields: vec![FieldView {
                        name: "Bytes".into(),
                        value: format!("{} bytes", s.length),
                        range: Some(s.range()),
                    }],
                    diagnostics: Vec::new(),
                })
                .collect();
            root_nodes.push(AnalysisNode {
                id: NodeId::new(),
                label: format!("UTF-8 Strings ({} found)", utf8_strings.len()),
                kind: "utf8_strings".into(),
                range: ByteRange::new(0, read_len),
                children,
                fields: Vec::new(),
                diagnostics: Vec::new(),
            });
        }

        // ── Pass 3: Entropy analysis ──
        let entropy_regions = entropy::analyze_entropy(&data, 0);
        let overall_ent = entropy::overall_entropy(&data);
        if !entropy_regions.is_empty() {
            let mut children = Vec::new();
            for region in &entropy_regions {
                children.push(AnalysisNode {
                    id: NodeId::new(),
                    label: format!("Entropy: {:.2} ({})", region.entropy, region.class.label()),
                    kind: "entropy_region".into(),
                    range: region.range(),
                    children: Vec::new(),
                    fields: vec![
                        FieldView {
                            name: "Entropy".into(),
                            value: format!("{:.4}", region.entropy),
                            range: Some(region.range()),
                        },
                        FieldView {
                            name: "Classification".into(),
                            value: region.class.label().into(),
                            range: None,
                        },
                        FieldView {
                            name: "Size".into(),
                            value: format!("{} bytes", region.length),
                            range: Some(region.range()),
                        },
                    ],
                    diagnostics: Vec::new(),
                });
            }

            root_nodes.push(AnalysisNode {
                id: NodeId::new(),
                label: format!(
                    "Entropy Analysis ({} regions, overall {:.2})",
                    entropy_regions.len(),
                    overall_ent
                ),
                kind: "entropy".into(),
                range: ByteRange::new(0, read_len),
                children,
                fields: vec![
                    FieldView {
                        name: "Overall entropy".into(),
                        value: format!("{:.4}", overall_ent),
                        range: None,
                    },
                    FieldView {
                        name: "Regions".into(),
                        value: entropy_regions.len().to_string(),
                        range: None,
                    },
                ],
                diagnostics: Vec::new(),
            });
        }

        // ── Pass 4: Chunk/record detection ──
        let padding = chunks::detect_padding(&data, 0, tunables.min_padding_size);
        let records = chunks::detect_fixed_records(&data, 0, tunables.min_record_count);
        let length_prefixed =
            chunks::detect_length_prefixed(&data, 0, tunables.length_prefix_scan_window);

        let chunk_results: Vec<&chunks::DetectedChunk> = padding
            .iter()
            .chain(records.iter())
            .chain(length_prefixed.iter())
            .collect();

        if !chunk_results.is_empty() {
            let mut children = Vec::new();
            for chunk in &chunk_results {
                children.push(AnalysisNode {
                    id: NodeId::new(),
                    label: chunk.description.clone(),
                    kind: "chunk".into(),
                    range: chunk.range(),
                    children: Vec::new(),
                    fields: Vec::new(),
                    diagnostics: vec![Diagnostic {
                        severity: Severity::Info,
                        message: "Heuristic detection — may be coincidental".into(),
                        range: Some(chunk.range()),
                    }],
                });
            }
            root_nodes.push(AnalysisNode {
                id: NodeId::new(),
                label: format!(
                    "Chunk/Record Detection ({} candidates)",
                    chunk_results.len()
                ),
                kind: "chunks".into(),
                range: ByteRange::new(0, read_len),
                children,
                fields: Vec::new(),
                diagnostics: Vec::new(),
            });
        }

        // ── Pass 5: TLV detection ──
        let tlv_chains = tlv::detect_tlv_chains(
            &data,
            0,
            tunables.min_tlv_chain_len,
            tunables.max_tlv_chains,
        );
        if !tlv_chains.is_empty() {
            let mut children = Vec::new();
            for chain in &tlv_chains {
                let mut elem_children = Vec::new();
                for (i, elem) in chain.elements.iter().enumerate().take(20) {
                    elem_children.push(AnalysisNode {
                        id: NodeId::new(),
                        label: format!(
                            "Element {}: tag=0x{:02X}, {} bytes",
                            i, elem.tag, elem.value_len
                        ),
                        kind: "tlv_element".into(),
                        range: elem.range(),
                        children: Vec::new(),
                        fields: vec![
                            FieldView {
                                name: "Tag".into(),
                                value: format!("0x{:02X}", elem.tag),
                                range: Some(ByteRange::new(elem.offset, elem.tag_len)),
                            },
                            FieldView {
                                name: "Value length".into(),
                                value: format!("{} bytes", elem.value_len),
                                range: None,
                            },
                        ],
                        diagnostics: Vec::new(),
                    });
                }
                if chain.elements.len() > 20 {
                    elem_children.push(AnalysisNode {
                        id: NodeId::new(),
                        label: format!("... and {} more elements", chain.elements.len() - 20),
                        kind: "tlv_overflow".into(),
                        range: chain.range(),
                        children: Vec::new(),
                        fields: Vec::new(),
                        diagnostics: Vec::new(),
                    });
                }

                children.push(AnalysisNode {
                    id: NodeId::new(),
                    label: format!(
                        "TLV Chain: {} ({} elements, confidence {:.0}%)",
                        chain.encoding.label(),
                        chain.elements.len(),
                        chain.confidence * 100.0
                    ),
                    kind: "tlv_chain".into(),
                    range: chain.range(),
                    children: elem_children,
                    fields: vec![
                        FieldView {
                            name: "Encoding".into(),
                            value: chain.encoding.label().into(),
                            range: None,
                        },
                        FieldView {
                            name: "Elements".into(),
                            value: chain.elements.len().to_string(),
                            range: None,
                        },
                        FieldView {
                            name: "Confidence".into(),
                            value: format!("{:.1}%", chain.confidence * 100.0),
                            range: None,
                        },
                    ],
                    diagnostics: vec![Diagnostic {
                        severity: Severity::Info,
                        message: "Possible TLV chain — structure is speculative".into(),
                        range: Some(chain.range()),
                    }],
                });
            }
            root_nodes.push(AnalysisNode {
                id: NodeId::new(),
                label: format!("TLV Detection ({} chains)", tlv_chains.len()),
                kind: "tlv".into(),
                range: ByteRange::new(0, read_len),
                children,
                fields: Vec::new(),
                diagnostics: Vec::new(),
            });
        }

        // ── Pass 5b: Key-value text patterns ──
        // Pulls structured `key=value` / `key: value` lines out of the
        // ASCII-extracted strings. Only emits a node when the count clears
        // the per-mode threshold so single accidental matches stay quiet.
        let kv_pairs = strings::detect_key_value_pairs(&all_strings);
        if kv_pairs.len() >= tunables.min_kv_pairs {
            let children: Vec<_> = kv_pairs
                .iter()
                .map(|p| AnalysisNode {
                    id: NodeId::new(),
                    label: format!("{} = {}", p.key, truncate_display(&p.value, 60)),
                    kind: "kv_pair".into(),
                    range: p.range(),
                    children: Vec::new(),
                    fields: vec![
                        FieldView {
                            name: "Key".into(),
                            value: p.key.clone(),
                            range: Some(p.range()),
                        },
                        FieldView {
                            name: "Value".into(),
                            value: truncate_display(&p.value, 120),
                            range: Some(p.range()),
                        },
                    ],
                    diagnostics: Vec::new(),
                })
                .collect();
            root_nodes.push(AnalysisNode {
                id: NodeId::new(),
                label: format!("Key-Value Patterns ({} pairs)", kv_pairs.len()),
                kind: "kv_pairs".into(),
                range: ByteRange::new(0, read_len),
                children,
                fields: Vec::new(),
                diagnostics: vec![Diagnostic {
                    severity: Severity::Info,
                    message: "Heuristic key=value / key: value detection".into(),
                    range: None,
                }],
            });
        }

        // ── Pass 5c: Encoded sections (hex / base64) ──
        // Validate against the full byte run (not the cached content prefix)
        // so very long mixed-content runs whose suffix is not actually
        // encoded don't get over-claimed.
        let encoded_sections = strings::detect_encoded_sections(
            &all_strings,
            &data,
            0,
            tunables.min_encoded_section_len,
        );
        if !encoded_sections.is_empty() {
            let children: Vec<_> = encoded_sections
                .iter()
                .map(|sec| AnalysisNode {
                    id: NodeId::new(),
                    label: format!(
                        "{}: \"{}\"",
                        sec.kind.label(),
                        truncate_display(&sec.preview, 60)
                    ),
                    kind: "encoded_section".into(),
                    range: sec.range(),
                    children: Vec::new(),
                    fields: vec![
                        FieldView {
                            name: "Encoding".into(),
                            value: sec.kind.label().into(),
                            range: None,
                        },
                        FieldView {
                            name: "Length".into(),
                            value: format!("{} bytes", sec.length),
                            range: Some(sec.range()),
                        },
                    ],
                    diagnostics: Vec::new(),
                })
                .collect();
            root_nodes.push(AnalysisNode {
                id: NodeId::new(),
                label: format!("Encoded Sections ({} found)", encoded_sections.len()),
                kind: "encoded_sections".into(),
                range: ByteRange::new(0, read_len),
                children,
                fields: Vec::new(),
                diagnostics: vec![Diagnostic {
                    severity: Severity::Info,
                    message: "Heuristic hex / base64 classification — may be coincidental".into(),
                    range: None,
                }],
            });
        }

        // ── Pass 6: Confidence scoring ──
        let conf = confidence::compute_confidence(
            file_len,
            &signatures,
            &all_strings,
            &entropy_regions,
            &tlv_chains,
        );

        report_diagnostics.push(Diagnostic {
            severity: if conf.score > tunables.confidence_warn_threshold {
                Severity::Info
            } else {
                Severity::Warning
            },
            message: format!(
                "Overall confidence: {:.0}% — {}",
                conf.score * 100.0,
                conf.summary
            ),
            range: None,
        });

        // Add confidence summary as a top-level node.
        let mut conf_fields: Vec<FieldView> = vec![FieldView {
            name: "Score".into(),
            value: format!("{:.1}%", conf.score * 100.0),
            range: None,
        }];
        for ev in &conf.evidence {
            conf_fields.push(FieldView {
                name: ev.source.into(),
                value: ev.description.clone(),
                range: None,
            });
        }

        root_nodes.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("Confidence Summary ({:.0}%)", conf.score * 100.0),
            kind: "confidence".into(),
            range: ByteRange::new(0, file_len.min(read_len)),
            children: Vec::new(),
            fields: conf_fields,
            diagnostics: Vec::new(),
        });

        // Add file overview fields.
        let mut overview_fields = vec![
            FieldView {
                name: "File size".into(),
                value: format!("{} bytes ({})", file_len, format_size(file_len)),
                range: None,
            },
            FieldView {
                name: "Detected kind".into(),
                value: handle.kind.to_string(),
                range: None,
            },
            FieldView {
                name: "Sensitivity".into(),
                value: self.mode.label().into(),
                range: None,
            },
            FieldView {
                name: "Overall entropy".into(),
                value: format!("{:.4} bits/byte", overall_ent),
                range: None,
            },
        ];
        if !signatures.is_empty() {
            overview_fields.push(FieldView {
                name: "Signatures".into(),
                value: signatures
                    .iter()
                    .map(|s| s.name)
                    .collect::<Vec<_>>()
                    .join(", "),
                range: None,
            });
        }

        root_nodes.insert(
            0,
            AnalysisNode {
                id: NodeId::new(),
                label: "File Overview".into(),
                kind: "overview".into(),
                range: ByteRange::new(0, file_len.min(read_len)),
                children: Vec::new(),
                fields: overview_fields,
                diagnostics: Vec::new(),
            },
        );

        Ok(AnalysisReport {
            analyzer_id: "generic".into(),
            root_nodes,
            diagnostics: report_diagnostics,
        })
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn truncate_display(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tinkerspark_core_bytes::MemoryByteSource;
    use tinkerspark_core_types::{DetectedKind, FileId};

    fn make_handle(kind: DetectedKind, size: u64) -> FileHandle {
        FileHandle {
            id: FileId::new(),
            path: PathBuf::from("test.bin"),
            size,
            kind,
        }
    }

    #[test]
    fn analyzes_empty_ish_binary() {
        let data = vec![0x00; 64];
        let src = MemoryByteSource::new(data.clone());
        let handle = make_handle(DetectedKind::Binary, data.len() as u64);
        let analyzer = GenericAnalyzer::new();

        assert_eq!(analyzer.can_analyze(&handle, &src), AnalyzerConfidence::Low);

        let report = analyzer.analyze(&handle, &src).unwrap();
        assert_eq!(report.analyzer_id, "generic");
        assert!(
            !report.root_nodes.is_empty(),
            "should produce at least overview node"
        );

        // Should have overview node.
        assert_eq!(report.root_nodes[0].kind, "overview");
    }

    #[test]
    fn analyzes_png_header() {
        let mut data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR".to_vec();
        data.extend(vec![0xFF; 100]); // fake image data
        let src = MemoryByteSource::new(data.clone());
        let handle = make_handle(DetectedKind::Binary, data.len() as u64);

        let report = GenericAnalyzer::new().analyze(&handle, &src).unwrap();

        // Should detect PNG signature.
        let sig_node = report.root_nodes.iter().find(|n| n.kind == "signatures");
        assert!(sig_node.is_some(), "should have signatures node");
        let sig_node = sig_node.unwrap();
        assert!(
            sig_node.children.iter().any(|c| c.label.contains("PNG")),
            "should detect PNG signature"
        );
    }

    #[test]
    fn analyzes_text_file() {
        let data = b"Hello World! This is a test file with some text content.\n\
                     Another line of text here for the string extraction.\n";
        let src = MemoryByteSource::new(data.to_vec());
        let handle = make_handle(DetectedKind::Text, data.len() as u64);

        let report = GenericAnalyzer::new().analyze(&handle, &src).unwrap();

        // Should find embedded strings.
        let str_node = report.root_nodes.iter().find(|n| n.kind == "strings");
        assert!(str_node.is_some(), "should have strings node");
    }

    #[test]
    fn confidence_diagnostic_present() {
        let data = vec![0x42; 128];
        let src = MemoryByteSource::new(data.clone());
        let handle = make_handle(DetectedKind::Binary, data.len() as u64);

        let report = GenericAnalyzer::new().analyze(&handle, &src).unwrap();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.message.contains("confidence")),
            "should include confidence diagnostic"
        );
    }

    /// Build a small synthetic blob designed to expose differences between
    /// sensitivity modes. The TLV chain must lead the buffer because the TLV
    /// detector only parses from offset 0; the short string and short padding
    /// region come after, separated by non-printable / non-padding bytes so
    /// the runs stay isolated.
    fn mixed_signal_blob() -> Vec<u8> {
        let mut data = Vec::new();
        // Two consecutive ASN.1 SEQUENCEs at offset 0 — Balanced/Aggressive
        // (min_chain_len=2) accept; Conservative (min_chain_len=3) rejects.
        data.extend_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x2A]);
        data.extend_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x2B]);
        // Non-printable, non-padding separator so the next run starts fresh.
        data.push(0xFE);
        // 3-char string — only Aggressive (min_string_len=3) accepts it.
        data.extend_from_slice(b"abc");
        data.push(0xFE);
        // 5-byte zero padding — only Aggressive (min_padding_size=4) accepts it.
        data.extend_from_slice(&[0x00; 5]);
        data
    }

    fn count_kind(report: &AnalysisReport, kind: &str) -> usize {
        report.root_nodes.iter().filter(|n| n.kind == kind).count()
    }

    #[test]
    fn sensitivity_modes_produce_distinct_output() {
        let data = mixed_signal_blob();
        let src = MemoryByteSource::new(data.clone());
        let handle = make_handle(DetectedKind::Binary, data.len() as u64);

        let conservative = GenericAnalyzer::with_mode(Sensitivity::Conservative)
            .analyze(&handle, &src)
            .unwrap();
        let balanced = GenericAnalyzer::with_mode(Sensitivity::Balanced)
            .analyze(&handle, &src)
            .unwrap();
        let aggressive = GenericAnalyzer::with_mode(Sensitivity::Aggressive)
            .analyze(&handle, &src)
            .unwrap();

        // Conservative rejects the 2-element TLV chain (min_tlv_chain_len=3),
        // the 5-byte padding (min_padding_size=16), and the 3-char string
        // (min_string_len=6).
        assert_eq!(count_kind(&conservative, "tlv"), 0);
        assert_eq!(count_kind(&conservative, "strings"), 0);

        // Balanced accepts the 2-element chain but still rejects the short
        // string and short padding.
        assert_eq!(count_kind(&balanced, "tlv"), 1);
        assert_eq!(count_kind(&balanced, "strings"), 0);

        // Aggressive accepts everything: chain, short string, short padding.
        assert_eq!(count_kind(&aggressive, "tlv"), 1);
        assert_eq!(count_kind(&aggressive, "strings"), 1);
        assert!(
            count_kind(&aggressive, "chunks") >= 1,
            "aggressive should pick up the 5-byte zero run as a chunk"
        );
    }

    #[test]
    fn sensitivity_mode_is_surfaced_in_overview_and_diagnostics() {
        let data = vec![0x42; 64];
        let src = MemoryByteSource::new(data.clone());
        let handle = make_handle(DetectedKind::Binary, data.len() as u64);

        let report = GenericAnalyzer::with_mode(Sensitivity::Aggressive)
            .analyze(&handle, &src)
            .unwrap();

        let overview = report
            .root_nodes
            .iter()
            .find(|n| n.kind == "overview")
            .expect("overview node");
        let mode_field = overview
            .fields
            .iter()
            .find(|f| f.name == "Sensitivity")
            .expect("Sensitivity field on overview");
        assert_eq!(mode_field.value, "Aggressive");

        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.message.contains("sensitivity: Aggressive")),
            "diagnostic line should name the active sensitivity"
        );
    }

    #[test]
    fn default_mode_is_balanced() {
        assert_eq!(GenericAnalyzer::new().mode(), Sensitivity::Balanced);
        assert_eq!(GenericAnalyzer::default().mode(), Sensitivity::Balanced);
    }
}
