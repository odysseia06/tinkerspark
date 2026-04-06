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

/// Generic fallback analyzer that provides heuristic structural analysis
/// for any binary file.
///
/// Designed to run at the lowest confidence so that any dedicated analyzer
/// always wins. Produces suggested structure, never authoritative parsing.
pub struct GenericAnalyzer;

impl Analyzer for GenericAnalyzer {
    fn id(&self) -> &'static str {
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
            message: "Generic analysis produces suggested structure, not authoritative parsing."
                .into(),
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
        let all_strings = strings::extract_strings(&data, 0);
        if !all_strings.is_empty() {
            let groups = strings::group_strings(&all_strings, 32);
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
        let padding = chunks::detect_padding(&data, 0);
        let records = chunks::detect_fixed_records(&data, 0);
        let length_prefixed = chunks::detect_length_prefixed(&data, 0);

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
        let tlv_chains = tlv::detect_tlv_chains(&data, 0);
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

        // ── Pass 6: Confidence scoring ──
        let conf = confidence::compute_confidence(
            file_len,
            &signatures,
            &all_strings,
            &entropy_regions,
            &tlv_chains,
        );

        report_diagnostics.push(Diagnostic {
            severity: if conf.score > 0.4 {
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
        let analyzer = GenericAnalyzer;

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

        let report = GenericAnalyzer.analyze(&handle, &src).unwrap();

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

        let report = GenericAnalyzer.analyze(&handle, &src).unwrap();

        // Should find embedded strings.
        let str_node = report.root_nodes.iter().find(|n| n.kind == "strings");
        assert!(str_node.is_some(), "should have strings node");
    }

    #[test]
    fn confidence_diagnostic_present() {
        let data = vec![0x42; 128];
        let src = MemoryByteSource::new(data.clone());
        let handle = make_handle(DetectedKind::Binary, data.len() as u64);

        let report = GenericAnalyzer.analyze(&handle, &src).unwrap();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.message.contains("confidence")),
            "should include confidence diagnostic"
        );
    }
}
