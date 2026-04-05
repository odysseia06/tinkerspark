// format-openpgp: OpenPGP analyzer adapter.
//
// Uses Sequoia (pure-Rust crypto backend) for packet parsing and our own
// packet boundary walker for exact byte-range tracking.

mod boundary;
mod fields;

use sequoia_openpgp::armor;
use sequoia_openpgp::packet::Packet;
use sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};

use tinkerspark_core_analyze::{
    AnalysisNode, AnalysisReport, AnalyzeError, Analyzer, AnalyzerConfidence, FieldView,
};
use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::{ByteRange, DetectedKind, Diagnostic, FileHandle, NodeId, Severity};

/// OpenPGP analyzer backed by Sequoia.
pub struct OpenPgpAnalyzer;

impl Analyzer for OpenPgpAnalyzer {
    fn id(&self) -> &'static str {
        "openpgp"
    }

    fn can_analyze(&self, handle: &FileHandle, _src: &dyn ByteSource) -> AnalyzerConfidence {
        match &handle.kind {
            DetectedKind::OpenPgpArmored | DetectedKind::OpenPgpBinary => {
                AnalyzerConfidence::Medium
            }
            DetectedKind::OpenPgpByExtension => AnalyzerConfidence::Low,
            _ => AnalyzerConfidence::None,
        }
    }

    fn analyze(
        &self,
        handle: &FileHandle,
        src: &dyn ByteSource,
    ) -> Result<AnalysisReport, AnalyzeError> {
        let file_len = src.len();
        if file_len == 0 {
            return Ok(AnalysisReport {
                analyzer_id: self.id().to_string(),
                root_nodes: Vec::new(),
                diagnostics: vec![Diagnostic {
                    severity: Severity::Info,
                    message: "Empty file".to_string(),
                    range: None,
                }],
            });
        }

        let all_bytes = src.read_range(ByteRange::new(0, file_len))?;

        // Dearmor if needed to get binary OpenPGP data.
        let (binary_data, is_armored) = dearmor_if_needed(&all_bytes, &handle.kind);

        // Walk packet boundaries for exact byte ranges.
        let boundaries = boundary::walk_boundaries(&binary_data);

        // Parse with Sequoia for rich content. If Sequoia fails, fall back
        // to boundary-only analysis so we still show packet structure.
        let mut packets: Vec<Packet> = Vec::new();
        let mut diagnostics = Vec::new();

        match parse_with_sequoia(&binary_data) {
            Ok(parsed) => packets = parsed,
            Err(e) => {
                tracing::warn!(error = %e, "Sequoia parse failed, using boundary-only analysis");
                diagnostics.push(Diagnostic {
                    severity: Severity::Warning,
                    message: format!("Parser failed: {e}. Showing raw packet structure only."),
                    range: None,
                });
            }
        }

        // Build AnalysisNode tree by correlating parsed packets with boundaries.
        let node_count = boundaries.len().max(packets.len());
        let mut root_nodes = Vec::with_capacity(node_count);

        for i in 0..node_count {
            let boundary = boundaries.get(i);
            let packet = packets.get(i);

            let range = boundary
                .map(|b| ByteRange::new(b.offset, b.header_len + b.body_len))
                .unwrap_or(ByteRange::new(0, 0));

            let (tag_name, mut node_fields, node_diagnostics) = if let Some(pkt) = packet {
                let tag = format!("{}", pkt.tag());
                let fields = fields::extract_fields(pkt);
                let mut diags = Vec::new();

                if let Packet::Unknown(ref unk) = pkt {
                    diags.push(Diagnostic {
                        severity: Severity::Warning,
                        message: format!("Unknown packet tag: {}", unk.tag()),
                        range: Some(range),
                    });
                }

                (tag, fields, diags)
            } else {
                // Boundary-only: no Sequoia data.
                let tag = boundary
                    .map(|_| "Raw Packet".to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                (tag, Vec::new(), Vec::new())
            };

            let label = format!("Packet {}: {}", i + 1, tag_name);

            // Add byte range info as fields.
            if let Some(b) = boundary {
                if b.partial {
                    // Partial-body: framing and content are interleaved,
                    // so there's no contiguous header/body split.
                    node_fields.push(FieldView {
                        name: "Encoding".to_string(),
                        value: "partial body (streamed)".to_string(),
                        range: None,
                    });
                    node_fields.push(FieldView {
                        name: "Framing".to_string(),
                        value: format!("{} bytes", b.header_len),
                        range: None,
                    });
                    node_fields.push(FieldView {
                        name: "Content".to_string(),
                        value: format!("{} bytes", b.body_len),
                        range: None,
                    });
                } else {
                    node_fields.push(FieldView {
                        name: "Header".to_string(),
                        value: format!("{} bytes", b.header_len),
                        range: Some(ByteRange::new(b.offset, b.header_len)),
                    });
                    node_fields.push(FieldView {
                        name: "Body".to_string(),
                        value: format!("{} bytes", b.body_len),
                        range: Some(ByteRange::new(b.offset + b.header_len, b.body_len)),
                    });
                }
            }

            root_nodes.push(AnalysisNode {
                id: NodeId::new(),
                label,
                kind: tag_name,
                range,
                children: Vec::new(),
                fields: node_fields,
                diagnostics: node_diagnostics,
            });
        }

        if is_armored {
            diagnostics.push(Diagnostic {
                severity: Severity::Info,
                message: "File is ASCII-armored. Byte ranges refer to decoded binary content."
                    .to_string(),
                range: None,
            });
        }

        if root_nodes.is_empty() {
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                message: "No OpenPGP packets found.".to_string(),
                range: None,
            });
        }

        tracing::info!(
            packets = root_nodes.len(),
            armored = is_armored,
            "OpenPGP analysis complete"
        );

        Ok(AnalysisReport {
            analyzer_id: self.id().to_string(),
            root_nodes,
            diagnostics,
        })
    }
}

/// Parse binary OpenPGP data with Sequoia, returning top-level packets.
///
/// Uses `next()` (not `recurse()`) to stay at the top level, matching
/// the flat packet boundaries from our boundary walker.
fn parse_with_sequoia(data: &[u8]) -> Result<Vec<Packet>, String> {
    let mut packets = Vec::new();
    let mut ppr = PacketParser::from_bytes(data).map_err(|e| format!("init: {e}"))?;

    while let PacketParserResult::Some(mut pp) = ppr {
        pp.buffer_unread_content()
            .map_err(|e| format!("buffer: {e}"))?;
        let (packet, next_ppr) = pp.next().map_err(|e| format!("next: {e}"))?;
        packets.push(packet);
        ppr = next_ppr;
    }
    Ok(packets)
}

/// Dearmor the input if it's ASCII-armored, returning the binary data
/// and whether dearmoring was performed.
fn dearmor_if_needed(data: &[u8], kind: &DetectedKind) -> (Vec<u8>, bool) {
    if *kind == DetectedKind::OpenPgpArmored {
        match dearmor(data) {
            Ok(binary) => return (binary, true),
            Err(e) => {
                tracing::warn!(error = %e, "dearmor failed, trying as binary");
            }
        }
    }

    // Try as binary directly. If kind is Armored but dearmor failed,
    // fall through and try binary anyway.
    (data.to_vec(), false)
}

fn dearmor(data: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    use std::io::Read;
    let mut reader = armor::Reader::from_bytes(data, armor::ReaderMode::Tolerant(None));
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}
