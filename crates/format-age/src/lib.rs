//! age encryption format analyzer for Tinkerspark.
//!
//! Parses age encrypted files (header + recipient stanzas + payload boundary)
//! and age identity/key files. The age format is simple enough for manual parsing.
//!
//! Format reference: https://age-encryption.org/v1

use tinkerspark_core_analyze::{
    AnalysisNode, AnalysisReport, AnalyzeError, Analyzer, AnalyzerConfidence, FieldView,
};
use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::{ByteRange, DetectedKind, Diagnostic, FileHandle, NodeId, Severity};

pub struct AgeAnalyzer;

impl Analyzer for AgeAnalyzer {
    fn id(&self) -> &str {
        "age"
    }

    fn can_analyze(&self, handle: &FileHandle, _src: &dyn ByteSource) -> AnalyzerConfidence {
        match &handle.kind {
            DetectedKind::AgeEncrypted => AnalyzerConfidence::High,
            DetectedKind::AgeKey => AnalyzerConfidence::High,
            _ => AnalyzerConfidence::None,
        }
    }

    fn analyze(
        &self,
        handle: &FileHandle,
        src: &dyn ByteSource,
    ) -> Result<AnalysisReport, AnalyzeError> {
        let file_len = src.len();
        let data = src.read_range(ByteRange::new(0, file_len))?;

        match &handle.kind {
            DetectedKind::AgeEncrypted => parse_age_encrypted(&data, file_len),
            DetectedKind::AgeKey => parse_age_key(&data, file_len),
            _ => Err(AnalyzeError::Unsupported),
        }
    }
}

/// Parse an age-encrypted file header.
///
/// Format:
/// ```text
/// age-encryption.org/v1
/// -> X25519 <ephemeral-share>
/// <wrapped-key-base64>
/// -> scrypt <salt> <log-N>
/// <wrapped-key-base64>
/// --- <mac>
/// <binary payload>
/// ```
fn parse_age_encrypted(data: &[u8], file_len: u64) -> Result<AnalysisReport, AnalyzeError> {
    let text = String::from_utf8_lossy(data);
    let mut diagnostics = Vec::new();
    let mut children = Vec::new();

    // Find the header line.
    let first_line = text.lines().next().unwrap_or("");
    if !first_line.starts_with("age-encryption.org/") {
        return Err(AnalyzeError::Parse {
            message: "Missing age header line".into(),
        });
    }

    let version = first_line
        .strip_prefix("age-encryption.org/")
        .unwrap_or("unknown");

    let header_range = ByteRange::new(0, first_line.len() as u64);
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: format!("Header (version {})", version),
        kind: "age_header".into(),
        range: header_range,
        children: Vec::new(),
        fields: vec![FieldView {
            name: "Version".into(),
            value: version.to_string(),
            range: Some(header_range),
        }],
        diagnostics: Vec::new(),
    });

    // Parse recipient stanzas: lines starting with "-> "
    let mut offset = first_line.len() + 1; // +1 for newline
    let mut stanza_count = 0;
    let mut mac_offset = None;

    for line in text[offset.min(text.len())..].lines() {
        let line_len = line.len();
        let line_start = offset;

        if line.starts_with("-> ") {
            stanza_count += 1;
            let stanza_parts: Vec<&str> = line[3..].splitn(2, ' ').collect();
            let stanza_type = stanza_parts.first().unwrap_or(&"unknown");
            let stanza_args = stanza_parts.get(1).unwrap_or(&"");

            let mut stanza_fields = vec![FieldView {
                name: "Type".into(),
                value: stanza_type.to_string(),
                range: None,
            }];
            if !stanza_args.is_empty() {
                stanza_fields.push(FieldView {
                    name: "Arguments".into(),
                    value: stanza_args.to_string(),
                    range: None,
                });
            }

            children.push(AnalysisNode {
                id: NodeId::new(),
                label: format!("Recipient Stanza {}: {}", stanza_count, stanza_type),
                kind: "age_stanza".into(),
                range: ByteRange::new(line_start as u64, line_len as u64),
                children: Vec::new(),
                fields: stanza_fields,
                diagnostics: Vec::new(),
            });
        } else if line.starts_with("---") {
            // MAC / header terminator
            let mac = line.strip_prefix("--- ").unwrap_or("");
            mac_offset = Some(line_start);
            children.push(AnalysisNode {
                id: NodeId::new(),
                label: "Header MAC".into(),
                kind: "age_mac".into(),
                range: ByteRange::new(line_start as u64, line_len as u64),
                children: Vec::new(),
                fields: vec![FieldView {
                    name: "MAC".into(),
                    value: if mac.is_empty() {
                        "(empty)".into()
                    } else {
                        format!("{}...", &mac[..mac.len().min(32)])
                    },
                    range: Some(ByteRange::new(line_start as u64, line_len as u64)),
                }],
                diagnostics: Vec::new(),
            });
            offset += line_len + 1;
            break;
        }

        offset += line_len + 1;
    }

    // Payload: everything after the "---" line
    if let Some(_mac_off) = mac_offset {
        let payload_start = offset as u64;
        if payload_start < file_len {
            let payload_len = file_len - payload_start;
            children.push(AnalysisNode {
                id: NodeId::new(),
                label: format!("Encrypted Payload ({} bytes)", payload_len),
                kind: "age_payload".into(),
                range: ByteRange::new(payload_start, payload_len),
                children: Vec::new(),
                fields: vec![FieldView {
                    name: "Size".into(),
                    value: format!("{} bytes", payload_len),
                    range: Some(ByteRange::new(payload_start, payload_len)),
                }],
                diagnostics: Vec::new(),
            });
        }
    } else {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: "No header terminator (---) found; file may be truncated".into(),
            range: None,
        });
    }

    if stanza_count == 0 {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: "No recipient stanzas found in header".into(),
            range: None,
        });
    }

    Ok(AnalysisReport {
        analyzer_id: "age".into(),
        root_nodes: vec![AnalysisNode {
            id: NodeId::new(),
            label: format!("age Encrypted File ({} recipients)", stanza_count),
            kind: "age_encrypted".into(),
            range: ByteRange::new(0, file_len),
            children,
            fields: vec![
                FieldView {
                    name: "Version".into(),
                    value: version.to_string(),
                    range: None,
                },
                FieldView {
                    name: "Recipients".into(),
                    value: stanza_count.to_string(),
                    range: None,
                },
            ],
            diagnostics: Vec::new(),
        }],
        diagnostics,
    })
}

/// Parse an age identity/key file.
///
/// Format:
/// ```text
/// # created: 2024-01-01T00:00:00Z
/// # public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
/// AGE-SECRET-KEY-1QQQQQQQQQQQQQQ...
/// ```
fn parse_age_key(data: &[u8], file_len: u64) -> Result<AnalysisReport, AnalyzeError> {
    let text = String::from_utf8_lossy(data);
    let mut fields = Vec::new();
    let mut diagnostics = Vec::new();
    let mut children = Vec::new();

    let mut offset = 0usize;
    let mut key_found = false;

    for line in text.lines() {
        let line_start = offset;
        let line_len = line.len();

        if line.starts_with("# created:") {
            let created = line.strip_prefix("# created:").unwrap_or("").trim();
            fields.push(FieldView {
                name: "Created".into(),
                value: created.to_string(),
                range: Some(ByteRange::new(line_start as u64, line_len as u64)),
            });
        } else if line.starts_with("# public key:") {
            let pubkey = line.strip_prefix("# public key:").unwrap_or("").trim();
            fields.push(FieldView {
                name: "Public Key".into(),
                value: pubkey.to_string(),
                range: Some(ByteRange::new(line_start as u64, line_len as u64)),
            });
        } else if line.starts_with("AGE-SECRET-KEY-") {
            key_found = true;
            children.push(AnalysisNode {
                id: NodeId::new(),
                label: "Secret Key".into(),
                kind: "age_secret_key".into(),
                range: ByteRange::new(line_start as u64, line_len as u64),
                children: Vec::new(),
                fields: vec![
                    FieldView {
                        name: "Key".into(),
                        value: format!("AGE-SECRET-KEY-{}...", &line[15..line.len().min(20)]),
                        range: Some(ByteRange::new(line_start as u64, line_len as u64)),
                    },
                    FieldView {
                        name: "Length".into(),
                        value: format!("{} chars", line.len()),
                        range: None,
                    },
                ],
                diagnostics: Vec::new(),
            });
        } else if line.starts_with('#') {
            // Other comment line.
            children.push(AnalysisNode {
                id: NodeId::new(),
                label: format!("Comment: {}", &line[1..].trim()),
                kind: "age_comment".into(),
                range: ByteRange::new(line_start as u64, line_len as u64),
                children: Vec::new(),
                fields: Vec::new(),
                diagnostics: Vec::new(),
            });
        }

        offset += line_len + 1; // +1 for newline
    }

    if !key_found {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: "No AGE-SECRET-KEY- line found".into(),
            range: None,
        });
    }

    Ok(AnalysisReport {
        analyzer_id: "age".into(),
        root_nodes: vec![AnalysisNode {
            id: NodeId::new(),
            label: "age Identity Key".into(),
            kind: "age_key".into(),
            range: ByteRange::new(0, file_len),
            children,
            fields,
            diagnostics: Vec::new(),
        }],
        diagnostics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tinkerspark_core_bytes::MemoryByteSource;
    use tinkerspark_core_types::FileId;

    fn make_handle(kind: DetectedKind, size: u64) -> FileHandle {
        FileHandle {
            id: FileId::new(),
            path: PathBuf::from("test.age"),
            size,
            kind,
        }
    }

    #[test]
    fn parses_age_encrypted_header() {
        let data = b"age-encryption.org/v1\n\
            -> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KS1oULd30\n\
            SmhOQROry/AlmOQf7NBCvQ5JrdIqjfb2MCowjPoLMCU\n\
            --- Vn7F9DP6bJCYE7SKFYXG4gzNewGay5TT+aGLqPireS0\n\
            \x00\x01\x02\x03payload";
        let report = parse_age_encrypted(data, data.len() as u64).unwrap();
        assert_eq!(report.analyzer_id, "age");
        let root = &report.root_nodes[0];
        assert!(root.label.contains("1 recipients"));
        assert!(root.children.iter().any(|c| c.kind == "age_stanza"));
        assert!(root.children.iter().any(|c| c.kind == "age_payload"));
    }

    #[test]
    fn parses_age_key_file() {
        let data = b"# created: 2024-01-01T00:00:00Z\n\
            # public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n\
            AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n";
        let report = parse_age_key(data, data.len() as u64).unwrap();
        assert_eq!(report.analyzer_id, "age");
        let root = &report.root_nodes[0];
        assert!(root.fields.iter().any(|f| f.name == "Created"));
        assert!(root.fields.iter().any(|f| f.name == "Public Key"));
        assert!(root.children.iter().any(|c| c.kind == "age_secret_key"));
    }

    #[test]
    fn confidence_for_age_kinds() {
        let analyzer = AgeAnalyzer;
        let src = MemoryByteSource::new(vec![0]);
        let handle = |kind| FileHandle {
            id: FileId::new(),
            path: PathBuf::from("test"),
            size: 1,
            kind,
        };
        assert_eq!(
            analyzer.can_analyze(&handle(DetectedKind::AgeEncrypted), &src),
            AnalyzerConfidence::High
        );
        assert_eq!(
            analyzer.can_analyze(&handle(DetectedKind::AgeKey), &src),
            AnalyzerConfidence::High
        );
        assert_eq!(
            analyzer.can_analyze(&handle(DetectedKind::Binary), &src),
            AnalyzerConfidence::None
        );
    }
}
