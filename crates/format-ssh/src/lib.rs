//! SSH key analyzer for Tinkerspark.
//!
//! Handles OpenSSH public keys, OpenSSH private keys, and authorized_keys files.
//! Uses the `ssh-key` crate for parsing where possible, with manual fallback
//! for byte-range mapping.

use tinkerspark_core_analyze::{
    AnalysisNode, AnalysisReport, AnalyzeError, Analyzer, AnalyzerConfidence, FieldView,
};
use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::{ByteRange, DetectedKind, Diagnostic, FileHandle, NodeId, Severity};

pub struct SshAnalyzer;

impl Analyzer for SshAnalyzer {
    fn id(&self) -> &'static str {
        "ssh"
    }

    fn can_analyze(&self, handle: &FileHandle, _src: &dyn ByteSource) -> AnalyzerConfidence {
        match &handle.kind {
            DetectedKind::SshPrivateKey => AnalyzerConfidence::High,
            DetectedKind::SshPublicKey => AnalyzerConfidence::High,
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
        let text = String::from_utf8_lossy(&data);

        let mut root_nodes = Vec::new();
        let mut diagnostics = Vec::new();

        match &handle.kind {
            DetectedKind::SshPublicKey => match parse_public_key_line(&text, &data) {
                Ok(node) => root_nodes.push(node),
                Err(msg) => {
                    diagnostics.push(Diagnostic {
                        severity: Severity::Error,
                        message: msg,
                        range: Some(ByteRange::new(0, file_len)),
                    });
                }
            },
            DetectedKind::SshPrivateKey => match parse_private_key(&text, file_len) {
                Ok((node, mut diags)) => {
                    root_nodes.push(node);
                    diagnostics.append(&mut diags);
                }
                Err(msg) => {
                    diagnostics.push(Diagnostic {
                        severity: Severity::Error,
                        message: msg,
                        range: Some(ByteRange::new(0, file_len)),
                    });
                }
            },
            _ => {
                return Err(AnalyzeError::Unsupported);
            }
        }

        if root_nodes.is_empty() {
            return Err(AnalyzeError::Parse {
                message: "No SSH key data found".into(),
            });
        }

        Ok(AnalysisReport {
            analyzer_id: "ssh".into(),
            root_nodes,
            diagnostics,
        })
    }
}

/// Parse an SSH public key line: "algorithm base64-blob [comment]"
fn parse_public_key_line(text: &str, raw: &[u8]) -> Result<AnalysisNode, String> {
    let line = text.lines().next().unwrap_or("").trim();
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err("Invalid SSH public key: expected 'algorithm base64 [comment]'".into());
    }

    let algo = parts[0];
    let blob = parts[1];
    let comment = parts.get(2).unwrap_or(&"");

    // Try to get more info from ssh-key crate.
    let mut fields = vec![
        FieldView {
            name: "Algorithm".into(),
            value: algo.to_string(),
            range: Some(ByteRange::new(0, algo.len() as u64)),
        },
        FieldView {
            name: "Key Data (base64)".into(),
            value: format!("{} chars", blob.len()),
            range: byte_range_of_substring(raw, line.as_bytes(), blob.as_bytes()),
        },
    ];

    if !comment.is_empty() {
        fields.push(FieldView {
            name: "Comment".into(),
            value: comment.to_string(),
            range: byte_range_of_substring(raw, line.as_bytes(), comment.as_bytes()),
        });
    }

    // Try parsing with ssh-key for additional metadata.
    let mut key_diagnostics = Vec::new();
    match ssh_key::PublicKey::from_openssh(line) {
        Ok(pk) => {
            fields.push(FieldView {
                name: "Key Type".into(),
                value: pk.algorithm().as_str().to_string(),
                range: None,
            });
            fields.push(FieldView {
                name: "Fingerprint (SHA-256)".into(),
                value: pk.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                range: None,
            });
        }
        Err(e) => {
            key_diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                message: format!("ssh-key parse: {}", e),
                range: None,
            });
        }
    }

    Ok(AnalysisNode {
        id: NodeId::new(),
        label: format!("SSH Public Key ({})", algo),
        kind: "ssh_public_key".into(),
        range: ByteRange::new(0, line.len() as u64),
        children: Vec::new(),
        fields,
        diagnostics: key_diagnostics,
    })
}

/// Parse an OpenSSH private key (PEM-wrapped binary format).
fn parse_private_key(text: &str, file_len: u64) -> Result<(AnalysisNode, Vec<Diagnostic>), String> {
    let mut diagnostics = Vec::new();
    let mut fields = Vec::new();

    // Find PEM boundaries.
    let begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    let end = "-----END OPENSSH PRIVATE KEY-----";

    let begin_pos = text
        .find(begin)
        .ok_or("Missing BEGIN OPENSSH PRIVATE KEY marker")?;
    let end_pos = text
        .find(end)
        .ok_or("Missing END OPENSSH PRIVATE KEY marker")?;

    let header_end = begin_pos + begin.len();
    let base64_region = &text[header_end..end_pos];
    let base64_clean: String = base64_region
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    fields.push(FieldView {
        name: "Format".into(),
        value: "OpenSSH private key".into(),
        range: Some(ByteRange::new(begin_pos as u64, begin.len() as u64)),
    });
    fields.push(FieldView {
        name: "Encoded size".into(),
        value: format!("{} base64 chars", base64_clean.len()),
        range: None,
    });

    diagnostics.push(Diagnostic {
        severity: Severity::Info,
        message: "Private key detected. Internal structure parsing is byte-range mapped \
                  to the PEM wrapper."
            .into(),
        range: None,
    });

    // Try parsing with ssh-key for metadata.
    // NOTE: ssh-key::PrivateKey::from_openssh requires the key to not be encrypted,
    // or will fail. We handle both cases.
    match ssh_key::PrivateKey::from_openssh(text) {
        Ok(sk) => {
            fields.push(FieldView {
                name: "Algorithm".into(),
                value: sk.algorithm().as_str().to_string(),
                range: None,
            });
            fields.push(FieldView {
                name: "Public Key Fingerprint (SHA-256)".into(),
                value: sk.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                range: None,
            });
            if !sk.comment().is_empty() {
                fields.push(FieldView {
                    name: "Comment".into(),
                    value: sk.comment().to_string(),
                    range: None,
                });
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("encrypted") || msg.contains("passphrase") {
                fields.push(FieldView {
                    name: "Encrypted".into(),
                    value: "Yes (passphrase-protected)".into(),
                    range: None,
                });
                diagnostics.push(Diagnostic {
                    severity: Severity::Info,
                    message: "Key is encrypted; detailed fields require decryption".into(),
                    range: None,
                });
            } else {
                diagnostics.push(Diagnostic {
                    severity: Severity::Warning,
                    message: format!("Could not parse private key details: {}", e),
                    range: None,
                });
            }
        }
    }

    // TODO: Parse the binary format manually for byte-range mapping of
    // internal fields (cipher name, kdf, number of keys, public key section,
    // encrypted section). The OpenSSH private key binary format is:
    //   "openssh-key-v1\0" magic
    //   string ciphername
    //   string kdfname
    //   string kdfoptions
    //   uint32 number of keys
    //   string publickey1
    //   string encrypted_section
    // This is a follow-up task.

    Ok((
        AnalysisNode {
            id: NodeId::new(),
            label: "SSH Private Key".into(),
            kind: "ssh_private_key".into(),
            range: ByteRange::new(0, file_len),
            children: Vec::new(),
            fields,
            diagnostics: Vec::new(),
        },
        diagnostics,
    ))
}

/// Compute a byte range for a substring within a parent slice.
fn byte_range_of_substring(parent: &[u8], _line: &[u8], sub: &[u8]) -> Option<ByteRange> {
    let parent_start = parent.as_ptr() as usize;
    let sub_start = sub.as_ptr() as usize;
    if sub_start < parent_start {
        return None;
    }
    let offset = sub_start - parent_start;
    if offset + sub.len() > parent.len() {
        return None;
    }
    ByteRange::try_new(offset as u64, sub.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tinkerspark_core_bytes::MemoryByteSource;
    use tinkerspark_core_types::FileId;

    #[test]
    fn confidence_for_ssh_kinds() {
        let analyzer = SshAnalyzer;
        let src = MemoryByteSource::new(vec![0]);
        let handle = |kind| FileHandle {
            id: FileId::new(),
            path: PathBuf::from("key"),
            size: 1,
            kind,
        };
        assert_eq!(
            analyzer.can_analyze(&handle(DetectedKind::SshPublicKey), &src),
            AnalyzerConfidence::High
        );
        assert_eq!(
            analyzer.can_analyze(&handle(DetectedKind::SshPrivateKey), &src),
            AnalyzerConfidence::High
        );
        assert_eq!(
            analyzer.can_analyze(&handle(DetectedKind::Binary), &src),
            AnalyzerConfidence::None
        );
    }

    #[test]
    fn parses_public_key_line() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@host";
        let result = parse_public_key_line(key, key.as_bytes());
        assert!(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.kind, "ssh_public_key");
        assert!(node
            .fields
            .iter()
            .any(|f| f.name == "Algorithm" && f.value == "ssh-ed25519"));
    }
}
