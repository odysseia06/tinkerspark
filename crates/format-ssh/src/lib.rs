//! SSH key analyzer for Tinkerspark.
//!
//! Handles OpenSSH public keys and OpenSSH private keys.
//! Private keys are parsed at the binary level for precise byte-range mapping
//! of the `openssh-key-v1` container structure.

pub mod binary;

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

        let mut root_nodes = Vec::new();
        let mut diagnostics = Vec::new();

        match &handle.kind {
            DetectedKind::SshPublicKey => match parse_public_key_line(&data) {
                Ok(node) => root_nodes.push(node),
                Err(msg) => {
                    diagnostics.push(Diagnostic {
                        severity: Severity::Error,
                        message: msg,
                        range: Some(ByteRange::new(0, file_len)),
                    });
                }
            },
            DetectedKind::SshPrivateKey => match parse_private_key(&data, file_len) {
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

// ── Public key parsing ──────────────────────────────────────────────────

/// Parse an SSH public key line: "algorithm base64-blob [comment]"
fn parse_public_key_line(raw: &[u8]) -> Result<AnalysisNode, String> {
    let text = String::from_utf8_lossy(raw);
    let line = text.lines().next().unwrap_or("").trim();
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err("Invalid SSH public key: expected 'algorithm base64 [comment]'".into());
    }

    let algo = parts[0];
    let blob = parts[1];
    let comment = parts.get(2).unwrap_or(&"");

    let mut fields = vec![
        FieldView {
            name: "Algorithm".into(),
            value: algo.to_string(),
            range: Some(ByteRange::new(0, algo.len() as u64)),
        },
        FieldView {
            name: "Key Data (base64)".into(),
            value: format!("{} chars", blob.len()),
            range: byte_range_in(raw, blob.as_bytes()),
        },
    ];

    if !comment.is_empty() {
        fields.push(FieldView {
            name: "Comment".into(),
            value: comment.to_string(),
            range: byte_range_in(raw, comment.as_bytes()),
        });
    }

    // Use ssh-key crate for additional metadata.
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

// ── Private key parsing ─────────────────────────────────────────────────

/// Parse an OpenSSH private key, extracting the binary container structure.
fn parse_private_key(
    file_data: &[u8],
    file_len: u64,
) -> Result<(AnalysisNode, Vec<Diagnostic>), String> {
    let mut diagnostics = Vec::new();

    // Find PEM boundaries and decode base64 to get the binary blob.
    let (decoded, pem_begin_offset) = decode_pem_private_key(file_data)?;

    diagnostics.push(Diagnostic {
        severity: Severity::Info,
        message: "File is PEM-encoded. Byte ranges refer to the decoded binary content, \
                  not the original PEM text."
            .into(),
        range: None,
    });

    // Parse the binary container.
    let container = match binary::parse_container(&decoded) {
        Ok(c) => c,
        Err(e) => {
            return Err(format!("Failed to parse OpenSSH container: {}", e));
        }
    };

    let base = 0u64; // Byte ranges are relative to the decoded binary.
    let mut children = Vec::new();
    let mut root_fields = Vec::new();

    // Auth magic.
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: "Auth Magic".into(),
        kind: "ssh_magic".into(),
        range: container.auth_magic.to_range(base),
        children: Vec::new(),
        fields: vec![FieldView {
            name: "Value".into(),
            value: "openssh-key-v1\\0".into(),
            range: Some(container.auth_magic.to_range(base)),
        }],
        diagnostics: Vec::new(),
    });

    // Cipher name.
    let cipher_str = container
        .ciphername
        .as_str()
        .unwrap_or("<binary>")
        .to_string();
    children.push(make_string_node(
        "Cipher",
        "ssh_cipher",
        &container.ciphername,
        base,
    ));
    root_fields.push(FieldView {
        name: "Cipher".into(),
        value: cipher_str.clone(),
        range: Some(container.ciphername.value_span.to_range(base)),
    });

    // KDF name.
    let kdf_str = container.kdfname.as_str().unwrap_or("<binary>").to_string();
    children.push(make_string_node("KDF", "ssh_kdf", &container.kdfname, base));
    root_fields.push(FieldView {
        name: "KDF".into(),
        value: kdf_str,
        range: Some(container.kdfname.value_span.to_range(base)),
    });

    // KDF options.
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: format!("KDF Options ({} bytes)", container.kdfoptions.value.len()),
        kind: "ssh_kdfoptions".into(),
        range: container.kdfoptions.full_span.to_range(base),
        children: Vec::new(),
        fields: vec![FieldView {
            name: "Size".into(),
            value: format!("{} bytes", container.kdfoptions.value.len()),
            range: Some(container.kdfoptions.value_span.to_range(base)),
        }],
        diagnostics: Vec::new(),
    });

    // Key count.
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: format!("Key Count: {}", container.nkeys),
        kind: "ssh_nkeys".into(),
        range: container.nkeys_span.to_range(base),
        children: Vec::new(),
        fields: vec![FieldView {
            name: "Count".into(),
            value: container.nkeys.to_string(),
            range: Some(container.nkeys_span.to_range(base)),
        }],
        diagnostics: Vec::new(),
    });
    root_fields.push(FieldView {
        name: "Keys".into(),
        value: container.nkeys.to_string(),
        range: Some(container.nkeys_span.to_range(base)),
    });

    // Public key blobs.
    for (i, pk) in container.public_keys.iter().enumerate() {
        let mut pk_fields = vec![FieldView {
            name: "Size".into(),
            value: format!("{} bytes", pk.value.len()),
            range: Some(pk.value_span.to_range(base)),
        }];
        // Try to extract key type from the public key blob.
        if pk.value.len() >= 4 {
            let type_len =
                u32::from_be_bytes([pk.value[0], pk.value[1], pk.value[2], pk.value[3]]) as usize;
            if type_len <= pk.value.len() - 4 {
                if let Ok(kt) = std::str::from_utf8(&pk.value[4..4 + type_len]) {
                    pk_fields.push(FieldView {
                        name: "Key Type".into(),
                        value: kt.to_string(),
                        range: None,
                    });
                }
            }
        }
        children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("Public Key {}", i),
            kind: "ssh_public_key_blob".into(),
            range: pk.full_span.to_range(base),
            children: Vec::new(),
            fields: pk_fields,
            diagnostics: Vec::new(),
        });
    }

    // Private section.
    let priv_range = container.private_section.full_span.to_range(base);
    if container.is_encrypted {
        children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!(
                "Private Section (encrypted, {} bytes)",
                container.private_section.value.len()
            ),
            kind: "ssh_private_encrypted".into(),
            range: priv_range,
            children: Vec::new(),
            fields: vec![
                FieldView {
                    name: "Encrypted".into(),
                    value: "Yes".into(),
                    range: None,
                },
                FieldView {
                    name: "Cipher".into(),
                    value: cipher_str,
                    range: None,
                },
                FieldView {
                    name: "Size".into(),
                    value: format!("{} bytes", container.private_section.value.len()),
                    range: Some(container.private_section.value_span.to_range(base)),
                },
            ],
            diagnostics: vec![Diagnostic {
                severity: Severity::Info,
                message: "Private section is encrypted; internal fields require decryption".into(),
                range: Some(container.private_section.value_span.to_range(base)),
            }],
        });
        root_fields.push(FieldView {
            name: "Encrypted".into(),
            value: "Yes".into(),
            range: None,
        });
    } else {
        // Parse the unencrypted private section.
        let priv_children = parse_unencrypted_private_section(&container, base, &mut diagnostics);
        children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!(
                "Private Section (unencrypted, {} bytes)",
                container.private_section.value.len()
            ),
            kind: "ssh_private_unencrypted".into(),
            range: priv_range,
            children: priv_children,
            fields: vec![FieldView {
                name: "Encrypted".into(),
                value: "No".into(),
                range: None,
            }],
            diagnostics: Vec::new(),
        });
        root_fields.push(FieldView {
            name: "Encrypted".into(),
            value: "No".into(),
            range: None,
        });
    }

    // Try ssh-key crate for fingerprint on unencrypted keys.
    let file_text = String::from_utf8_lossy(file_data);
    match ssh_key::PrivateKey::from_openssh(&*file_text) {
        Ok(sk) => {
            root_fields.push(FieldView {
                name: "Algorithm".into(),
                value: sk.algorithm().as_str().to_string(),
                range: None,
            });
            root_fields.push(FieldView {
                name: "Fingerprint (SHA-256)".into(),
                value: sk.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                range: None,
            });
            if !sk.comment().is_empty() {
                root_fields.push(FieldView {
                    name: "Comment".into(),
                    value: sk.comment().to_string(),
                    range: None,
                });
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("encrypted") || msg.contains("passphrase") {
                // Already handled above.
            } else if !container.is_encrypted {
                diagnostics.push(Diagnostic {
                    severity: Severity::Warning,
                    message: format!("ssh-key metadata extraction: {}", e),
                    range: None,
                });
            }
        }
    }

    let _ = pem_begin_offset; // Reserved for future PEM offset mapping.

    Ok((
        AnalysisNode {
            id: NodeId::new(),
            label: "OpenSSH Private Key".into(),
            kind: "ssh_private_key".into(),
            range: ByteRange::new(0, file_len),
            children,
            fields: root_fields,
            diagnostics: Vec::new(),
        },
        diagnostics,
    ))
}

/// Parse the unencrypted private section into child nodes.
fn parse_unencrypted_private_section(
    container: &binary::ParsedContainer,
    base: u64,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<AnalysisNode> {
    let mut children = Vec::new();

    let section = match binary::parse_private_section(
        &container.private_section.value,
        container.nkeys,
        container.private_section.value_span.offset,
    ) {
        Ok(s) => s,
        Err(e) => {
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                message: format!("Failed to parse private section: {}", e),
                range: Some(container.private_section.value_span.to_range(base)),
            });
            return children;
        }
    };

    // Check ints.
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: format!("Check Int 1: 0x{:08X}", section.checkint1),
        kind: "ssh_checkint".into(),
        range: section.checkint1_span.to_range(base),
        children: Vec::new(),
        fields: vec![FieldView {
            name: "Value".into(),
            value: format!("0x{:08X}", section.checkint1),
            range: Some(section.checkint1_span.to_range(base)),
        }],
        diagnostics: Vec::new(),
    });
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: format!("Check Int 2: 0x{:08X}", section.checkint2),
        kind: "ssh_checkint".into(),
        range: section.checkint2_span.to_range(base),
        children: Vec::new(),
        fields: vec![FieldView {
            name: "Value".into(),
            value: format!("0x{:08X}", section.checkint2),
            range: Some(section.checkint2_span.to_range(base)),
        }],
        diagnostics: Vec::new(),
    });

    if !section.checkints_match {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "Check integers do not match (0x{:08X} != 0x{:08X}); data may be corrupt",
                section.checkint1, section.checkint2
            ),
            range: Some(section.checkint1_span.to_range(base)),
        });
    }

    if section.multi_key_limited {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message:
                "Parsing stopped before the end of a multi-key container; \
                      remaining keys were not parsed (unsupported algorithm in non-final position)."
                    .into(),
            range: section.unparsed_remainder.map(|s| s.to_range(base)),
        });
    }

    // Key entries.
    for (i, key) in section.keys.iter().enumerate() {
        let keytype_str = key.keytype.as_str().unwrap_or("<binary>").to_string();
        let comment_str = key.comment.as_str().unwrap_or("<binary>").to_string();

        let mut key_children = Vec::new();

        key_children.push(make_string_node(
            "Key Type",
            "ssh_keytype",
            &key.keytype,
            base,
        ));

        match &key.key_fields {
            binary::KeyFields::Ed25519 { pubkey, combined } => {
                key_children.push(AnalysisNode {
                    id: NodeId::new(),
                    label: format!("Public Key ({} bytes)", pubkey.value.len()),
                    kind: "ssh_ed25519_pubkey".into(),
                    range: pubkey.full_span.to_range(base),
                    children: Vec::new(),
                    fields: vec![FieldView {
                        name: "Size".into(),
                        value: format!("{} bytes", pubkey.value.len()),
                        range: Some(pubkey.value_span.to_range(base)),
                    }],
                    diagnostics: Vec::new(),
                });
                // The combined field is seed(32) || pubkey(32).
                // We expose it as one node but label the structure.
                let seed_len = combined.value.len().saturating_sub(pubkey.value.len());
                key_children.push(AnalysisNode {
                    id: NodeId::new(),
                    label: format!(
                        "Private Material ({} bytes: {} seed + {} pubkey)",
                        combined.value.len(),
                        seed_len,
                        pubkey.value.len()
                    ),
                    kind: "ssh_ed25519_private".into(),
                    range: combined.full_span.to_range(base),
                    children: Vec::new(),
                    fields: vec![
                        FieldView {
                            name: "Size".into(),
                            value: format!("{} bytes", combined.value.len()),
                            range: Some(combined.value_span.to_range(base)),
                        },
                        FieldView {
                            name: "Structure".into(),
                            value: format!(
                                "{}-byte seed || {}-byte public key copy",
                                seed_len,
                                pubkey.value.len()
                            ),
                            range: None,
                        },
                    ],
                    diagnostics: Vec::new(),
                });
            }
            binary::KeyFields::Opaque {
                data_span,
                algorithm,
            } => {
                if data_span.length > 0 {
                    key_children.push(AnalysisNode {
                        id: NodeId::new(),
                        label: format!("Key Data ({} bytes)", data_span.length),
                        kind: "ssh_key_data".into(),
                        range: data_span.to_range(base),
                        children: Vec::new(),
                        fields: vec![FieldView {
                            name: "Size".into(),
                            value: format!("{} bytes", data_span.length),
                            range: Some(data_span.to_range(base)),
                        }],
                        diagnostics: vec![Diagnostic {
                            severity: Severity::Info,
                            message: format!(
                                "Algorithm-specific field decoding not yet supported for {}",
                                algorithm
                            ),
                            range: None,
                        }],
                    });
                }
            }
        }

        key_children.push(make_string_node(
            "Comment",
            "ssh_comment",
            &key.comment,
            base,
        ));

        children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("Key {}: {} (\"{}\")", i, keytype_str, comment_str),
            kind: "ssh_private_key_entry".into(),
            range: key.full_span.to_range(base),
            children: key_children,
            fields: vec![
                FieldView {
                    name: "Algorithm".into(),
                    value: keytype_str,
                    range: Some(key.keytype.value_span.to_range(base)),
                },
                FieldView {
                    name: "Comment".into(),
                    value: comment_str,
                    range: Some(key.comment.value_span.to_range(base)),
                },
            ],
            diagnostics: Vec::new(),
        });
    }

    // Padding (only when all keys were parsed and remainder is validated padding).
    if let Some(pad) = section.padding_span {
        children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("Padding ({} bytes)", pad.length),
            kind: "ssh_padding".into(),
            range: pad.to_range(base),
            children: Vec::new(),
            fields: vec![FieldView {
                name: "Size".into(),
                value: format!("{} bytes", pad.length),
                range: Some(pad.to_range(base)),
            }],
            diagnostics: Vec::new(),
        });
    }

    // Unparsed remainder (when parsing stopped early on a multi-key container).
    if let Some(rem) = section.unparsed_remainder {
        children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("Unparsed Remainder ({} bytes)", rem.length),
            kind: "ssh_unparsed".into(),
            range: rem.to_range(base),
            children: Vec::new(),
            fields: vec![FieldView {
                name: "Size".into(),
                value: format!("{} bytes", rem.length),
                range: Some(rem.to_range(base)),
            }],
            diagnostics: vec![Diagnostic {
                severity: Severity::Info,
                message: "Contains undecoded key material from unsupported algorithms".into(),
                range: Some(rem.to_range(base)),
            }],
        });
    }

    children
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Decode the PEM-wrapped OpenSSH private key, returning the decoded binary
/// and the byte offset of the BEGIN marker in the original file.
fn decode_pem_private_key(file_data: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let text = std::str::from_utf8(file_data).map_err(|_| "File is not valid UTF-8")?;

    let begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    let end = "-----END OPENSSH PRIVATE KEY-----";

    let begin_pos = text
        .find(begin)
        .ok_or("Missing BEGIN OPENSSH PRIVATE KEY marker")?;
    let end_pos = text
        .find(end)
        .ok_or("Missing END OPENSSH PRIVATE KEY marker")?;

    let header_end = begin_pos + begin.len();
    let base64_text = &text[header_end..end_pos];
    let clean: String = base64_text.chars().filter(|c| !c.is_whitespace()).collect();

    let decoded = base64_decode(&clean).ok_or("Invalid base64 in private key")?;
    Ok((decoded, begin_pos))
}

/// Simple base64 decoder (standard alphabet with padding).
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for ch in input.bytes() {
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => continue,
            _ => return None,
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(result)
}

/// Build an AnalysisNode for a length-prefixed string field.
fn make_string_node(
    label: &str,
    kind: &str,
    field: &binary::StringField,
    base: u64,
) -> AnalysisNode {
    let display = field.as_str().unwrap_or("<binary>").to_string();
    AnalysisNode {
        id: NodeId::new(),
        label: format!("{}: \"{}\"", label, display),
        kind: kind.into(),
        range: field.full_span.to_range(base),
        children: Vec::new(),
        fields: vec![FieldView {
            name: label.into(),
            value: display,
            range: Some(field.value_span.to_range(base)),
        }],
        diagnostics: Vec::new(),
    }
}

/// Compute a byte range for a substring within a parent buffer.
fn byte_range_in(parent: &[u8], sub: &[u8]) -> Option<ByteRange> {
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
        let key = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@host";
        let result = parse_public_key_line(key);
        assert!(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.kind, "ssh_public_key");
        assert!(node
            .fields
            .iter()
            .any(|f| f.name == "Algorithm" && f.value == "ssh-ed25519"));
    }
}
