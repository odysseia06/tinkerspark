//! JWK/JWT/JWS analyzer for Tinkerspark.
//!
//! Handles:
//! - JWK (JSON Web Key): JSON objects with "kty" field
//! - JWT (JSON Web Token): compact serialization (header.payload.signature)
//! - JWS (JSON Web Signature): same compact format as JWT
//!
//! Uses `serde_json` for JSON parsing and `base64` for base64url decoding.

use tinkerspark_core_analyze::{
    AnalysisNode, AnalysisReport, AnalyzeError, Analyzer, AnalyzerConfidence, FieldView,
};
use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::{ByteRange, DetectedKind, Diagnostic, FileHandle, NodeId, Severity};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

pub struct JwkAnalyzer;

impl Analyzer for JwkAnalyzer {
    fn id(&self) -> &'static str {
        "jwk"
    }

    fn can_analyze(&self, handle: &FileHandle, _src: &dyn ByteSource) -> AnalyzerConfidence {
        match &handle.kind {
            DetectedKind::JsonWebKey => AnalyzerConfidence::High,
            DetectedKind::JsonWebToken => AnalyzerConfidence::High,
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
        let text = text.trim();

        match &handle.kind {
            DetectedKind::JsonWebToken => parse_jwt(text, file_len),
            DetectedKind::JsonWebKey => parse_jwk(text, file_len),
            _ => Err(AnalyzeError::Unsupported),
        }
    }
}

/// Parse a JWT/JWS in compact serialization: header.payload.signature
fn parse_jwt(text: &str, file_len: u64) -> Result<AnalysisReport, AnalyzeError> {
    let parts: Vec<&str> = text.splitn(4, '.').collect();
    if parts.len() < 3 {
        return Err(AnalyzeError::Parse {
            message: format!("Expected 3 dot-separated parts, found {}", parts.len()),
        });
    }

    let mut diagnostics = Vec::new();
    let mut children = Vec::new();

    // Track byte offsets for each part.
    let mut offset = 0u64;

    // ── Header ──
    let header_raw = parts[0];
    let header_range = ByteRange::new(offset, header_raw.len() as u64);
    offset += header_raw.len() as u64 + 1; // +1 for dot

    let header_node = match decode_jwt_part(header_raw, "Header", header_range) {
        Ok(node) => node,
        Err(msg) => {
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                message: format!("Header decode failed: {}", msg),
                range: Some(header_range),
            });
            AnalysisNode {
                id: NodeId::new(),
                label: "Header (decode failed)".into(),
                kind: "jwt_header".into(),
                range: header_range,
                children: Vec::new(),
                fields: vec![FieldView {
                    name: "Raw (base64url)".into(),
                    value: truncate(header_raw, 80),
                    range: Some(header_range),
                }],
                diagnostics: Vec::new(),
            }
        }
    };
    children.push(header_node);

    // ── Payload ��─
    let payload_raw = parts[1];
    let payload_range = ByteRange::new(offset, payload_raw.len() as u64);
    offset += payload_raw.len() as u64 + 1;

    let payload_node = match decode_jwt_part(payload_raw, "Payload", payload_range) {
        Ok(node) => node,
        Err(msg) => {
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                message: format!("Payload decode failed: {}", msg),
                range: Some(payload_range),
            });
            AnalysisNode {
                id: NodeId::new(),
                label: "Payload (decode failed)".into(),
                kind: "jwt_payload".into(),
                range: payload_range,
                children: Vec::new(),
                fields: vec![FieldView {
                    name: "Raw (base64url)".into(),
                    value: truncate(payload_raw, 80),
                    range: Some(payload_range),
                }],
                diagnostics: Vec::new(),
            }
        }
    };
    children.push(payload_node);

    // ── Signature ──
    let sig_raw = parts[2];
    let sig_range = ByteRange::new(offset, sig_raw.len() as u64);

    let sig_decoded_len = URL_SAFE_NO_PAD
        .decode(sig_raw)
        .map(|v| v.len())
        .unwrap_or(0);

    children.push(AnalysisNode {
        id: NodeId::new(),
        label: "Signature".into(),
        kind: "jwt_signature".into(),
        range: sig_range,
        children: Vec::new(),
        fields: vec![
            FieldView {
                name: "Encoded size".into(),
                value: format!("{} chars", sig_raw.len()),
                range: Some(sig_range),
            },
            FieldView {
                name: "Decoded size".into(),
                value: format!("{} bytes", sig_decoded_len),
                range: None,
            },
        ],
        diagnostics: Vec::new(),
    });

    // Extract algorithm from header if available.
    let mut root_fields = Vec::new();
    if let Ok(decoded) = URL_SAFE_NO_PAD.decode(header_raw) {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&decoded) {
            if let Some(alg) = json.get("alg").and_then(|v| v.as_str()) {
                root_fields.push(FieldView {
                    name: "Algorithm".into(),
                    value: alg.to_string(),
                    range: None,
                });
            }
            if let Some(typ) = json.get("typ").and_then(|v| v.as_str()) {
                root_fields.push(FieldView {
                    name: "Type".into(),
                    value: typ.to_string(),
                    range: None,
                });
            }
        }
    }

    Ok(AnalysisReport {
        analyzer_id: "jwk".into(),
        root_nodes: vec![AnalysisNode {
            id: NodeId::new(),
            label: "JSON Web Token (JWT)".into(),
            kind: "jwt".into(),
            range: ByteRange::new(0, file_len),
            children,
            fields: root_fields,
            diagnostics: Vec::new(),
        }],
        diagnostics,
    })
}

/// Decode a base64url JWT part and extract JSON fields.
fn decode_jwt_part(raw: &str, label: &str, range: ByteRange) -> Result<AnalysisNode, String> {
    let decoded = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|e| format!("base64url: {}", e))?;
    let json: serde_json::Value =
        serde_json::from_slice(&decoded).map_err(|e| format!("JSON: {}", e))?;

    let fields = json_to_fields(&json);
    let kind = format!("jwt_{}", label.to_lowercase());

    Ok(AnalysisNode {
        id: NodeId::new(),
        label: label.into(),
        kind,
        range,
        children: Vec::new(),
        fields,
        diagnostics: Vec::new(),
    })
}

/// Parse a JWK (JSON Web Key) or JWK Set.
fn parse_jwk(text: &str, file_len: u64) -> Result<AnalysisReport, AnalyzeError> {
    let json: serde_json::Value = serde_json::from_str(text).map_err(|e| AnalyzeError::Parse {
        message: format!("Invalid JSON: {}", e),
    })?;

    let mut diagnostics = Vec::new();
    let mut root_nodes = Vec::new();

    // Check if it's a JWK Set (has "keys" array) or single JWK.
    if let Some(keys) = json.get("keys").and_then(|v| v.as_array()) {
        // JWK Set
        let mut children = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            children.push(build_jwk_node(key, i, file_len));
        }
        root_nodes.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("JWK Set ({} keys)", keys.len()),
            kind: "jwk_set".into(),
            range: ByteRange::new(0, file_len),
            children,
            fields: vec![FieldView {
                name: "Key Count".into(),
                value: keys.len().to_string(),
                range: None,
            }],
            diagnostics: Vec::new(),
        });
    } else if json.get("kty").is_some() {
        // Single JWK
        root_nodes.push(build_jwk_node(&json, 0, file_len));
    } else {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: "JSON object has no 'kty' or 'keys' field; may not be a valid JWK".into(),
            range: None,
        });
        // Still try to show the JSON structure.
        root_nodes.push(AnalysisNode {
            id: NodeId::new(),
            label: "JSON Object (not a recognized JWK)".into(),
            kind: "json".into(),
            range: ByteRange::new(0, file_len),
            children: Vec::new(),
            fields: json_to_fields(&json),
            diagnostics: Vec::new(),
        });
    }

    Ok(AnalysisReport {
        analyzer_id: "jwk".into(),
        root_nodes,
        diagnostics,
    })
}

/// Build an analysis node for a single JWK.
fn build_jwk_node(key: &serde_json::Value, index: usize, file_len: u64) -> AnalysisNode {
    let kty = key.get("kty").and_then(|v| v.as_str()).unwrap_or("unknown");
    let kid = key.get("kid").and_then(|v| v.as_str()).unwrap_or("");
    let alg = key.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    let use_field = key.get("use").and_then(|v| v.as_str()).unwrap_or("");

    let label = if !kid.is_empty() {
        format!("Key {}: {} (kid={})", index, kty, kid)
    } else {
        format!("Key {}: {}", index, kty)
    };

    let mut fields = vec![FieldView {
        name: "Key Type (kty)".into(),
        value: kty.to_string(),
        range: None,
    }];

    if !alg.is_empty() {
        fields.push(FieldView {
            name: "Algorithm (alg)".into(),
            value: alg.to_string(),
            range: None,
        });
    }
    if !kid.is_empty() {
        fields.push(FieldView {
            name: "Key ID (kid)".into(),
            value: kid.to_string(),
            range: None,
        });
    }
    if !use_field.is_empty() {
        fields.push(FieldView {
            name: "Use".into(),
            value: use_field.to_string(),
            range: None,
        });
    }

    // Add key-type-specific fields.
    match kty {
        "RSA" => {
            if let Some(n) = key.get("n").and_then(|v| v.as_str()) {
                // Approximate key size from modulus base64url length.
                let approx_bits = n.len() * 6; // base64url chars * 6 bits
                fields.push(FieldView {
                    name: "Modulus size (approx)".into(),
                    value: format!("~{} bits", approx_bits),
                    range: None,
                });
            }
            if let Some(e) = key.get("e").and_then(|v| v.as_str()) {
                fields.push(FieldView {
                    name: "Exponent (e)".into(),
                    value: e.to_string(),
                    range: None,
                });
            }
            // Check for private key components.
            if key.get("d").is_some() {
                fields.push(FieldView {
                    name: "Private key".into(),
                    value: "Present (d, p, q, dp, dq, qi)".into(),
                    range: None,
                });
            }
        }
        "EC" => {
            if let Some(crv) = key.get("crv").and_then(|v| v.as_str()) {
                fields.push(FieldView {
                    name: "Curve (crv)".into(),
                    value: crv.to_string(),
                    range: None,
                });
            }
            if key.get("d").is_some() {
                fields.push(FieldView {
                    name: "Private key".into(),
                    value: "Present (d)".into(),
                    range: None,
                });
            }
        }
        "OKP" => {
            if let Some(crv) = key.get("crv").and_then(|v| v.as_str()) {
                fields.push(FieldView {
                    name: "Curve (crv)".into(),
                    value: crv.to_string(),
                    range: None,
                });
            }
            if key.get("d").is_some() {
                fields.push(FieldView {
                    name: "Private key".into(),
                    value: "Present (d)".into(),
                    range: None,
                });
            }
        }
        "oct" => {
            if let Some(k) = key.get("k").and_then(|v| v.as_str()) {
                let approx_bits = k.len() * 6;
                fields.push(FieldView {
                    name: "Key size (approx)".into(),
                    value: format!("~{} bits", approx_bits),
                    range: None,
                });
            }
        }
        _ => {}
    }

    // Add key_ops if present.
    if let Some(ops) = key.get("key_ops").and_then(|v| v.as_array()) {
        let ops_str: Vec<&str> = ops.iter().filter_map(|v| v.as_str()).collect();
        if !ops_str.is_empty() {
            fields.push(FieldView {
                name: "Key Operations".into(),
                value: ops_str.join(", "),
                range: None,
            });
        }
    }

    // NOTE: Byte-range mapping for individual JSON fields within the file
    // requires a JSON parser that tracks source spans. This is a follow-up
    // improvement. Currently, the whole-file/object range is used.
    // TODO: Add span-tracking JSON parser for field-level byte ranges.

    AnalysisNode {
        id: NodeId::new(),
        label,
        kind: "jwk".into(),
        range: ByteRange::new(0, file_len),
        children: Vec::new(),
        fields,
        diagnostics: Vec::new(),
    }
}

/// Convert JSON object fields to FieldView list.
fn json_to_fields(json: &serde_json::Value) -> Vec<FieldView> {
    let obj = match json.as_object() {
        Some(o) => o,
        None => return Vec::new(),
    };

    obj.iter()
        .map(|(k, v)| {
            let value = match v {
                serde_json::Value::String(s) => truncate(s, 120),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Null => "null".into(),
                serde_json::Value::Array(a) => format!("[{} items]", a.len()),
                serde_json::Value::Object(o) => format!("{{...}} ({} keys)", o.len()),
            };
            FieldView {
                name: k.clone(),
                value,
                range: None, // TODO: span-tracking for byte ranges
            }
        })
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
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
    use tinkerspark_core_types::FileId;

    fn make_handle(kind: DetectedKind, size: u64) -> FileHandle {
        FileHandle {
            id: FileId::new(),
            path: PathBuf::from("test.json"),
            size,
            kind,
        }
    }

    #[test]
    fn confidence_for_jwk_kinds() {
        let analyzer = JwkAnalyzer;
        let src = MemoryByteSource::new(vec![0]);
        let handle = |kind| make_handle(kind, 1);
        assert_eq!(
            analyzer.can_analyze(&handle(DetectedKind::JsonWebKey), &src),
            AnalyzerConfidence::High
        );
        assert_eq!(
            analyzer.can_analyze(&handle(DetectedKind::JsonWebToken), &src),
            AnalyzerConfidence::High
        );
        assert_eq!(
            analyzer.can_analyze(&handle(DetectedKind::Binary), &src),
            AnalyzerConfidence::None
        );
    }

    #[test]
    fn parses_simple_jwk() {
        let jwk = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM","e":"AQAB"}"#;
        let report = parse_jwk(jwk, jwk.len() as u64).unwrap();
        assert_eq!(report.analyzer_id, "jwk");
        let node = &report.root_nodes[0];
        assert!(node
            .fields
            .iter()
            .any(|f| f.name == "Key Type (kty)" && f.value == "RSA"));
    }

    #[test]
    fn parses_jwk_set() {
        let jwks = r#"{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}"#;
        let report = parse_jwk(jwks, jwks.len() as u64).unwrap();
        let root = &report.root_nodes[0];
        assert!(root.label.contains("JWK Set"));
        assert_eq!(root.children.len(), 1);
    }

    #[test]
    fn parses_jwt() {
        // Minimal JWT: {"alg":"HS256","typ":"JWT"}.{"sub":"1234567890"}.signature
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                    eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
                    SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let report = parse_jwt(jwt, jwt.len() as u64).unwrap();
        let root = &report.root_nodes[0];
        assert!(root.label.contains("JWT"));
        assert_eq!(root.children.len(), 3); // header, payload, signature
        assert!(root
            .fields
            .iter()
            .any(|f| f.name == "Algorithm" && f.value == "HS256"));
    }
}
