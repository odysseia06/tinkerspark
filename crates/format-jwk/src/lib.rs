//! JWK/JWT/JWS analyzer for Tinkerspark.
//!
//! Handles:
//! - JWK (JSON Web Key): JSON objects with "kty" field
//! - JWT (JSON Web Token): compact serialization (header.payload.signature)
//! - JWS (JSON Web Signature): same compact format as JWT
//!
//! Uses `serde_json` for JSON parsing and `base64` for base64url decoding.
//! Field-level source spans are produced by the in-crate [`json_span`]
//! scanner so the structure pane can navigate to exact JSON field bytes.

mod json_span;

use std::collections::HashMap;

use tinkerspark_core_analyze::{
    AnalysisNode, AnalysisReport, AnalyzeError, Analyzer, AnalyzerConfidence, FieldView,
};
use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::{ByteRange, DetectedKind, Diagnostic, FileHandle, NodeId, Severity};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::json_span::FieldSpan;

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
        // The full file text, NOT trimmed. The span-tracking parsers want
        // real file offsets, so trimming would shift every emitted byte
        // range by the leading-whitespace length. The parsers handle their
        // own whitespace skipping internally.
        let text = String::from_utf8_lossy(&data);

        match &handle.kind {
            DetectedKind::JsonWebToken => parse_jwt(&text, file_len),
            DetectedKind::JsonWebKey => parse_jwk(&text, file_len),
            _ => Err(AnalyzeError::Unsupported),
        }
    }
}

/// Parse a JWT/JWS in compact serialization: header.payload.signature
fn parse_jwt(text: &str, file_len: u64) -> Result<AnalysisReport, AnalyzeError> {
    // Find where the JWT body actually starts in the file. Leading and
    // trailing whitespace must not shift the part offsets — we still want
    // them to be real file positions.
    let leading_ws = text.len() - text.trim_start().len();
    let body = text[leading_ws..].trim_end();

    let parts: Vec<&str> = body.splitn(4, '.').collect();
    if parts.len() < 3 {
        return Err(AnalyzeError::Parse {
            message: format!("Expected 3 dot-separated parts, found {}", parts.len()),
        });
    }

    let mut diagnostics = Vec::new();
    let mut children = Vec::new();

    // Byte offsets are file offsets, anchored at the first non-whitespace
    // byte of the file (so a leading newline or BOM doesn't shift them).
    let mut offset = leading_ws as u64;

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

/// Decode a base64url JWT part and extract JSON field values for display.
///
/// JWT field ranges are intentionally **not** populated: base64 has no
/// character-level mapping back to the source file, so any range we
/// emitted would either be a wrong file offset (confusing the structure
/// pane) or a decoded-buffer offset (a different coordinate system that
/// `FieldView::range` doesn't model). The encoded part itself still has
/// a real file range on the parent node, which is the only granularity
/// `FieldView::range` can carry coherently. See issue #5 for the
/// "where source mapping is still meaningful" hedge that lets us punt on
/// per-field JWT navigation until a typed coordinate space exists.
fn decode_jwt_part(raw: &str, label: &str, range: ByteRange) -> Result<AnalysisNode, String> {
    let decoded = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|e| format!("base64url: {}", e))?;
    let json: serde_json::Value =
        serde_json::from_slice(&decoded).map_err(|e| format!("JSON: {}", e))?;

    // Empty span map → every FieldView keeps `range: None`.
    let no_spans = HashMap::new();
    let fields = json_to_fields(&json, &no_spans);
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
///
/// `text` is the **full** file text — leading/trailing whitespace
/// preserved — so the span scanner can emit real file offsets. `serde_json`
/// tolerates surrounding whitespace and `index_object` skips it before the
/// opening `{`, so both layers see the same byte coordinate system.
fn parse_jwk(text: &str, file_len: u64) -> Result<AnalysisReport, AnalyzeError> {
    let json: serde_json::Value = serde_json::from_str(text).map_err(|e| AnalyzeError::Parse {
        message: format!("Invalid JSON: {}", e),
    })?;

    let mut diagnostics = Vec::new();
    let mut root_nodes = Vec::new();

    // The span scanner walks the same buffer the parser saw and skips
    // leading whitespace itself, so the returned ranges are absolute file
    // positions even when the file starts with a BOM, newline, or stray
    // padding before the opening `{`.
    let outer_index = json_span::index_object(text, 0);

    // Check if it's a JWK Set (has "keys" array) or single JWK.
    if let Some(keys) = json.get("keys").and_then(|v| v.as_array()) {
        // Locate the `keys` array's byte range and walk its elements.
        let child_ranges = if let Some(keys_span) = outer_index.get("keys") {
            let array_text = slice_text(text, keys_span.value);
            let array_offset = keys_span.value.offset();
            json_span::index_array_objects(array_text, array_offset)
        } else {
            Vec::new()
        };

        let mut children = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let (child_range, child_index) = if let Some(range) = child_ranges.get(i) {
                let child_text = slice_text(text, *range);
                let idx = json_span::index_object(child_text, range.offset());
                (*range, idx)
            } else {
                (ByteRange::new(0, file_len), HashMap::new())
            };
            children.push(build_jwk_node(key, i, child_range, &child_index));
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
                range: outer_index.get("keys").map(|s| s.value),
            }],
            diagnostics: Vec::new(),
        });
    } else if json.get("kty").is_some() {
        // Single JWK — use the file-wide range as the object range.
        root_nodes.push(build_jwk_node(
            &json,
            0,
            ByteRange::new(0, file_len),
            &outer_index,
        ));
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
            fields: json_to_fields(&json, &outer_index),
            diagnostics: Vec::new(),
        });
    }

    Ok(AnalysisReport {
        analyzer_id: "jwk".into(),
        root_nodes,
        diagnostics,
    })
}

/// Slice a substring out of `text` using a `ByteRange`. Returns an empty
/// string when the range falls outside the buffer (defensive — span
/// extraction is best-effort).
fn slice_text(text: &str, range: ByteRange) -> &str {
    let start = range.offset() as usize;
    let end = (range.offset() + range.length()) as usize;
    text.get(start..end).unwrap_or("")
}

/// Build an analysis node for a single JWK.
///
/// `object_range` is the byte range of this JWK's `{...}` literal in the
/// source file. `index` maps top-level field names to their key/value byte
/// ranges within the same coordinate system. Field-view ranges fall back
/// to `None` when a key is absent from the index (graceful degradation
/// when span extraction failed).
fn build_jwk_node(
    key: &serde_json::Value,
    index_in_set: usize,
    object_range: ByteRange,
    spans: &HashMap<String, FieldSpan>,
) -> AnalysisNode {
    let kty = key.get("kty").and_then(|v| v.as_str()).unwrap_or("unknown");
    let kid = key.get("kid").and_then(|v| v.as_str()).unwrap_or("");
    let alg = key.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    let use_field = key.get("use").and_then(|v| v.as_str()).unwrap_or("");

    let label = if !kid.is_empty() {
        format!("Key {}: {} (kid={})", index_in_set, kty, kid)
    } else {
        format!("Key {}: {}", index_in_set, kty)
    };

    let mut fields = vec![FieldView {
        name: "Key Type (kty)".into(),
        value: kty.to_string(),
        range: spans.get("kty").map(|s| s.value),
    }];

    if !alg.is_empty() {
        fields.push(FieldView {
            name: "Algorithm (alg)".into(),
            value: alg.to_string(),
            range: spans.get("alg").map(|s| s.value),
        });
    }
    if !kid.is_empty() {
        fields.push(FieldView {
            name: "Key ID (kid)".into(),
            value: kid.to_string(),
            range: spans.get("kid").map(|s| s.value),
        });
    }
    if !use_field.is_empty() {
        fields.push(FieldView {
            name: "Use".into(),
            value: use_field.to_string(),
            range: spans.get("use").map(|s| s.value),
        });
    }

    // Add key-type-specific fields.
    match kty {
        "RSA" => {
            if let Some(n) = key.get("n").and_then(|v| v.as_str()) {
                // Approximate key size from modulus base64url length.
                let approx_bits = n.len() * 6; // base64url chars * 6 bits
                fields.push(FieldView {
                    name: "Modulus (n)".into(),
                    value: format!("~{} bits", approx_bits),
                    range: spans.get("n").map(|s| s.value),
                });
            }
            if let Some(e) = key.get("e").and_then(|v| v.as_str()) {
                fields.push(FieldView {
                    name: "Exponent (e)".into(),
                    value: e.to_string(),
                    range: spans.get("e").map(|s| s.value),
                });
            }
            // Check for private key components.
            if key.get("d").is_some() {
                fields.push(FieldView {
                    name: "Private exponent (d)".into(),
                    value: "Present".into(),
                    range: spans.get("d").map(|s| s.value),
                });
            }
            for component in &["p", "q", "dp", "dq", "qi"] {
                if key.get(*component).is_some() {
                    fields.push(FieldView {
                        name: format!("RSA private ({component})"),
                        value: "Present".into(),
                        range: spans.get(*component).map(|s| s.value),
                    });
                }
            }
        }
        "EC" => {
            if let Some(crv) = key.get("crv").and_then(|v| v.as_str()) {
                fields.push(FieldView {
                    name: "Curve (crv)".into(),
                    value: crv.to_string(),
                    range: spans.get("crv").map(|s| s.value),
                });
            }
            if key.get("x").is_some() {
                fields.push(FieldView {
                    name: "Point x".into(),
                    value: "Present".into(),
                    range: spans.get("x").map(|s| s.value),
                });
            }
            if key.get("y").is_some() {
                fields.push(FieldView {
                    name: "Point y".into(),
                    value: "Present".into(),
                    range: spans.get("y").map(|s| s.value),
                });
            }
            if key.get("d").is_some() {
                fields.push(FieldView {
                    name: "Private scalar (d)".into(),
                    value: "Present".into(),
                    range: spans.get("d").map(|s| s.value),
                });
            }
        }
        "OKP" => {
            if let Some(crv) = key.get("crv").and_then(|v| v.as_str()) {
                fields.push(FieldView {
                    name: "Curve (crv)".into(),
                    value: crv.to_string(),
                    range: spans.get("crv").map(|s| s.value),
                });
            }
            if key.get("x").is_some() {
                fields.push(FieldView {
                    name: "Public key (x)".into(),
                    value: "Present".into(),
                    range: spans.get("x").map(|s| s.value),
                });
            }
            if key.get("d").is_some() {
                fields.push(FieldView {
                    name: "Private key (d)".into(),
                    value: "Present".into(),
                    range: spans.get("d").map(|s| s.value),
                });
            }
        }
        "oct" => {
            if let Some(k) = key.get("k").and_then(|v| v.as_str()) {
                let approx_bits = k.len() * 6;
                fields.push(FieldView {
                    name: "Symmetric key (k)".into(),
                    value: format!("~{} bits", approx_bits),
                    range: spans.get("k").map(|s| s.value),
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
                range: spans.get("key_ops").map(|s| s.value),
            });
        }
    }

    AnalysisNode {
        id: NodeId::new(),
        label,
        kind: "jwk".into(),
        range: object_range,
        children: Vec::new(),
        fields,
        diagnostics: Vec::new(),
    }
}

/// Convert JSON object fields to FieldView list, attaching the span
/// index's per-field byte ranges where available.
fn json_to_fields(json: &serde_json::Value, spans: &HashMap<String, FieldSpan>) -> Vec<FieldView> {
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
                range: spans.get(k).map(|s| s.value),
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

    fn slice_text<'a>(text: &'a str, range: ByteRange) -> &'a str {
        let start = range.offset() as usize;
        let end = (range.offset() + range.length()) as usize;
        &text[start..end]
    }

    #[test]
    fn jwk_field_ranges_point_at_source_substrings() {
        let jwk = r#"{"kty":"RSA","n":"abc","e":"AQAB","kid":"k1","alg":"RS256","use":"sig"}"#;
        let report = parse_jwk(jwk, jwk.len() as u64).unwrap();
        let node = &report.root_nodes[0];

        let parent = node.range;
        let cases: &[(&str, &str)] = &[
            ("Key Type (kty)", "\"RSA\""),
            ("Modulus (n)", "\"abc\""),
            ("Exponent (e)", "\"AQAB\""),
            ("Key ID (kid)", "\"k1\""),
            ("Algorithm (alg)", "\"RS256\""),
            ("Use", "\"sig\""),
        ];

        for (field_name, expected) in cases {
            let field = node
                .fields
                .iter()
                .find(|f| f.name == *field_name)
                .unwrap_or_else(|| panic!("missing field {field_name}"));
            let range = field
                .range
                .unwrap_or_else(|| panic!("field {field_name} has no range"));
            assert!(
                range.length() > 0,
                "field {field_name} should have non-empty range"
            );
            assert_eq!(
                slice_text(jwk, range),
                *expected,
                "field {field_name} range should slice the expected source substring"
            );
            assert!(
                range.offset() >= parent.offset() && range.end() <= parent.end(),
                "field {field_name} range must be nested inside the parent JWK object"
            );
        }
    }

    #[test]
    fn jwk_set_children_have_distinct_sub_ranges_with_field_spans() {
        let jwks =
            r#"{"keys":[{"kty":"EC","crv":"P-256","x":"AAA","y":"BBB"},{"kty":"oct","k":"CCC"}]}"#;
        let report = parse_jwk(jwks, jwks.len() as u64).unwrap();
        let set = &report.root_nodes[0];
        assert_eq!(set.kind, "jwk_set");
        assert_eq!(set.children.len(), 2);

        // Each child's range must be a strict sub-range of the set, and
        // the two children must have distinct ranges.
        let mut offsets: Vec<u64> = set.children.iter().map(|c| c.range.offset()).collect();
        offsets.sort_unstable();
        offsets.dedup();
        assert_eq!(offsets.len(), 2);
        for child in &set.children {
            assert!(child.range.length() < set.range.length());
            assert!(child.range.offset() >= set.range.offset());
            assert!(child.range.end() <= set.range.end());
        }

        // Field ranges on each child must slice their expected substrings
        // from the original source, AND must be nested inside the child
        // object's range — proving the per-child sub-index is wired
        // correctly, not the outer-set index.
        let ec = &set.children[0];
        let crv_range = ec
            .fields
            .iter()
            .find(|f| f.name == "Curve (crv)")
            .unwrap()
            .range
            .unwrap();
        assert_eq!(slice_text(jwks, crv_range), "\"P-256\"");
        assert!(crv_range.offset() >= ec.range.offset());
        assert!(crv_range.end() <= ec.range.end());

        let oct = &set.children[1];
        let k_range = oct
            .fields
            .iter()
            .find(|f| f.name == "Symmetric key (k)")
            .unwrap()
            .range
            .unwrap();
        assert_eq!(slice_text(jwks, k_range), "\"CCC\"");
        assert!(k_range.offset() >= oct.range.offset());
        assert!(k_range.end() <= oct.range.end());

        // The kty field on each child should also point at its own kty,
        // not at the outer object's first kty.
        let ec_kty = ec
            .fields
            .iter()
            .find(|f| f.name == "Key Type (kty)")
            .unwrap()
            .range
            .unwrap();
        assert_eq!(slice_text(jwks, ec_kty), "\"EC\"");
        let oct_kty = oct
            .fields
            .iter()
            .find(|f| f.name == "Key Type (kty)")
            .unwrap()
            .range
            .unwrap();
        assert_eq!(slice_text(jwks, oct_kty), "\"oct\"");
        assert_ne!(ec_kty.offset(), oct_kty.offset());
    }

    #[test]
    fn jwk_field_ranges_survive_pretty_printed_input() {
        let jwk = "{\n  \"kty\" : \"RSA\" ,\n  \"e\"   : \"AQAB\"\n}";
        let report = parse_jwk(jwk, jwk.len() as u64).unwrap();
        let node = &report.root_nodes[0];
        let kty_range = node
            .fields
            .iter()
            .find(|f| f.name == "Key Type (kty)")
            .unwrap()
            .range
            .unwrap();
        assert_eq!(slice_text(jwk, kty_range), "\"RSA\"");
        let e_range = node
            .fields
            .iter()
            .find(|f| f.name == "Exponent (e)")
            .unwrap()
            .range
            .unwrap();
        assert_eq!(slice_text(jwk, e_range), "\"AQAB\"");
    }

    #[test]
    fn jwt_field_ranges_are_not_emitted_to_avoid_coordinate_space_drift() {
        // Issue #5 originally added decoded-buffer field ranges, but base64
        // has no character-level mapping back to the file, and FieldView
        // uses a single unmarked ByteRange. To keep the model coherent we
        // intentionally leave per-field JWT ranges empty until a typed
        // coordinate space exists. The encoded part still has a file range
        // on its own AnalysisNode, which IS valid file offsets.
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                    eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
                    SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let report = parse_jwt(jwt, jwt.len() as u64).unwrap();
        let root = &report.root_nodes[0];

        let header = root
            .children
            .iter()
            .find(|c| c.kind == "jwt_header")
            .unwrap();
        // The header node range is a real file offset.
        assert!(header.range.length() > 0);
        // But each header field range is None — no coordinate-space mixing.
        for field in &header.fields {
            assert!(
                field.range.is_none(),
                "JWT header field {:?} unexpectedly carries a range",
                field.name
            );
        }

        let payload = root
            .children
            .iter()
            .find(|c| c.kind == "jwt_payload")
            .unwrap();
        for field in &payload.fields {
            assert!(field.range.is_none());
        }
    }

    #[test]
    fn jwk_field_ranges_survive_leading_file_whitespace() {
        // The reviewer's regression: a file that starts with whitespace
        // (BOM, leading newline, indented JSON) must not shift the field
        // offsets. The span scanner should still report real file offsets.
        let prefix = "\n  \t";
        let body = r#"{"kty":"RSA","n":"abc","e":"AQAB"}"#;
        let mut full = String::new();
        full.push_str(prefix);
        full.push_str(body);

        let report = parse_jwk(&full, full.len() as u64).unwrap();
        let node = &report.root_nodes[0];
        // The node range now spans the whole file (parent),
        // and field ranges fall inside it AND slice the right substrings.
        let kty_range = node
            .fields
            .iter()
            .find(|f| f.name == "Key Type (kty)")
            .unwrap()
            .range
            .expect("kty should still have a span when the file has leading ws");
        assert_eq!(slice_text(&full, kty_range), "\"RSA\"");
        assert!(kty_range.offset() > prefix.len() as u64 - 1);

        let n_range = node
            .fields
            .iter()
            .find(|f| f.name == "Modulus (n)")
            .unwrap()
            .range
            .unwrap();
        assert_eq!(slice_text(&full, n_range), "\"abc\"");
    }

    #[test]
    fn jwk_set_child_ranges_survive_leading_file_whitespace() {
        let prefix = "\n\n  \t";
        let body = r#"{"keys":[{"kty":"EC","crv":"P-256"},{"kty":"oct","k":"CCC"}]}"#;
        let mut full = String::new();
        full.push_str(prefix);
        full.push_str(body);

        let report = parse_jwk(&full, full.len() as u64).unwrap();
        let set = &report.root_nodes[0];
        assert_eq!(set.children.len(), 2);

        // Each child's range should still slice its real {...} object out
        // of the original (whitespace-prefixed) source.
        let ec = &set.children[0];
        assert_eq!(slice_text(&full, ec.range), r#"{"kty":"EC","crv":"P-256"}"#);
        let oct = &set.children[1];
        assert_eq!(slice_text(&full, oct.range), r#"{"kty":"oct","k":"CCC"}"#);

        // And per-child field spans must point at THAT child's bytes inside
        // the whitespace-shifted source.
        let crv_range = ec
            .fields
            .iter()
            .find(|f| f.name == "Curve (crv)")
            .unwrap()
            .range
            .unwrap();
        assert_eq!(slice_text(&full, crv_range), "\"P-256\"");
        let k_range = oct
            .fields
            .iter()
            .find(|f| f.name == "Symmetric key (k)")
            .unwrap()
            .range
            .unwrap();
        assert_eq!(slice_text(&full, k_range), "\"CCC\"");
    }

    #[test]
    fn jwt_part_ranges_survive_leading_file_whitespace() {
        let jwt = "  \neyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\n";
        let report = parse_jwt(jwt, jwt.len() as u64).unwrap();
        let root = &report.root_nodes[0];

        // Find the header part by kind, then verify its range slices the
        // raw base64 header chunk out of the original (ws-prefixed) input.
        let header = root
            .children
            .iter()
            .find(|c| c.kind == "jwt_header")
            .unwrap();
        assert_eq!(slice_text(jwt, header.range), "eyJhbGciOiJIUzI1NiJ9");

        let payload = root
            .children
            .iter()
            .find(|c| c.kind == "jwt_payload")
            .unwrap();
        assert_eq!(slice_text(jwt, payload.range), "eyJzdWIiOiIxIn0");

        let sig = root
            .children
            .iter()
            .find(|c| c.kind == "jwt_signature")
            .unwrap();
        assert_eq!(slice_text(jwt, sig.range), "sig");
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
