//! Lightweight JSON source-span scanner.
//!
//! Walks a JSON object literal once and returns byte-range information for
//! each top-level key/value pair. This is purpose-built for the JWK / JWT
//! field-mapping use case in `lib.rs` — it does not attempt to be a general
//! JSON parser, only a span indexer over already-parsed object shapes.
//!
//! Why a hand-rolled scanner instead of a new dependency: `serde_json` is
//! already in the dep tree but does not expose source spans, and pulling in
//! a span-aware JSON crate (`jsonc-parser`, `serde_spanned`, etc.) for ~150
//! lines of state-machine code would be over-budget for this issue.

use std::collections::HashMap;
use tinkerspark_core_types::ByteRange;

/// Span info for a single top-level field in a JSON object.
#[derive(Debug, Clone, Copy)]
pub struct FieldSpan {
    /// Range of the key string including the surrounding `"` quotes.
    /// Currently unused by the analyzer (it only highlights value spans),
    /// but kept on the struct because the indexer's key-extraction
    /// correctness is verified by unit tests and the field is the natural
    /// hook for a future key-vs-value highlighting refinement.
    #[allow(dead_code)]
    pub key: ByteRange,
    /// Range of the value token. For strings this includes the quotes; for
    /// arrays/objects it includes the brackets/braces; for primitives it
    /// covers exactly the literal characters.
    pub value: ByteRange,
}

/// Walk a JSON object literal and return spans for each top-level key.
///
/// `text` should start at (or have leading whitespace before) the opening
/// `{`. `text_offset` is the file offset of `text[0]` in the caller's
/// coordinate system, so the returned ranges are absolute file positions.
///
/// On malformed input the indexer returns whatever it managed to recognize
/// before the failure point. Callers must not rely on completeness — fields
/// that don't show up in the map simply get `None` ranges in the analyzer
/// output, which matches the existing graceful-degradation contract.
pub fn index_object(text: &str, text_offset: u64) -> HashMap<String, FieldSpan> {
    let mut result = HashMap::new();
    let bytes = text.as_bytes();
    let mut pos = skip_whitespace(bytes, 0);
    if pos >= bytes.len() || bytes[pos] != b'{' {
        return result;
    }
    pos += 1;

    loop {
        pos = skip_whitespace_and_commas(bytes, pos);
        if pos >= bytes.len() || bytes[pos] == b'}' {
            break;
        }
        if bytes[pos] != b'"' {
            return result;
        }
        let key_start = pos;
        let key_text_start = pos + 1;
        pos = match scan_string_end(bytes, pos) {
            Some(end) => end,
            None => return result,
        };
        let key_text_end = pos - 1; // exclude the closing quote
        let key_text = match std::str::from_utf8(&bytes[key_text_start..key_text_end]) {
            Ok(s) => unescape_json_key(s),
            Err(_) => return result,
        };
        let key_range = ByteRange::new(text_offset + key_start as u64, (pos - key_start) as u64);

        pos = skip_whitespace(bytes, pos);
        if pos >= bytes.len() || bytes[pos] != b':' {
            return result;
        }
        pos += 1;
        pos = skip_whitespace(bytes, pos);
        if pos >= bytes.len() {
            return result;
        }
        let value_start = pos;
        let value_end = match read_value_extent(bytes, pos) {
            Some(end) => end,
            None => return result,
        };
        pos = value_end;
        let value_range = ByteRange::new(
            text_offset + value_start as u64,
            (value_end - value_start) as u64,
        );
        result.insert(
            key_text,
            FieldSpan {
                key: key_range,
                value: value_range,
            },
        );
    }
    result
}

/// Walk a JSON array literal and return the byte range of each `{...}`
/// element. Non-object elements are skipped. Used by the JWK Set walker to
/// locate per-key sub-object spans within the `keys` array.
pub fn index_array_objects(text: &str, text_offset: u64) -> Vec<ByteRange> {
    let mut result = Vec::new();
    let bytes = text.as_bytes();
    let mut pos = skip_whitespace(bytes, 0);
    if pos >= bytes.len() || bytes[pos] != b'[' {
        return result;
    }
    pos += 1;

    loop {
        pos = skip_whitespace_and_commas(bytes, pos);
        if pos >= bytes.len() || bytes[pos] == b']' {
            break;
        }
        if bytes[pos] == b'{' {
            let elem_start = pos;
            let elem_end = match read_value_extent(bytes, pos) {
                Some(end) => end,
                None => break,
            };
            result.push(ByteRange::new(
                text_offset + elem_start as u64,
                (elem_end - elem_start) as u64,
            ));
            pos = elem_end;
        } else {
            // Skip non-object elements without recording them.
            match read_value_extent(bytes, pos) {
                Some(end) => pos = end,
                None => break,
            }
        }
    }
    result
}

fn skip_whitespace(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t' | b'\r' | b'\n') {
        pos += 1;
    }
    pos
}

fn skip_whitespace_and_commas(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t' | b'\r' | b'\n' | b',') {
        pos += 1;
    }
    pos
}

/// Given a `"`-prefixed string starting at `start`, return the position
/// immediately after the closing `"` (one past the close-quote byte).
fn scan_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start)? != &b'"' {
        return None;
    }
    let mut p = start + 1;
    while p < bytes.len() {
        match bytes[p] {
            b'\\' if p + 1 < bytes.len() => p += 2,
            b'"' => return Some(p + 1),
            _ => p += 1,
        }
    }
    None
}

/// Given a JSON value starting at `start`, return the byte position
/// immediately after the value ends. Handles strings, objects, arrays,
/// numbers, true/false/null. Returns `None` on malformed input.
fn read_value_extent(bytes: &[u8], start: usize) -> Option<usize> {
    if start >= bytes.len() {
        return None;
    }
    match bytes[start] {
        b'"' => scan_string_end(bytes, start),
        b'{' | b'[' => scan_balanced(bytes, start),
        b't' if bytes.get(start..start + 4) == Some(b"true") => Some(start + 4),
        b'f' if bytes.get(start..start + 5) == Some(b"false") => Some(start + 5),
        b'n' if bytes.get(start..start + 4) == Some(b"null") => Some(start + 4),
        b'-' | b'0'..=b'9' => Some(scan_number_end(bytes, start)),
        _ => None,
    }
}

/// Scan a balanced `{...}` or `[...]` region, respecting strings and
/// escapes. Returns the position one past the matching close bracket.
fn scan_balanced(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut p = start;
    let mut in_string = false;
    while p < bytes.len() {
        let b = bytes[p];
        if in_string {
            if b == b'\\' && p + 1 < bytes.len() {
                p += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            p += 1;
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(p + 1);
                }
            }
            _ => {}
        }
        p += 1;
    }
    None
}

fn scan_number_end(bytes: &[u8], start: usize) -> usize {
    let mut p = start;
    if p < bytes.len() && (bytes[p] == b'-' || bytes[p] == b'+') {
        p += 1;
    }
    while p < bytes.len() {
        let b = bytes[p];
        if b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-') {
            p += 1;
        } else {
            break;
        }
    }
    p
}

/// JSON keys are typically plain ASCII without escapes (especially in JWK /
/// JWT contexts). This helper handles the common escapes for completeness;
/// unknown escapes are passed through verbatim so we never panic.
fn unescape_json_key(raw: &str) -> String {
    if !raw.contains('\\') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slice<'a>(text: &'a str, range: ByteRange) -> &'a str {
        let start = range.offset() as usize;
        let end = (range.offset() + range.length()) as usize;
        &text[start..end]
    }

    #[test]
    fn indexes_simple_object() {
        let text = r#"{"kty":"RSA","e":"AQAB"}"#;
        let map = index_object(text, 0);
        assert_eq!(map.len(), 2);

        let kty = map.get("kty").unwrap();
        assert_eq!(slice(text, kty.key), "\"kty\"");
        assert_eq!(slice(text, kty.value), "\"RSA\"");

        let e = map.get("e").unwrap();
        assert_eq!(slice(text, e.key), "\"e\"");
        assert_eq!(slice(text, e.value), "\"AQAB\"");
    }

    #[test]
    fn indexes_nested_object_value() {
        let text = r#"{"outer":{"inner":1},"after":2}"#;
        let map = index_object(text, 0);
        let outer = map.get("outer").unwrap();
        assert_eq!(slice(text, outer.value), r#"{"inner":1}"#);
        let after = map.get("after").unwrap();
        assert_eq!(slice(text, after.value), "2");
    }

    #[test]
    fn indexes_array_value_and_numbers() {
        let text = r#"{"a":[1,2,3],"b":-1.5e2,"c":true,"d":null}"#;
        let map = index_object(text, 0);
        assert_eq!(slice(text, map.get("a").unwrap().value), "[1,2,3]");
        assert_eq!(slice(text, map.get("b").unwrap().value), "-1.5e2");
        assert_eq!(slice(text, map.get("c").unwrap().value), "true");
        assert_eq!(slice(text, map.get("d").unwrap().value), "null");
    }

    #[test]
    fn handles_whitespace_and_newlines() {
        let text = "{\n  \"kty\" : \"RSA\" ,\n  \"e\" : \"AQAB\"\n}";
        let map = index_object(text, 0);
        assert_eq!(map.len(), 2);
        assert_eq!(slice(text, map.get("kty").unwrap().value), "\"RSA\"");
    }

    #[test]
    fn respects_text_offset() {
        let text = r#"{"x":1}"#;
        let map = index_object(text, 100);
        let x = map.get("x").unwrap();
        assert_eq!(x.key.offset(), 101);
        assert_eq!(x.value.offset(), 105);
    }

    #[test]
    fn handles_string_escape_in_value() {
        let text = r#"{"k":"a\"b","next":1}"#;
        let map = index_object(text, 0);
        assert_eq!(slice(text, map.get("k").unwrap().value), r#""a\"b""#);
        assert_eq!(slice(text, map.get("next").unwrap().value), "1");
    }

    #[test]
    fn malformed_input_returns_partial() {
        let text = r#"{"good":1,"bad":}"#;
        let map = index_object(text, 0);
        assert!(map.contains_key("good"));
        assert!(!map.contains_key("bad"));
    }

    #[test]
    fn index_array_objects_walks_keys_array() {
        let text = r#"[{"kty":"RSA"},{"kty":"EC"}]"#;
        let ranges = index_array_objects(text, 0);
        assert_eq!(ranges.len(), 2);
        assert_eq!(slice(text, ranges[0]), r#"{"kty":"RSA"}"#);
        assert_eq!(slice(text, ranges[1]), r#"{"kty":"EC"}"#);
    }

    #[test]
    fn index_array_objects_skips_non_object_elements() {
        let text = r#"[1,{"kty":"oct"},"x"]"#;
        let ranges = index_array_objects(text, 0);
        assert_eq!(ranges.len(), 1);
        assert_eq!(slice(text, ranges[0]), r#"{"kty":"oct"}"#);
    }
}
