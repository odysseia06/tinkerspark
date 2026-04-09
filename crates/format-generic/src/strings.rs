use tinkerspark_core_types::ByteRange;

/// A run of printable characters found in binary data.
#[derive(Debug, Clone)]
pub struct StringRegion {
    pub offset: u64,
    pub length: u64,
    pub content: String,
}

impl StringRegion {
    pub fn range(&self) -> ByteRange {
        ByteRange::new(self.offset, self.length)
    }
}

/// Maximum number of bytes (or, for UTF-8 extraction, codepoints) preserved
/// in [`StringRegion::content`]. This caps per-string memory while still
/// being large enough to keep realistic PEM bodies, hex dumps, and inline
/// base64 payloads intact for downstream classifiers like
/// [`detect_encoded_sections`]. The full run length is still recorded in
/// [`StringRegion::length`]; only the cached `content` is bounded. Display
/// callers should re-truncate via [`truncate_display`] in lib.rs.
const MAX_STRING_LEN: usize = 4096;

fn is_printable(b: u8) -> bool {
    b.is_ascii_graphic() || b == b' ' || b == b'\t'
}

/// Extract runs of printable ASCII strings from the data.
///
/// Returns up to `max_strings` results, each at least `min_string_len` bytes.
/// `StringRegion::content` always holds a valid prefix of the actual run
/// (no display markers like `"..."` are mixed in) so downstream analyzers —
/// notably [`detect_encoded_sections`] — can classify it without having to
/// strip presentation noise.
pub fn extract_strings(
    data: &[u8],
    base_offset: u64,
    min_string_len: usize,
    max_strings: usize,
) -> Vec<StringRegion> {
    if max_strings == 0 {
        return Vec::new();
    }

    let mut results = Vec::new();
    let mut run_start = None;

    for (i, &b) in data.iter().enumerate() {
        if is_printable(b) {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(start) = run_start.take() {
            let len = i - start;
            if len >= min_string_len {
                let cached_len = len.min(MAX_STRING_LEN);
                let content =
                    String::from_utf8_lossy(&data[start..start + cached_len]).into_owned();
                results.push(StringRegion {
                    offset: base_offset + start as u64,
                    length: len as u64,
                    content,
                });
                if results.len() >= max_strings {
                    return results;
                }
            }
        }
    }

    // Handle trailing run.
    if let Some(start) = run_start {
        let len = data.len() - start;
        if len >= min_string_len && results.len() < max_strings {
            let cached_len = len.min(MAX_STRING_LEN);
            let content = String::from_utf8_lossy(&data[start..start + cached_len]).into_owned();
            results.push(StringRegion {
                offset: base_offset + start as u64,
                length: len as u64,
                content,
            });
        }
    }

    results
}

/// Length of a UTF-8 codepoint given its leading byte, or `None` if the
/// byte is not a valid UTF-8 start byte.
fn utf8_char_len(first: u8) -> Option<usize> {
    if first < 0x80 {
        Some(1)
    } else if first < 0xC2 {
        None
    } else if first < 0xE0 {
        Some(2)
    } else if first < 0xF0 {
        Some(3)
    } else if first < 0xF5 {
        Some(4)
    } else {
        None
    }
}

/// Extract runs of valid UTF-8 text that contain at least one non-ASCII
/// codepoint. Pure-ASCII runs are intentionally skipped because the existing
/// [`extract_strings`] pass already covers them — this function exists to
/// surface the *additional* coverage from UTF-8-aware decoding (e.g. CJK,
/// accented Latin, Cyrillic, emoji).
///
/// Length thresholds count codepoints, not bytes, so a 4-char Japanese
/// string (12 bytes) is treated the same as a 4-char ASCII string. Control
/// characters (other than horizontal tab) terminate a run.
pub fn extract_utf8_strings(
    data: &[u8],
    base_offset: u64,
    min_chars: usize,
    max_strings: usize,
) -> Vec<StringRegion> {
    if max_strings == 0 {
        return Vec::new();
    }
    let mut results = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let start = i;
        let mut chars = 0usize;
        let mut had_non_ascii = false;
        while i < data.len() {
            let first = data[i];
            let Some(char_len) = utf8_char_len(first) else {
                break;
            };
            if i + char_len > data.len() {
                break;
            }
            let bytes = &data[i..i + char_len];
            let Ok(s) = std::str::from_utf8(bytes) else {
                break;
            };
            let Some(c) = s.chars().next() else {
                break;
            };
            if c.is_control() && c != '\t' {
                break;
            }
            if char_len > 1 {
                had_non_ascii = true;
            }
            i += char_len;
            chars += 1;
        }
        if had_non_ascii && chars >= min_chars {
            let len_bytes = i - start;
            let raw = String::from_utf8_lossy(&data[start..i]).into_owned();
            // Cap by codepoint count to bound memory while keeping the cached
            // content a valid prefix of the run for downstream classifiers.
            let content: String = raw.chars().take(MAX_STRING_LEN).collect();
            results.push(StringRegion {
                offset: base_offset + start as u64,
                length: len_bytes as u64,
                content,
            });
            if results.len() >= max_strings {
                return results;
            }
        }
        // Advance past whatever we couldn't consume so we always make progress.
        if i == start {
            i += 1;
        }
    }
    results
}

/// A `key=value` or `key: value` pair detected inside an extracted string.
#[derive(Debug, Clone)]
pub struct KeyValuePair {
    /// File offset of the source string.
    pub offset: u64,
    /// File length of the source string.
    pub length: u64,
    pub key: String,
    pub value: String,
}

impl KeyValuePair {
    pub fn range(&self) -> ByteRange {
        ByteRange::new(self.offset, self.length)
    }
}

/// Scan extracted strings for entire `key=value` or `key: value` lines and
/// return them as structured pairs. Conservative: keys must start with a
/// letter and only contain alphanumeric / `_` / `-` / `.`; the `:` separator
/// requires a following space (HTTP-header style) so URLs and times don't
/// match. Strings that aren't whole key-value lines (prose, log lines with
/// inline `=`, etc.) are ignored.
pub fn detect_key_value_pairs(strings: &[StringRegion]) -> Vec<KeyValuePair> {
    let mut pairs = Vec::new();
    for s in strings {
        if let Some((key, value)) = parse_kv_line(&s.content) {
            pairs.push(KeyValuePair {
                offset: s.offset,
                length: s.length,
                key,
                value,
            });
        }
    }
    pairs
}

fn parse_kv_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    let bytes = trimmed.as_bytes();
    let first = *bytes.first()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    // Walk the key prefix until we hit a separator or invalid char.
    let mut sep_pos = None;
    let mut sep_kind = b'=';
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'=' || b == b':' {
            sep_pos = Some(i);
            sep_kind = b;
            break;
        }
        if !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.') {
            return None;
        }
    }
    let sep_pos = sep_pos?;
    if sep_pos == 0 {
        return None;
    }
    let key = trimmed[..sep_pos].trim().to_string();
    if key.is_empty() {
        return None;
    }
    let mut value_start = sep_pos + 1;
    // ':' separator requires a following space — HTTP-header / YAML-like.
    // This rejects URLs, times, and similar non-pair colons.
    if sep_kind == b':' {
        if value_start >= bytes.len() || bytes[value_start] != b' ' {
            return None;
        }
        value_start += 1;
    }
    let value = trimmed[value_start..].trim();
    if value.is_empty() {
        return None;
    }
    Some((key, value.to_string()))
}

/// Encoding scheme inferred for a string region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingKind {
    /// All characters are `[0-9A-Fa-f]`, the length is even, and at least one
    /// character is a hex letter (so pure-decimal strings don't match).
    Hex,
    /// Standard or URL-safe base64 alphabet, length divisible by 4 (modulo
    /// trailing `=` padding), with a healthy mix of upper / lower / digit
    /// characters so prose doesn't match.
    Base64,
}

impl EncodingKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Hex => "Hex",
            Self::Base64 => "Base64",
        }
    }
}

/// A string region whose content was classified as a known encoding.
#[derive(Debug, Clone)]
pub struct EncodedSection {
    pub offset: u64,
    pub length: u64,
    pub kind: EncodingKind,
    /// First few characters for display in the analysis tree.
    pub preview: String,
}

impl EncodedSection {
    pub fn range(&self) -> ByteRange {
        ByteRange::new(self.offset, self.length)
    }
}

/// Walk extracted strings and report any whose content is plausibly an
/// encoded blob (hex or base64) and at least `min_len` characters long.
/// Conservative on both forms — see [`EncodingKind`] for the rules.
///
/// `data` is the original byte buffer that produced `strings`, with `data[0]`
/// representing file offset `data_base_offset`. Classification runs against
/// the full byte run for each region (slicing back into `data`) rather than
/// the cached `StringRegion::content` prefix, so very long runs whose
/// suffix isn't actually hex/base64 don't get over-claimed when only the
/// prefix would have qualified.
pub fn detect_encoded_sections(
    strings: &[StringRegion],
    data: &[u8],
    data_base_offset: u64,
    min_len: usize,
) -> Vec<EncodedSection> {
    let mut results = Vec::new();
    for s in strings {
        let Some(local_start) = s.offset.checked_sub(data_base_offset) else {
            continue;
        };
        let local_start = local_start as usize;
        let Some(local_end) = local_start.checked_add(s.length as usize) else {
            continue;
        };
        if local_end > data.len() {
            continue;
        }
        // Extracted runs are guaranteed printable ASCII (or valid UTF-8 for
        // the UTF-8 extractor), so from_utf8_lossy is allocation-free for
        // the common ASCII case and never produces replacement chars here.
        let full = String::from_utf8_lossy(&data[local_start..local_end]);
        if let Some(kind) = classify_encoding(&full, min_len) {
            let preview: String = full.chars().take(32).collect();
            let preview = if full.chars().count() > 32 {
                format!("{preview}...")
            } else {
                preview
            };
            results.push(EncodedSection {
                offset: s.offset,
                length: s.length,
                kind,
                preview,
            });
        }
    }
    results
}

/// Classify a candidate string. Hex is preferred over base64 when both
/// would qualify (hex's character set is a strict subset).
pub fn classify_encoding(content: &str, min_len: usize) -> Option<EncodingKind> {
    if content.len() < min_len {
        return None;
    }
    if is_hex_blob(content) {
        return Some(EncodingKind::Hex);
    }
    if is_base64_blob(content) {
        return Some(EncodingKind::Base64);
    }
    None
}

fn is_hex_blob(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return false;
    }
    let mut has_letter = false;
    for &b in bytes {
        match b {
            b'0'..=b'9' => {}
            b'a'..=b'f' | b'A'..=b'F' => has_letter = true,
            _ => return false,
        }
    }
    has_letter
}

fn is_base64_blob(s: &str) -> bool {
    let trimmed = s.trim_end_matches('=');
    let pad = s.len() - trimmed.len();
    if pad > 2 || (trimmed.len() + pad) % 4 != 0 {
        return false;
    }
    let mut has_digit = false;
    let mut has_upper = false;
    let mut has_lower = false;
    for &b in trimmed.as_bytes() {
        match b {
            b'0'..=b'9' => has_digit = true,
            b'A'..=b'Z' => has_upper = true,
            b'a'..=b'z' => has_lower = true,
            b'+' | b'/' | b'-' | b'_' => {}
            _ => return false,
        }
    }
    has_digit && has_upper && has_lower
}

/// Group nearby strings into logical clusters.
///
/// Strings within `gap_threshold` bytes of each other are grouped together.
/// Returns (group_offset, group_length, strings_in_group).
pub fn group_strings(strings: &[StringRegion], gap_threshold: u64) -> Vec<(u64, u64, Vec<usize>)> {
    if strings.is_empty() {
        return Vec::new();
    }
    let mut groups: Vec<(u64, u64, Vec<usize>)> = Vec::new();
    let mut current_start = strings[0].offset;
    let mut current_end = strings[0].offset + strings[0].length;
    let mut current_indices = vec![0usize];

    for (i, s) in strings.iter().enumerate().skip(1) {
        if s.offset <= current_end + gap_threshold {
            current_end = current_end.max(s.offset + s.length);
            current_indices.push(i);
        } else {
            groups.push((current_start, current_end - current_start, current_indices));
            current_start = s.offset;
            current_end = s.offset + s.length;
            current_indices = vec![i];
        }
    }
    groups.push((current_start, current_end - current_start, current_indices));
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_strings() {
        let data = b"\x00\x00Hello World\x00\x00\x00test\x00";
        let strings = extract_strings(data, 0, 4, 200);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].content, "Hello World");
        assert_eq!(strings[0].offset, 2);
        assert_eq!(strings[1].content, "test");
    }

    #[test]
    fn skips_short_runs() {
        let data = b"\x00ab\x00cdef\x00";
        let strings = extract_strings(data, 0, 4, 200);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].content, "cdef");
    }

    #[test]
    fn respects_base_offset() {
        let data = b"Hello\x00";
        let strings = extract_strings(data, 100, 4, 200);
        assert_eq!(strings[0].offset, 100);
    }

    #[test]
    fn min_string_len_is_honored() {
        let data = b"\x00ab\x00cdef\x00";
        let strict = extract_strings(data, 0, 5, 200);
        assert!(strict.is_empty(), "5-char threshold should reject 'cdef'");
        let loose = extract_strings(data, 0, 2, 200);
        assert_eq!(loose.len(), 2, "2-char threshold should accept 'ab'");
    }

    #[test]
    fn max_strings_zero_returns_empty() {
        let data = b"hello\x00world\x00trailing";
        let strings = extract_strings(data, 0, 4, 0);
        assert!(
            strings.is_empty(),
            "max_strings=0 must yield no results, not 1"
        );
    }

    #[test]
    fn max_strings_caps_inline_and_trailing_runs() {
        // Two qualifying inline runs plus one trailing run that would push the
        // count past the cap if the trailing branch ignored it.
        let data = b"alpha\x00bravo\x00charlie";
        let strings = extract_strings(data, 0, 4, 1);
        assert_eq!(strings.len(), 1, "should stop at cap on inline branch");

        let strings = extract_strings(data, 0, 4, 2);
        assert_eq!(strings.len(), 2, "trailing branch must respect the cap too");
    }

    #[test]
    fn utf8_extraction_finds_non_ascii_runs() {
        // "héllo" — contains a 2-byte UTF-8 char (é = 0xC3 0xA9).
        let data = b"\x00\x00h\xc3\xa9llo\x00";
        let strings = extract_utf8_strings(data, 0, 4, 10);
        assert_eq!(strings.len(), 1, "should find one UTF-8 run");
        assert_eq!(strings[0].content, "héllo");
        assert_eq!(strings[0].offset, 2);
    }

    #[test]
    fn utf8_extraction_skips_pure_ascii_runs() {
        // ASCII-only — already covered by extract_strings, must NOT
        // duplicate it here.
        let data = b"\x00plain ascii text\x00";
        let strings = extract_utf8_strings(data, 0, 4, 10);
        assert!(
            strings.is_empty(),
            "pure-ASCII should not be reported by extract_utf8_strings"
        );
    }

    #[test]
    fn utf8_extraction_handles_cjk() {
        // "日本語" — three 3-byte CJK codepoints.
        let data = b"\x00\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\x00";
        let strings = extract_utf8_strings(data, 0, 3, 10);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].content, "日本語");
    }

    #[test]
    fn utf8_extraction_min_chars_counts_codepoints_not_bytes() {
        // 2-char CJK = 6 bytes. min_chars=3 should reject.
        let data = b"\xe6\x97\xa5\xe6\x9c\xac\x00";
        assert!(extract_utf8_strings(data, 0, 3, 10).is_empty());
        // min_chars=2 should accept.
        assert_eq!(extract_utf8_strings(data, 0, 2, 10).len(), 1);
    }

    #[test]
    fn utf8_extraction_breaks_on_invalid_sequence() {
        // Valid "héllo", then a stray 0xFF, then more text.
        let data = b"h\xc3\xa9llo\xff\x00more";
        let strings = extract_utf8_strings(data, 0, 4, 10);
        // Only the first run is reported (the trailing "more" is pure ASCII).
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].content, "héllo");
    }

    #[test]
    fn utf8_extraction_max_strings_zero_returns_empty() {
        let data = b"h\xc3\xa9llo";
        assert!(extract_utf8_strings(data, 0, 4, 0).is_empty());
    }

    fn region(content: &str) -> StringRegion {
        StringRegion {
            offset: 0,
            length: content.len() as u64,
            content: content.into(),
        }
    }

    #[test]
    fn parses_equals_pair() {
        let s = vec![region("name=Alice")];
        let pairs = detect_key_value_pairs(&s);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].key, "name");
        assert_eq!(pairs[0].value, "Alice");
    }

    #[test]
    fn parses_http_header_pair() {
        let s = vec![region("Content-Type: application/json")];
        let pairs = detect_key_value_pairs(&s);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].key, "Content-Type");
        assert_eq!(pairs[0].value, "application/json");
    }

    #[test]
    fn rejects_prose() {
        let s = vec![
            region("This is a sentence with words"),
            region("hello world"),
        ];
        assert!(detect_key_value_pairs(&s).is_empty());
    }

    #[test]
    fn rejects_url_like_colon_without_space() {
        // "https://example.com" should NOT match a key-value pattern.
        let s = vec![region("https://example.com")];
        assert!(detect_key_value_pairs(&s).is_empty());
    }

    #[test]
    fn rejects_arithmetic_with_equals() {
        let s = vec![region("2+2=4")];
        assert!(detect_key_value_pairs(&s).is_empty());
    }

    #[test]
    fn rejects_key_starting_with_digit() {
        let s = vec![region("9foo=bar")];
        assert!(detect_key_value_pairs(&s).is_empty());
    }

    #[test]
    fn rejects_pair_with_empty_value() {
        let s = vec![region("key=")];
        assert!(detect_key_value_pairs(&s).is_empty());
    }

    #[test]
    fn rejects_pair_with_space_in_key() {
        // Inline kv inside a sentence — conservative scanner ignores.
        let s = vec![region("the answer is x=42")];
        assert!(detect_key_value_pairs(&s).is_empty());
    }

    #[test]
    fn classifies_hex_blob() {
        // 24 chars, has hex letters, even length.
        assert_eq!(
            classify_encoding("deadbeef0123456789abcdef", 16),
            Some(EncodingKind::Hex)
        );
    }

    #[test]
    fn rejects_pure_decimal_as_hex() {
        // "1234567890" is even length but contains no hex letters — likely
        // a number, not a hex blob.
        assert_eq!(classify_encoding("1234567890", 8), None);
    }

    #[test]
    fn rejects_odd_length_hex() {
        assert_eq!(classify_encoding("deadbee", 4), None);
    }

    #[test]
    fn classifies_base64_blob() {
        // "Hello World" base64 = "SGVsbG8gV29ybGQ=" — 16 chars, mixed case,
        // has digits, ends with single '=' padding.
        assert_eq!(
            classify_encoding("SGVsbG8gV29ybGQ=", 16),
            Some(EncodingKind::Base64)
        );
    }

    #[test]
    fn rejects_short_string() {
        assert_eq!(classify_encoding("deadbeef", 16), None);
    }

    #[test]
    fn rejects_prose_as_base64() {
        // Long enough, divisible by 4, but no digits and no upper case — fails
        // the character-mix requirement.
        assert_eq!(
            classify_encoding("hellohellohellohello", 16),
            None,
            "lowercase prose must not pass base64 classification"
        );
    }

    #[test]
    fn rejects_pure_uppercase_as_base64() {
        // 16 uppercase chars, no digits, no lowercase → fails mix.
        assert_eq!(classify_encoding("ABCDEFGHIJKLMNOP", 16), None);
    }

    #[test]
    fn long_hex_blob_survives_extraction_and_classifies() {
        // 600-char hex blob — well above the old 256-char cap that used to
        // mutate content with a "..." marker and break classification.
        let mut data = vec![0x00; 8];
        let hex: String = std::iter::repeat("deadbeef").take(75).collect();
        assert_eq!(hex.len(), 600);
        data.extend_from_slice(hex.as_bytes());
        data.push(0x00);

        let strings = extract_strings(&data, 0, 4, 200);
        assert_eq!(strings.len(), 1);
        // The cached content must be valid hex chars only — no "..." marker.
        assert!(
            strings[0].content.chars().all(|c| c.is_ascii_hexdigit()),
            "cached content must not contain display markers; got: {:?}",
            &strings[0].content[..32.min(strings[0].content.len())]
        );
        // The full run length is still recorded even though content may be
        // capped at MAX_STRING_LEN.
        assert_eq!(strings[0].length, 600);

        let sections = detect_encoded_sections(&strings, &data, 0, 32);
        assert_eq!(
            sections.len(),
            1,
            "long hex blob must classify as Hex even when content is bounded"
        );
        assert_eq!(sections[0].kind, EncodingKind::Hex);
        assert_eq!(sections[0].length, 600, "section length follows the run");
    }

    #[test]
    fn very_long_hex_blob_is_capped_but_still_classifies() {
        // Push beyond the 4096-char cap to make sure the hard cap path works.
        let mut data = vec![0x00; 4];
        let hex: String = std::iter::repeat("deadbeef").take(1000).collect(); // 8000 chars
        data.extend_from_slice(hex.as_bytes());
        data.push(0x00);

        let strings = extract_strings(&data, 0, 4, 200);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].length, 8000, "full length is preserved");
        assert!(
            strings[0].content.len() <= MAX_STRING_LEN,
            "cached content is bounded"
        );
        assert!(strings[0].content.chars().all(|c| c.is_ascii_hexdigit()));
        let sections = detect_encoded_sections(&strings, &data, 0, 32);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].kind, EncodingKind::Hex);
    }

    #[test]
    fn long_base64_blob_classifies_after_extraction() {
        // 400-char base64-shaped blob with mixed-case + digits.
        let mut data = vec![0x00; 4];
        let chunk = "SGVsbG8gV29ybGQgZm9vYmFy";
        let b64: String = std::iter::repeat(chunk).take(20).collect();
        // 24 * 20 = 480 chars (but spaces inside chunk break the printable
        // run — switch to a no-space sample).
        let _ = b64;
        let chunk_clean = "SGVsbG8wV29ybGQwZm9vYmFy"; // 24 chars, all base64-valid
        let b64: String = std::iter::repeat(chunk_clean).take(20).collect(); // 480 chars
        assert_eq!(b64.len(), 480);
        data.extend_from_slice(b64.as_bytes());
        data.push(0x00);

        let strings = extract_strings(&data, 0, 4, 200);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].length, 480);
        let sections = detect_encoded_sections(&strings, &data, 0, 32);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].kind, EncodingKind::Base64);
        assert_eq!(sections[0].length, 480);
    }

    #[test]
    fn long_run_with_encoded_prefix_and_prose_suffix_is_rejected() {
        // 4096 valid hex chars followed by 200 prose chars, all in one
        // contiguous printable run. The cached content (capped at
        // MAX_STRING_LEN = 4096) holds only the hex prefix, so a
        // prefix-only classifier would over-claim this as Hex. The
        // full-byte-run validator must reject it.
        let mut data = vec![0x00; 4];
        let hex: String = std::iter::repeat("deadbeef").take(512).collect();
        assert_eq!(hex.len(), 4096);
        data.extend_from_slice(hex.as_bytes());
        // Prose suffix — printable ASCII so it stays in the same string run.
        data.extend_from_slice(b" hello world this is not hex");
        data.push(0x00);

        let strings = extract_strings(&data, 0, 4, 200);
        assert_eq!(strings.len(), 1);
        let s = &strings[0];
        assert_eq!(s.length as usize, 4096 + 28);
        // Cached content was capped — the prefix is hex.
        assert!(s.content.chars().all(|c| c.is_ascii_hexdigit()));
        // But the full run is mixed, so classification must reject it.
        let sections = detect_encoded_sections(&strings, &data, 0, 32);
        assert!(
            sections.is_empty(),
            "mixed-content long run must not be over-claimed; got {:?}",
            sections.iter().map(|s| s.kind).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_encoded_sections_filters_short_and_prose() {
        // Build a single backing buffer with each candidate at a unique
        // offset so the validator can slice the full byte run for each.
        let candidates: &[&str] = &[
            "deadbeef0123456789abcdef", // hex, 24 chars
            "SGVsbG8gV29ybGQ=",         // base64, 16 chars
            "ab12",                     // too short
            "hello world",              // prose
        ];
        let mut data = Vec::new();
        let mut regions = Vec::new();
        for c in candidates {
            let offset = data.len() as u64;
            data.extend_from_slice(c.as_bytes());
            data.push(0x00); // separator
            regions.push(StringRegion {
                offset,
                length: c.len() as u64,
                content: (*c).to_string(),
            });
        }
        let sections = detect_encoded_sections(&regions, &data, 0, 16);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].kind, EncodingKind::Hex);
        assert_eq!(sections[1].kind, EncodingKind::Base64);
    }

    #[test]
    fn parses_dotted_and_underscored_keys() {
        let s = vec![region("log.level=debug"), region("api_key=abc123")];
        let pairs = detect_key_value_pairs(&s);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].key, "log.level");
        assert_eq!(pairs[1].key, "api_key");
    }

    #[test]
    fn groups_nearby_strings() {
        let strings = vec![
            StringRegion {
                offset: 0,
                length: 5,
                content: "Hello".into(),
            },
            StringRegion {
                offset: 8,
                length: 5,
                content: "World".into(),
            },
            StringRegion {
                offset: 100,
                length: 4,
                content: "test".into(),
            },
        ];
        let groups = group_strings(&strings, 10);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].2.len(), 2); // first group has 2 strings
        assert_eq!(groups[1].2.len(), 1); // second group has 1 string
    }
}
