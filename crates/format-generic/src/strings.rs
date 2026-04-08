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

/// Maximum length of a single extracted string (truncate longer runs).
const MAX_STRING_LEN: usize = 256;

fn is_printable(b: u8) -> bool {
    b.is_ascii_graphic() || b == b' ' || b == b'\t'
}

/// Extract runs of printable ASCII strings from the data.
///
/// Returns up to `max_strings` results, each at least `min_string_len` bytes.
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
                let display_len = len.min(MAX_STRING_LEN);
                let content = String::from_utf8_lossy(&data[start..start + display_len]);
                let mut content = content.into_owned();
                if len > MAX_STRING_LEN {
                    content.push_str("...");
                }
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
            let display_len = len.min(MAX_STRING_LEN);
            let content = String::from_utf8_lossy(&data[start..start + display_len]);
            let mut content = content.into_owned();
            if len > MAX_STRING_LEN {
                content.push_str("...");
            }
            results.push(StringRegion {
                offset: base_offset + start as u64,
                length: len as u64,
                content,
            });
        }
    }

    results
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
