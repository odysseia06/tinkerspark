/// Direction for search operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchDirection {
    Forward,
    Backward,
}

/// What to search for.
#[derive(Debug, Clone)]
pub enum SearchQuery {
    /// Search for an exact byte pattern.
    Bytes(Vec<u8>),
    /// Search for a UTF-8 text string (case-sensitive byte match).
    Text(String),
}

impl SearchQuery {
    pub fn pattern_bytes(&self) -> &[u8] {
        match self {
            SearchQuery::Bytes(b) => b,
            SearchQuery::Text(s) => s.as_bytes(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pattern_bytes().is_empty()
    }
}

/// A search hit with its file offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchHit {
    pub offset: u64,
    pub length: usize,
}

/// Search for a pattern in a byte slice, starting from a given offset within
/// that slice. Returns the offset relative to the slice start.
///
/// This is the core search primitive. The caller is responsible for reading
/// appropriate chunks from the ByteSource and translating offsets.
pub fn find_in_slice(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    if start + needle.len() > haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|pos| pos + start)
}

/// Search backward in a byte slice from a given position.
/// Returns the offset relative to the slice start.
pub fn rfind_in_slice(haystack: &[u8], needle: &[u8], before: usize) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    // Last valid start position for a match at or before `before`.
    let last_start = before.min(haystack.len() - needle.len());
    // Slice must include enough bytes for the last window.
    let slice_end = last_start + needle.len();
    haystack[..slice_end]
        .windows(needle.len())
        .rposition(|w| w == needle)
}

/// Parse a hex string like "FF 00 AB" or "ff00ab" into bytes.
/// Tolerates spaces and mixed case.
pub fn parse_hex_pattern(input: &str) -> Option<Vec<u8>> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() || !clean.len().is_multiple_of(2) {
        return None;
    }
    let mut result = Vec::with_capacity(clean.len() / 2);
    for chunk in clean.as_bytes().chunks(2) {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        result.push((hi << 4) | lo);
    }
    Some(result)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Search a ByteSource in fixed-size chunks to avoid loading the entire file.
///
/// Chunks overlap by `needle.len() - 1` bytes so matches that span chunk
/// boundaries are not missed. Returns the first hit at or after `start_offset`
/// in the forward direction, or the last hit at or before `start_offset` in
/// the backward direction.
pub fn search_chunked(
    source: &dyn tinkerspark_core_bytes::ByteSource,
    needle: &[u8],
    start_offset: u64,
    direction: SearchDirection,
) -> Option<SearchHit> {
    let file_len = source.len();
    if needle.is_empty() || file_len == 0 || needle.len() as u64 > file_len {
        return None;
    }

    let overlap = (needle.len() - 1) as u64;
    // The chunk must always be larger than the overlap so the scan advances.
    // If the needle itself is bigger than the default chunk, grow the chunk.
    const BASE_CHUNK: u64 = 256 * 1024; // 256 KiB
    let chunk_size = BASE_CHUNK.max(needle.len() as u64 + overlap);

    match direction {
        SearchDirection::Forward => {
            // First pass: from start_offset to end of file.
            if let Some(hit) =
                search_forward_range(source, needle, start_offset, file_len, chunk_size, overlap)
            {
                return Some(hit);
            }
            // Wrap: from 0 to start_offset + needle.len() (to cover the start position).
            let wrap_end = (start_offset + needle.len() as u64).min(file_len);
            search_forward_range(source, needle, 0, wrap_end, chunk_size, overlap)
        }
        SearchDirection::Backward => {
            // First pass: from start_offset backward to 0.
            if let Some(hit) =
                search_backward_range(source, needle, start_offset, chunk_size, overlap)
            {
                return Some(hit);
            }
            // Wrap: from end of file backward to start_offset.
            let wrap_start = file_len.saturating_sub(1);
            if wrap_start > start_offset {
                search_backward_range(source, needle, wrap_start, chunk_size, overlap)
            } else {
                None
            }
        }
    }
}

fn search_forward_range(
    source: &dyn tinkerspark_core_bytes::ByteSource,
    needle: &[u8],
    from: u64,
    to: u64,
    chunk_size: u64,
    overlap: u64,
) -> Option<SearchHit> {
    use tinkerspark_core_types::ByteRange;

    let file_len = source.len();
    let mut chunk_start = from;

    while chunk_start < to {
        let chunk_end = (chunk_start + chunk_size).min(file_len);
        let range = ByteRange::new(chunk_start, chunk_end - chunk_start);
        let data = source.read_range(range).ok()?;

        // Search within this chunk. The local start offset handles the
        // first chunk where we need to skip bytes before `from`.
        let local_start = 0;
        if let Some(pos) = find_in_slice(&data, needle, local_start) {
            let file_offset = chunk_start + pos as u64;
            if file_offset < to {
                return Some(SearchHit {
                    offset: file_offset,
                    length: needle.len(),
                });
            }
        }

        // Advance by at least one byte, stepping back by overlap so we don't
        // miss cross-boundary matches.
        let next = chunk_end.saturating_sub(overlap);
        if next <= chunk_start || chunk_end >= to.min(file_len) {
            break;
        }
        chunk_start = next;
    }
    None
}

fn search_backward_range(
    source: &dyn tinkerspark_core_bytes::ByteSource,
    needle: &[u8],
    from: u64,
    chunk_size: u64,
    overlap: u64,
) -> Option<SearchHit> {
    use tinkerspark_core_types::ByteRange;

    let file_len = source.len();
    // We scan chunks from the `from` position backward to 0.
    let mut chunk_end = (from + needle.len() as u64).min(file_len);

    loop {
        let chunk_start = chunk_end.saturating_sub(chunk_size).min(chunk_end);
        let range = ByteRange::new(chunk_start, chunk_end - chunk_start);
        let data = source.read_range(range).ok()?;

        // The `before` offset within this chunk: we want matches whose start
        // position (in file coords) is <= from.
        let local_before = if from >= chunk_start {
            (from - chunk_start) as usize
        } else {
            0
        };

        if let Some(pos) = rfind_in_slice(&data, needle, local_before) {
            return Some(SearchHit {
                offset: chunk_start + pos as u64,
                length: needle.len(),
            });
        }

        if chunk_start == 0 {
            break;
        }
        // Move the window backward, keeping overlap. Ensure progress.
        let next_end = chunk_start + overlap;
        if next_end >= chunk_end {
            break;
        }
        chunk_end = next_end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_in_slice_basic() {
        let data = b"hello world";
        assert_eq!(find_in_slice(data, b"world", 0), Some(6));
        assert_eq!(find_in_slice(data, b"hello", 0), Some(0));
        assert_eq!(find_in_slice(data, b"xyz", 0), None);
    }

    #[test]
    fn find_in_slice_with_start() {
        let data = b"abcabc";
        assert_eq!(find_in_slice(data, b"abc", 0), Some(0));
        assert_eq!(find_in_slice(data, b"abc", 1), Some(3));
        assert_eq!(find_in_slice(data, b"abc", 4), None);
    }

    #[test]
    fn find_in_slice_empty_needle() {
        assert_eq!(find_in_slice(b"abc", b"", 0), None);
    }

    #[test]
    fn find_in_slice_needle_too_long() {
        assert_eq!(find_in_slice(b"ab", b"abc", 0), None);
    }

    #[test]
    fn rfind_in_slice_basic() {
        let data = b"abcabc";
        assert_eq!(rfind_in_slice(data, b"abc", 5), Some(3));
        assert_eq!(rfind_in_slice(data, b"abc", 2), Some(0));
    }

    #[test]
    fn rfind_in_slice_not_found() {
        assert_eq!(rfind_in_slice(b"abcdef", b"xyz", 5), None);
    }

    #[test]
    fn parse_hex_pattern_spaced() {
        assert_eq!(parse_hex_pattern("FF 00 AB"), Some(vec![0xFF, 0x00, 0xAB]));
    }

    #[test]
    fn parse_hex_pattern_compact() {
        assert_eq!(parse_hex_pattern("ff00ab"), Some(vec![0xFF, 0x00, 0xAB]));
    }

    #[test]
    fn parse_hex_pattern_invalid() {
        assert_eq!(parse_hex_pattern("FG"), None);
        assert_eq!(parse_hex_pattern("F"), None); // odd length
        assert_eq!(parse_hex_pattern(""), None);
    }

    #[test]
    fn search_query_bytes() {
        let q = SearchQuery::Bytes(vec![0xFF, 0x00]);
        assert_eq!(q.pattern_bytes(), &[0xFF, 0x00]);
        assert!(!q.is_empty());
    }

    #[test]
    fn search_query_text() {
        let q = SearchQuery::Text("hello".to_string());
        assert_eq!(q.pattern_bytes(), b"hello");
    }

    #[test]
    fn chunked_search_forward() {
        let data = b"aaaa_hello_bbbbb".to_vec();
        let src = tinkerspark_core_bytes::MemoryByteSource::new(data);
        let hit = search_chunked(&src, b"hello", 0, SearchDirection::Forward);
        assert_eq!(
            hit,
            Some(SearchHit {
                offset: 5,
                length: 5
            })
        );
    }

    #[test]
    fn chunked_search_forward_wraps() {
        let data = b"hello____".to_vec();
        let src = tinkerspark_core_bytes::MemoryByteSource::new(data);
        // Start after the match — should wrap and find it.
        let hit = search_chunked(&src, b"hello", 6, SearchDirection::Forward);
        assert_eq!(
            hit,
            Some(SearchHit {
                offset: 0,
                length: 5
            })
        );
    }

    #[test]
    fn chunked_search_backward() {
        let data = b"aaa_hello_bbb".to_vec();
        let src = tinkerspark_core_bytes::MemoryByteSource::new(data);
        let hit = search_chunked(&src, b"hello", 12, SearchDirection::Backward);
        assert_eq!(
            hit,
            Some(SearchHit {
                offset: 4,
                length: 5
            })
        );
    }

    #[test]
    fn chunked_search_not_found() {
        let data = b"abcdefgh".to_vec();
        let src = tinkerspark_core_bytes::MemoryByteSource::new(data);
        let hit = search_chunked(&src, b"xyz", 0, SearchDirection::Forward);
        assert_eq!(hit, None);
    }

    #[test]
    fn chunked_search_empty_needle() {
        let data = b"abc".to_vec();
        let src = tinkerspark_core_bytes::MemoryByteSource::new(data);
        assert_eq!(search_chunked(&src, b"", 0, SearchDirection::Forward), None);
    }

    #[test]
    fn chunked_search_needle_longer_than_base_chunk() {
        // Needle bigger than the 256 KiB base chunk size.
        // The chunk_size should auto-grow so the scan still works.
        let needle_len = 300_000; // ~293 KiB, exceeds 256 KiB base
        let prefix = vec![0u8; 100];
        let needle: Vec<u8> = (0..needle_len).map(|i| (i % 251) as u8).collect();
        let suffix = vec![0u8; 100];
        let mut data = Vec::with_capacity(prefix.len() + needle.len() + suffix.len());
        data.extend_from_slice(&prefix);
        data.extend_from_slice(&needle);
        data.extend_from_slice(&suffix);

        let src = tinkerspark_core_bytes::MemoryByteSource::new(data);
        let hit = search_chunked(&src, &needle, 0, SearchDirection::Forward);
        assert_eq!(
            hit,
            Some(SearchHit {
                offset: 100,
                length: needle_len,
            })
        );
    }

    #[test]
    fn chunked_search_needle_equals_file() {
        // Needle is the entire file — should match at offset 0.
        let data = b"exactmatch".to_vec();
        let src = tinkerspark_core_bytes::MemoryByteSource::new(data.clone());
        let hit = search_chunked(&src, &data, 0, SearchDirection::Forward);
        assert_eq!(
            hit,
            Some(SearchHit {
                offset: 0,
                length: 10,
            })
        );
    }
}
