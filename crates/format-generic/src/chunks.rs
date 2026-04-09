use tinkerspark_core_types::ByteRange;

/// A detected chunk or record-like structure in binary data.
#[derive(Debug, Clone)]
pub struct DetectedChunk {
    pub kind: ChunkKind,
    pub offset: u64,
    pub length: u64,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkKind {
    /// Repeated fixed-size records.
    FixedSizeRecords { record_size: usize, count: usize },
    /// Length-prefixed section (the length field encodes the body size).
    /// `big_endian` is meaningless for `length_field_size == 1` and is set
    /// to `true` for that case.
    LengthPrefixed {
        length_field_size: usize,
        body_length: u64,
        big_endian: bool,
    },
    /// Aligned padding region (zeros or repeated byte).
    Padding { pad_byte: u8 },
}

impl DetectedChunk {
    pub fn range(&self) -> ByteRange {
        ByteRange::new(self.offset, self.length)
    }
}

/// Common alignment boundaries to check.
const ALIGNMENTS: &[usize] = &[4, 8, 16, 32, 64, 512, 4096];

/// Detect padding regions (runs of identical bytes at alignment boundaries).
pub fn detect_padding(
    data: &[u8],
    base_offset: u64,
    min_padding_size: usize,
) -> Vec<DetectedChunk> {
    let mut results = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let b = data[i];
        // Only consider common padding bytes.
        if b != 0x00 && b != 0xFF && b != 0xCC && b != 0xAA {
            i += 1;
            continue;
        }
        let start = i;
        while i < data.len() && data[i] == b {
            i += 1;
        }
        let len = i - start;
        if len >= min_padding_size {
            // Check if it's at an alignment boundary.
            let at_alignment = ALIGNMENTS
                .iter()
                .any(|&a| (base_offset as usize + start) % a == 0);
            let desc = if at_alignment {
                format!("{} bytes of 0x{:02X} padding (aligned)", len, b)
            } else {
                format!("{} bytes of 0x{:02X} fill", len, b)
            };
            results.push(DetectedChunk {
                kind: ChunkKind::Padding { pad_byte: b },
                offset: base_offset + start as u64,
                length: len as u64,
                description: desc,
            });
        }
    }

    results
}

/// Try to detect repeated fixed-size records in a data region.
///
/// Looks for repeating structural patterns at common record sizes.
/// Returns detected patterns sorted by confidence (most records first).
pub fn detect_fixed_records(
    data: &[u8],
    base_offset: u64,
    min_record_count: usize,
) -> Vec<DetectedChunk> {
    let mut results = Vec::new();

    // Try common record sizes.
    let candidate_sizes: Vec<usize> = (4..=64)
        .filter(|&s| s % 2 == 0 || s == 5 || s == 7)
        .collect();

    for &size in &candidate_sizes {
        if data.len() < size * min_record_count {
            continue;
        }
        let count = data.len() / size;
        if count < min_record_count {
            continue;
        }

        // Heuristic: check if each record has a similar "shape" —
        // e.g., same byte at a fixed position, or similar byte distribution.
        let mut consistent_positions = 0;
        for pos in 0..size {
            let first_val = data[pos];
            let matches = (1..count.min(16))
                .filter(|&r| data[r * size + pos] == first_val)
                .count();
            if matches >= (count.min(16) - 1) / 2 {
                consistent_positions += 1;
            }
        }

        // Need at least 25% of positions to be consistent.
        if consistent_positions * 4 >= size {
            let covered = count * size;
            results.push(DetectedChunk {
                kind: ChunkKind::FixedSizeRecords {
                    record_size: size,
                    count,
                },
                offset: base_offset,
                length: covered as u64,
                description: format!(
                    "Possible {}-byte fixed records × {} ({} consistent positions)",
                    size, count, consistent_positions
                ),
            });
        }
    }

    // Sort by number of consistent positions (best first), keep only top few.
    results.truncate(3);
    results
}

/// Try to detect length-prefixed sections.
///
/// Checks common length encodings: 1-byte, 2-byte BE/LE, 4-byte BE/LE.
pub fn detect_length_prefixed(
    data: &[u8],
    base_offset: u64,
    scan_window: usize,
) -> Vec<DetectedChunk> {
    let mut results = Vec::new();

    // Try from the beginning and at various offsets.
    let offsets_to_try: Vec<usize> = (0..data.len().min(scan_window)).collect();

    for &start in &offsets_to_try {
        let remaining = &data[start..];

        // 1-byte length
        if remaining.len() >= 2 {
            let len = remaining[0] as u64;
            if len >= 4 && (1 + len) as usize <= remaining.len() && len < 256 {
                // Plausibility: the section should end at a reasonable point
                let end = 1 + len as usize;
                if is_plausible_section_boundary(remaining, end) {
                    results.push(DetectedChunk {
                        kind: ChunkKind::LengthPrefixed {
                            length_field_size: 1,
                            body_length: len,
                            big_endian: true,
                        },
                        offset: base_offset + start as u64,
                        length: 1 + len,
                        description: format!(
                            "Possible 1-byte length-prefixed section ({} bytes body)",
                            len
                        ),
                    });
                }
            }
        }

        // 2-byte BE length
        try_length_prefixed_int(&mut results, remaining, base_offset, start, 2, true);
        // 2-byte LE length
        try_length_prefixed_int(&mut results, remaining, base_offset, start, 2, false);
        // 4-byte BE length
        try_length_prefixed_int(&mut results, remaining, base_offset, start, 4, true);
        // 4-byte LE length
        try_length_prefixed_int(&mut results, remaining, base_offset, start, 4, false);

        // Stop after first few hits to avoid noise.
        if results.len() >= 10 {
            break;
        }
    }

    results.truncate(10);
    results
}

/// Try a single length-prefixed candidate at `start` with the given header
/// width and endianness, pushing into `results` on success.
fn try_length_prefixed_int(
    results: &mut Vec<DetectedChunk>,
    remaining: &[u8],
    base_offset: u64,
    start: usize,
    len_bytes: usize,
    big_endian: bool,
) {
    let header_len = len_bytes;
    if remaining.len() < header_len * 2 {
        return;
    }
    let len = match (len_bytes, big_endian) {
        (2, true) => u16::from_be_bytes([remaining[0], remaining[1]]) as u64,
        (2, false) => u16::from_le_bytes([remaining[0], remaining[1]]) as u64,
        (4, true) => {
            u32::from_be_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]) as u64
        }
        (4, false) => {
            u32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]) as u64
        }
        _ => return,
    };
    let max_len = match len_bytes {
        2 => 65_535u64,
        _ => u32::MAX as u64,
    };
    if len < 4 || (header_len as u64 + len) as usize > remaining.len() || len >= max_len {
        return;
    }
    let end = header_len + len as usize;
    if !is_plausible_section_boundary(remaining, end) {
        return;
    }
    let endianness_label = if big_endian { "BE" } else { "LE" };
    results.push(DetectedChunk {
        kind: ChunkKind::LengthPrefixed {
            length_field_size: len_bytes,
            body_length: len,
            big_endian,
        },
        offset: base_offset + start as u64,
        length: header_len as u64 + len,
        description: format!(
            "Possible {}-byte {} length-prefixed section ({} bytes body)",
            len_bytes, endianness_label, len
        ),
    });
}

/// Check if position `end` looks like a reasonable section boundary.
fn is_plausible_section_boundary(data: &[u8], end: usize) -> bool {
    if end >= data.len() {
        return end == data.len(); // Exactly at end of data is fine.
    }
    // Check if another length-prefixed section could follow.
    let next = data[end];
    // A new section often starts with a tag byte, type byte, or another length.
    // We just check it's not in the middle of a text run.
    next < 0x80 || next == 0x00 || next == 0xFF || next >= 0x30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_zero_padding() {
        let mut data = vec![0x42; 10];
        data.extend(vec![0x00; 32]);
        data.extend(vec![0x42; 10]);
        let padding = detect_padding(&data, 0, 8);
        assert_eq!(padding.len(), 1);
        assert_eq!(padding[0].offset, 10);
        assert_eq!(padding[0].length, 32);
    }

    #[test]
    fn skips_short_padding_with_default_threshold() {
        let data = vec![0x00; 4]; // too short for the default 8-byte threshold
        let padding = detect_padding(&data, 0, 8);
        assert!(padding.is_empty());
    }

    #[test]
    fn lower_threshold_finds_short_padding() {
        let data = vec![0x00; 4];
        let padding = detect_padding(&data, 0, 4);
        assert_eq!(padding.len(), 1, "4-byte threshold should accept this run");
    }

    #[test]
    fn detects_2byte_le_length_prefixed_section() {
        // 2-byte LE length = 0x0008 (8 bytes body), then 8 plausible bytes,
        // then a section boundary byte.
        let mut data = vec![0x08, 0x00];
        data.extend_from_slice(&[0x10; 8]);
        data.push(0x30); // boundary byte (>= 0x30, plausible)
        let chunks = detect_length_prefixed(&data, 0, 64);
        let le = chunks.iter().find(|c| {
            matches!(
                c.kind,
                ChunkKind::LengthPrefixed {
                    length_field_size: 2,
                    big_endian: false,
                    ..
                }
            )
        });
        assert!(
            le.is_some(),
            "should detect 2-byte LE length-prefixed section"
        );
        assert!(
            le.unwrap().description.contains("2-byte LE"),
            "description should label the LE encoding: {:?}",
            le.unwrap().description
        );
    }

    #[test]
    fn detects_4byte_le_length_prefixed_section() {
        // 4-byte LE length = 0x00000010 (16 bytes body).
        let mut data = vec![0x10, 0x00, 0x00, 0x00];
        data.extend_from_slice(&[0xAA; 16]);
        data.push(0x30);
        let chunks = detect_length_prefixed(&data, 0, 64);
        let le = chunks.iter().find(|c| {
            matches!(
                c.kind,
                ChunkKind::LengthPrefixed {
                    length_field_size: 4,
                    big_endian: false,
                    ..
                }
            )
        });
        assert!(
            le.is_some(),
            "should detect 4-byte LE length-prefixed section"
        );
        assert!(le.unwrap().description.contains("4-byte LE"));
    }

    #[test]
    fn le_and_be_detected_independently() {
        // A blob that parses as 2-byte LE 0x0008 OR 2-byte BE 0x0800 — only
        // the LE interpretation has enough following bytes to be plausible,
        // so the BE branch must NOT match.
        let mut data = vec![0x08, 0x00];
        data.extend_from_slice(&[0x42; 8]);
        data.push(0x30);
        let chunks = detect_length_prefixed(&data, 0, 64);
        let has_le = chunks.iter().any(|c| {
            matches!(
                c.kind,
                ChunkKind::LengthPrefixed {
                    length_field_size: 2,
                    big_endian: false,
                    ..
                }
            )
        });
        let has_be = chunks.iter().any(|c| {
            matches!(
                c.kind,
                ChunkKind::LengthPrefixed {
                    length_field_size: 2,
                    big_endian: true,
                    ..
                }
            )
        });
        assert!(has_le, "LE interpretation should match");
        assert!(!has_be, "BE interpretation should not over-claim this blob");
    }
}
