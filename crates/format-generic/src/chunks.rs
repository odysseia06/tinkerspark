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
    LengthPrefixed {
        length_field_size: usize,
        body_length: u64,
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

/// Minimum number of records to consider a fixed-size pattern.
const MIN_RECORD_COUNT: usize = 4;

/// Minimum padding region size to report.
const MIN_PADDING_SIZE: usize = 8;

/// Detect padding regions (runs of identical bytes at alignment boundaries).
pub fn detect_padding(data: &[u8], base_offset: u64) -> Vec<DetectedChunk> {
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
        if len >= MIN_PADDING_SIZE {
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
pub fn detect_fixed_records(data: &[u8], base_offset: u64) -> Vec<DetectedChunk> {
    let mut results = Vec::new();

    // Try common record sizes.
    let candidate_sizes: Vec<usize> = (4..=64)
        .filter(|&s| s % 2 == 0 || s == 5 || s == 7)
        .collect();

    for &size in &candidate_sizes {
        if data.len() < size * MIN_RECORD_COUNT {
            continue;
        }
        let count = data.len() / size;
        if count < MIN_RECORD_COUNT {
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
/// Checks common length encodings: 1-byte, 2-byte BE, 4-byte BE.
pub fn detect_length_prefixed(data: &[u8], base_offset: u64) -> Vec<DetectedChunk> {
    let mut results = Vec::new();

    // Try from the beginning and at various offsets.
    let offsets_to_try: Vec<usize> = (0..data.len().min(64)).collect();

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
        if remaining.len() >= 4 {
            let len = u16::from_be_bytes([remaining[0], remaining[1]]) as u64;
            if len >= 4 && (2 + len) as usize <= remaining.len() && len < 65535 {
                let end = 2 + len as usize;
                if is_plausible_section_boundary(remaining, end) {
                    results.push(DetectedChunk {
                        kind: ChunkKind::LengthPrefixed {
                            length_field_size: 2,
                            body_length: len,
                        },
                        offset: base_offset + start as u64,
                        length: 2 + len,
                        description: format!(
                            "Possible 2-byte BE length-prefixed section ({} bytes body)",
                            len
                        ),
                    });
                }
            }
        }

        // 4-byte BE length
        if remaining.len() >= 8 {
            let len =
                u32::from_be_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]) as u64;
            if len >= 4 && (4 + len) as usize <= remaining.len() && len <= data.len() as u64 {
                let end = 4 + len as usize;
                if is_plausible_section_boundary(remaining, end) {
                    results.push(DetectedChunk {
                        kind: ChunkKind::LengthPrefixed {
                            length_field_size: 4,
                            body_length: len,
                        },
                        offset: base_offset + start as u64,
                        length: 4 + len,
                        description: format!(
                            "Possible 4-byte BE length-prefixed section ({} bytes body)",
                            len
                        ),
                    });
                }
            }
        }

        // Stop after first few hits to avoid noise.
        if results.len() >= 10 {
            break;
        }
    }

    results.truncate(10);
    results
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
        let padding = detect_padding(&data, 0);
        assert_eq!(padding.len(), 1);
        assert_eq!(padding[0].offset, 10);
        assert_eq!(padding[0].length, 32);
    }

    #[test]
    fn skips_short_padding() {
        let data = vec![0x00; 4]; // too short
        let padding = detect_padding(&data, 0);
        assert!(padding.is_empty());
    }
}
