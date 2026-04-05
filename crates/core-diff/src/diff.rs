use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::ByteRange;

use crate::error::DiffSide;
use crate::{ChangedRange, DiffError, DiffResult};

/// Configuration for the diff algorithm.
#[derive(Debug, Clone)]
pub struct DiffConfig {
    /// Chunk size for reading from each source. Larger chunks reduce IO calls
    /// but use more memory. Default: 256 KiB.
    pub chunk_size: usize,
    /// Maximum gap (in bytes) between two changed regions that will still be
    /// coalesced into a single ChangedRange. Default: 0 (only truly adjacent
    /// changes are merged). Setting this higher produces fewer, larger ranges.
    pub coalesce_gap: u64,
}

impl Default for DiffConfig {
    fn default() -> Self {
        Self {
            chunk_size: 256 * 1024,
            coalesce_gap: 0,
        }
    }
}

/// Compare two byte sources byte-by-byte and return the list of changed ranges.
///
/// The algorithm reads both sources in aligned chunks, compares bytes within
/// each chunk, and coalesces consecutive differing bytes into ranges. A final
/// pass merges ranges separated by at most `config.coalesce_gap` bytes.
///
/// If the sources differ in length, the trailing bytes of the longer source
/// are reported as a single changed range.
///
/// Returns an error if either source fails to read a chunk.
pub fn compute_diff(
    left: &dyn ByteSource,
    right: &dyn ByteSource,
    config: &DiffConfig,
) -> Result<DiffResult, DiffError> {
    let left_len = left.len();
    let right_len = right.len();
    let common_len = left_len.min(right_len);
    let chunk_size = config.chunk_size.max(1) as u64;

    let mut raw_changes: Vec<ChangedRange> = Vec::new();

    // Compare the overlapping region in chunks.
    let mut offset: u64 = 0;
    while offset < common_len {
        let len = chunk_size.min(common_len - offset);
        let range = ByteRange::new(offset, len);

        let left_data = left.read_range(range).map_err(|e| DiffError::Read {
            side: DiffSide::Left,
            offset,
            source: e,
        })?;
        let right_data = right.read_range(range).map_err(|e| DiffError::Read {
            side: DiffSide::Right,
            offset,
            source: e,
        })?;

        // Scan for differing bytes within this chunk.
        let mut i = 0usize;
        let chunk_len = len as usize;
        while i < chunk_len {
            if left_data[i] != right_data[i] {
                // Found start of a difference. Scan to find its end.
                let start = i;
                while i < chunk_len && left_data[i] != right_data[i] {
                    i += 1;
                }
                let diff_len = (i - start) as u64;
                let abs_start = offset + start as u64;
                raw_changes.push(ChangedRange {
                    left: ByteRange::new(abs_start, diff_len),
                    right: ByteRange::new(abs_start, diff_len),
                });
            } else {
                i += 1;
            }
        }

        offset += len;
    }

    // If files differ in length, add a trailing range for the extra bytes.
    if left_len != right_len {
        let left_tail = left_len.saturating_sub(common_len);
        let right_tail = right_len.saturating_sub(common_len);
        raw_changes.push(ChangedRange {
            left: ByteRange::new(common_len.min(left_len), left_tail),
            right: ByteRange::new(common_len.min(right_len), right_tail),
        });
    }

    // Coalesce adjacent/nearby ranges.
    let changes = coalesce(raw_changes, config.coalesce_gap);

    Ok(DiffResult {
        changes,
        left_len,
        right_len,
    })
}

/// Merge consecutive ChangedRanges that are separated by at most `gap` bytes.
fn coalesce(ranges: Vec<ChangedRange>, gap: u64) -> Vec<ChangedRange> {
    let mut iter = ranges.into_iter();
    let Some(first) = iter.next() else {
        return Vec::new();
    };

    let mut result: Vec<ChangedRange> = Vec::new();
    let mut current = first;

    for next in iter {
        // Check if we can merge: the gap between current.left.end() and
        // next.left.offset() is <= gap (and similarly for right).
        let left_gap = next.left.offset().saturating_sub(current.left.end());
        let right_gap = next.right.offset().saturating_sub(current.right.end());

        if left_gap <= gap && right_gap <= gap {
            // Merge: extend current to cover both.
            let left_start = current.left.offset();
            let left_end = next.left.end();
            let right_start = current.right.offset();
            let right_end = next.right.end();

            current = ChangedRange {
                left: ByteRange::new(left_start, left_end - left_start),
                right: ByteRange::new(right_start, right_end - right_start),
            };
        } else {
            result.push(current);
            current = next;
        }
    }
    result.push(current);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tinkerspark_core_bytes::MemoryByteSource;

    #[test]
    fn identical_files() {
        let data = vec![1, 2, 3, 4, 5];
        let left = MemoryByteSource::new(data.clone());
        let right = MemoryByteSource::new(data);
        let result = compute_diff(&left, &right, &DiffConfig::default()).unwrap();
        assert!(result.is_identical());
        assert_eq!(result.change_count(), 0);
    }

    #[test]
    fn completely_different() {
        let left = MemoryByteSource::new(vec![0, 0, 0, 0]);
        let right = MemoryByteSource::new(vec![1, 1, 1, 1]);
        let result = compute_diff(&left, &right, &DiffConfig::default()).unwrap();
        assert_eq!(result.change_count(), 1);
        assert_eq!(result.changes[0].left, ByteRange::new(0, 4));
        assert_eq!(result.changes[0].right, ByteRange::new(0, 4));
    }

    #[test]
    fn single_byte_difference() {
        let left = MemoryByteSource::new(vec![1, 2, 3, 4, 5]);
        let right = MemoryByteSource::new(vec![1, 2, 99, 4, 5]);
        let result = compute_diff(&left, &right, &DiffConfig::default()).unwrap();
        assert_eq!(result.change_count(), 1);
        assert_eq!(result.changes[0].left, ByteRange::new(2, 1));
    }

    #[test]
    fn multiple_separate_changes() {
        let left = MemoryByteSource::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let right = MemoryByteSource::new(vec![1, 99, 3, 4, 5, 6, 88, 8]);
        let result = compute_diff(&left, &right, &DiffConfig::default()).unwrap();
        assert_eq!(result.change_count(), 2);
        assert_eq!(result.changes[0].left, ByteRange::new(1, 1));
        assert_eq!(result.changes[1].left, ByteRange::new(6, 1));
    }

    #[test]
    fn different_lengths_right_longer() {
        let left = MemoryByteSource::new(vec![1, 2, 3]);
        let right = MemoryByteSource::new(vec![1, 2, 3, 4, 5]);
        let result = compute_diff(&left, &right, &DiffConfig::default()).unwrap();
        assert_eq!(result.change_count(), 1);
        assert_eq!(result.changes[0].left, ByteRange::new(3, 0));
        assert_eq!(result.changes[0].right, ByteRange::new(3, 2));
    }

    #[test]
    fn different_lengths_left_longer() {
        let left = MemoryByteSource::new(vec![1, 2, 3, 4, 5]);
        let right = MemoryByteSource::new(vec![1, 2, 3]);
        let result = compute_diff(&left, &right, &DiffConfig::default()).unwrap();
        assert_eq!(result.change_count(), 1);
        assert_eq!(result.changes[0].left, ByteRange::new(3, 2));
        assert_eq!(result.changes[0].right, ByteRange::new(3, 0));
    }

    #[test]
    fn different_lengths_with_content_diff() {
        let left = MemoryByteSource::new(vec![1, 2, 3]);
        let right = MemoryByteSource::new(vec![1, 99, 3, 4, 5]);
        let result = compute_diff(&left, &right, &DiffConfig::default()).unwrap();
        assert_eq!(result.change_count(), 2);
        assert_eq!(result.changes[0].left, ByteRange::new(1, 1));
        assert_eq!(result.changes[1].right, ByteRange::new(3, 2));
    }

    #[test]
    fn coalesce_adjacent() {
        let left = MemoryByteSource::new(vec![1, 2, 3, 4]);
        let right = MemoryByteSource::new(vec![9, 9, 9, 9]);
        let result = compute_diff(&left, &right, &DiffConfig::default()).unwrap();
        assert_eq!(result.change_count(), 1);
    }

    #[test]
    fn coalesce_with_gap() {
        let left = MemoryByteSource::new(vec![1, 2, 3, 4, 5]);
        let right = MemoryByteSource::new(vec![99, 2, 3, 4, 99]);
        let result = compute_diff(&left, &right, &DiffConfig::default()).unwrap();
        assert_eq!(result.change_count(), 2);

        let config = DiffConfig {
            coalesce_gap: 3,
            ..Default::default()
        };
        let result = compute_diff(&left, &right, &config).unwrap();
        assert_eq!(result.change_count(), 1);
        assert_eq!(result.changes[0].left, ByteRange::new(0, 5));
    }

    #[test]
    fn empty_files() {
        let left = MemoryByteSource::new(vec![]);
        let right = MemoryByteSource::new(vec![]);
        let result = compute_diff(&left, &right, &DiffConfig::default()).unwrap();
        assert!(result.is_identical());
    }

    #[test]
    fn one_empty_one_not() {
        let left = MemoryByteSource::new(vec![]);
        let right = MemoryByteSource::new(vec![1, 2, 3]);
        let result = compute_diff(&left, &right, &DiffConfig::default()).unwrap();
        assert_eq!(result.change_count(), 1);
        assert_eq!(result.changes[0].left, ByteRange::new(0, 0));
        assert_eq!(result.changes[0].right, ByteRange::new(0, 3));
    }

    #[test]
    fn small_chunk_size() {
        let left = MemoryByteSource::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let right = MemoryByteSource::new(vec![1, 2, 99, 4, 5, 6, 88, 8]);
        let config = DiffConfig {
            chunk_size: 4,
            ..Default::default()
        };
        let result = compute_diff(&left, &right, &config).unwrap();
        assert_eq!(result.change_count(), 2);
        assert_eq!(result.changes[0].left, ByteRange::new(2, 1));
        assert_eq!(result.changes[1].left, ByteRange::new(6, 1));
    }

    #[test]
    fn cross_chunk_boundary_change() {
        let left = MemoryByteSource::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let right = MemoryByteSource::new(vec![1, 2, 3, 99, 99, 6, 7, 8]);
        let config = DiffConfig {
            chunk_size: 4,
            ..Default::default()
        };
        let result = compute_diff(&left, &right, &config).unwrap();
        assert_eq!(result.change_count(), 1);
        assert_eq!(result.changes[0].left, ByteRange::new(3, 2));
    }

    #[test]
    fn changed_bytes_stats() {
        let left = MemoryByteSource::new(vec![1, 2, 3]);
        let right = MemoryByteSource::new(vec![1, 99, 3, 4, 5]);
        let result = compute_diff(&left, &right, &DiffConfig::default()).unwrap();
        assert_eq!(result.left_changed_bytes(), 1);
        assert_eq!(result.right_changed_bytes(), 3);
    }
}
