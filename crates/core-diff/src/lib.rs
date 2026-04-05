// core-diff: Binary comparison engine.
//
// Byte-level diff of two ByteSources with changed-range coalescing
// and navigation helpers.
//
// Design note: The diff algorithm compares bytes at matching offsets
// (positional diff). This is the standard approach for binary comparison
// tools. It works well when comparing structurally similar files (e.g.,
// two versions of the same key). If one file has bytes inserted or
// deleted mid-stream, all subsequent bytes will be compared against
// shifted partners, producing a large trailing change. Format-aware
// alignment (e.g., diffing at the packet level) is a Phase 4+ concern
// that belongs in the analyzer layer, not the byte engine.

mod diff;
mod error;
mod navigate;

pub use diff::{compute_diff, DiffConfig};
pub use error::DiffError;
pub use navigate::DiffNavigator;

use tinkerspark_core_types::ByteRange;

/// A contiguous range of bytes that differs between two sources.
///
/// For equal-length regions the left and right ranges have the same length.
/// When files differ in total length, the trailing range only appears on
/// the longer side (the shorter side gets a zero-length range at EOF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedRange {
    pub left: ByteRange,
    pub right: ByteRange,
}

/// Result of comparing two byte sources.
#[derive(Debug, Clone, Default)]
pub struct DiffResult {
    pub changes: Vec<ChangedRange>,
    pub left_len: u64,
    pub right_len: u64,
}

impl DiffResult {
    pub fn is_identical(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn change_count(&self) -> usize {
        self.changes.len()
    }

    /// Total number of bytes that differ on the left side.
    pub fn left_changed_bytes(&self) -> u64 {
        self.changes.iter().map(|c| c.left.length()).sum()
    }

    /// Total number of bytes that differ on the right side.
    pub fn right_changed_bytes(&self) -> u64 {
        self.changes.iter().map(|c| c.right.length()).sum()
    }
}
