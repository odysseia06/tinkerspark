use tinkerspark_core_types::{ByteRange, PatchId};

use crate::error::PatchError;

/// A single patch operation: replace bytes at a given range with new data.
/// Currently enforces same-length replacement to keep the file size stable.
#[derive(Debug, Clone)]
pub struct Patch {
    pub id: PatchId,
    pub range: ByteRange,
    pub replacement: Vec<u8>,
    pub label: String,
}

/// An ordered collection of non-overlapping, same-length patches.
#[derive(Debug, Clone, Default)]
pub struct PatchSet {
    patches: Vec<Patch>,
}

/// Result of `PatchSet::add_replacing`.
pub struct ReplaceResult {
    pub new_id: PatchId,
    pub displaced: Vec<Patch>,
    pub fragment_ids: Vec<PatchId>,
}

impl PatchSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    pub fn len(&self) -> usize {
        self.patches.len()
    }

    pub fn patches(&self) -> &[Patch] {
        &self.patches
    }

    /// Add a patch, rejecting it if it overlaps any existing patch or is out of bounds.
    pub fn add(
        &mut self,
        range: ByteRange,
        replacement: Vec<u8>,
        label: String,
        file_len: u64,
    ) -> Result<PatchId, PatchError> {
        self.validate(&range, &replacement, file_len)?;

        // Check for overlaps with existing patches.
        for existing in &self.patches {
            if range.overlaps(&existing.range) {
                return Err(PatchError::Conflict {
                    existing: existing.range,
                    new: range,
                });
            }
        }

        Ok(self.push_patch(range, replacement, label))
    }

    /// Add a patch, splitting any existing patches that partially overlap.
    ///
    /// If an existing patch is fully covered by the new range, it is removed.
    /// If an existing patch extends beyond the new range on one or both sides,
    /// the non-overlapping fragments are preserved as new patches.
    pub fn add_replacing(
        &mut self,
        range: ByteRange,
        replacement: Vec<u8>,
        label: String,
        file_len: u64,
    ) -> Result<ReplaceResult, PatchError> {
        self.validate(&range, &replacement, file_len)?;

        // Extract all overlapping patches.
        let overlapping: Vec<Patch> = self
            .patches
            .extract_if(.., |p| range.overlaps(&p.range))
            .collect();

        // For each removed patch, create fragment patches for portions
        // that fall outside the new edit range.
        let mut fragment_ids = Vec::new();
        for old in &overlapping {
            // Left fragment: old starts before new range.
            if old.range.offset() < range.offset() {
                let frag_len = range.offset() - old.range.offset();
                let frag_range = ByteRange::new(old.range.offset(), frag_len);
                let frag_data = old.replacement[..frag_len as usize].to_vec();
                let frag = Patch {
                    id: PatchId::new(),
                    range: frag_range,
                    replacement: frag_data,
                    label: old.label.clone(),
                };
                fragment_ids.push(frag.id);
                self.patches.push(frag);
            }
            // Right fragment: old extends past new range.
            if old.range.end() > range.end() {
                let frag_start = range.end();
                let frag_len = old.range.end() - range.end();
                let data_offset = (frag_start - old.range.offset()) as usize;
                let frag_range = ByteRange::new(frag_start, frag_len);
                let frag_data =
                    old.replacement[data_offset..data_offset + frag_len as usize].to_vec();
                let frag = Patch {
                    id: PatchId::new(),
                    range: frag_range,
                    replacement: frag_data,
                    label: old.label.clone(),
                };
                fragment_ids.push(frag.id);
                self.patches.push(frag);
            }
        }

        let id = self.push_patch(range, replacement, label);

        Ok(ReplaceResult {
            new_id: id,
            displaced: overlapping,
            fragment_ids,
        })
    }

    fn validate(
        &self,
        range: &ByteRange,
        replacement: &[u8],
        file_len: u64,
    ) -> Result<(), PatchError> {
        if range.is_empty() {
            return Err(PatchError::EmptyPatch);
        }
        if range.end() > file_len {
            return Err(PatchError::OutOfBounds {
                range: *range,
                file_len,
            });
        }
        if replacement.len() as u64 != range.length() {
            return Err(PatchError::LengthMismatch {
                range_len: range.length(),
                replacement_len: replacement.len(),
            });
        }
        Ok(())
    }

    fn push_patch(&mut self, range: ByteRange, replacement: Vec<u8>, label: String) -> PatchId {
        let id = PatchId::new();
        self.patches.push(Patch {
            id,
            range,
            replacement,
            label,
        });
        id
    }

    /// Re-insert a previously removed patch, preserving its original ID.
    /// Used by undo to restore displaced patches.
    pub fn restore(&mut self, patch: Patch) {
        self.patches.push(patch);
    }

    /// Remove a patch by ID. Returns the removed patch if found.
    pub fn remove(&mut self, id: PatchId) -> Option<Patch> {
        if let Some(pos) = self.patches.iter().position(|p| p.id == id) {
            Some(self.patches.remove(pos))
        } else {
            None
        }
    }

    /// Remove the last patch. Returns it if the set was non-empty.
    pub fn pop(&mut self) -> Option<Patch> {
        self.patches.pop()
    }

    /// Clear all patches.
    pub fn clear(&mut self) {
        self.patches.clear();
    }

    /// Overlay patch bytes onto a buffer that already contains the base data.
    ///
    /// `buf_offset` is the file offset corresponding to `buf[0]`. Only patches
    /// overlapping the buffer range are touched — O(patches) per call.
    ///
    /// The buffer is modified in place: bytes covered by patches are replaced,
    /// bytes not covered are left as-is (i.e., the caller's base data).
    pub fn apply_patches(&self, buf: &mut [u8], buf_offset: u64) {
        let req_start = buf_offset;
        let req_end = buf_offset + buf.len() as u64;

        for patch in &self.patches {
            let p_start = patch.range.offset();
            let p_end = patch.range.end();

            if p_end <= req_start || p_start >= req_end {
                continue;
            }

            let overlap_start = p_start.max(req_start);
            let overlap_end = p_end.min(req_end);

            let out_start = (overlap_start - req_start) as usize;
            let patch_start = (overlap_start - p_start) as usize;
            let overlap_len = (overlap_end - overlap_start) as usize;

            buf[out_start..out_start + overlap_len]
                .copy_from_slice(&patch.replacement[patch_start..patch_start + overlap_len]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_patch_basic() {
        let mut ps = PatchSet::new();
        let id = ps
            .add(
                ByteRange::new(0, 3),
                vec![0xAA, 0xBB, 0xCC],
                "test".into(),
                10,
            )
            .unwrap();
        assert_eq!(ps.len(), 1);
        assert_eq!(ps.patches()[0].id, id);
    }

    #[test]
    fn add_patch_out_of_bounds() {
        let mut ps = PatchSet::new();
        let result = ps.add(ByteRange::new(8, 5), vec![0; 5], "oob".into(), 10);
        assert!(matches!(result, Err(PatchError::OutOfBounds { .. })));
    }

    #[test]
    fn add_patch_length_mismatch() {
        let mut ps = PatchSet::new();
        let result = ps.add(ByteRange::new(0, 3), vec![0xAA, 0xBB], "short".into(), 10);
        assert!(matches!(result, Err(PatchError::LengthMismatch { .. })));
    }

    #[test]
    fn add_patch_empty() {
        let mut ps = PatchSet::new();
        let result = ps.add(ByteRange::new(0, 0), vec![], "empty".into(), 10);
        assert!(matches!(result, Err(PatchError::EmptyPatch)));
    }

    #[test]
    fn add_patch_conflict() {
        let mut ps = PatchSet::new();
        ps.add(ByteRange::new(2, 4), vec![0; 4], "first".into(), 10)
            .unwrap();
        let result = ps.add(ByteRange::new(4, 3), vec![0; 3], "overlap".into(), 10);
        assert!(matches!(result, Err(PatchError::Conflict { .. })));
    }

    #[test]
    fn add_multiple_non_overlapping() {
        let mut ps = PatchSet::new();
        ps.add(ByteRange::new(0, 2), vec![0xAA, 0xBB], "p1".into(), 20)
            .unwrap();
        ps.add(
            ByteRange::new(5, 3),
            vec![0xCC, 0xDD, 0xEE],
            "p2".into(),
            20,
        )
        .unwrap();
        ps.add(ByteRange::new(10, 1), vec![0xFF], "p3".into(), 20)
            .unwrap();
        assert_eq!(ps.len(), 3);
    }

    #[test]
    fn remove_patch() {
        let mut ps = PatchSet::new();
        let id = ps
            .add(ByteRange::new(0, 1), vec![0xFF], "x".into(), 10)
            .unwrap();
        assert_eq!(ps.len(), 1);
        let removed = ps.remove(id).unwrap();
        assert_eq!(removed.id, id);
        assert!(ps.is_empty());
    }

    #[test]
    fn pop_patch() {
        let mut ps = PatchSet::new();
        ps.add(ByteRange::new(0, 1), vec![0xAA], "first".into(), 10)
            .unwrap();
        ps.add(ByteRange::new(5, 1), vec![0xBB], "second".into(), 10)
            .unwrap();
        let popped = ps.pop().unwrap();
        assert_eq!(popped.label, "second");
        assert_eq!(ps.len(), 1);
    }

    #[test]
    fn apply_patches_no_patches() {
        let ps = PatchSet::new();
        let mut buf = [2, 3, 4, 5];
        ps.apply_patches(&mut buf, 2);
        assert_eq!(buf, [2, 3, 4, 5]);
    }

    #[test]
    fn apply_patches_with_patch() {
        let mut ps = PatchSet::new();
        ps.add(ByteRange::new(2, 2), vec![0xAA, 0xBB], "p".into(), 10)
            .unwrap();

        let mut buf = [0, 1, 2, 3, 4];
        ps.apply_patches(&mut buf, 0);
        assert_eq!(buf, [0, 1, 0xAA, 0xBB, 4]);
    }

    #[test]
    fn apply_patches_partial_overlap() {
        let mut ps = PatchSet::new();
        ps.add(
            ByteRange::new(3, 4),
            vec![0xAA, 0xBB, 0xCC, 0xDD],
            "p".into(),
            10,
        )
        .unwrap();

        // Read range [2..6) overlaps patch [3..7).
        let mut buf = [2, 3, 4, 5];
        ps.apply_patches(&mut buf, 2);
        assert_eq!(buf, [2, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn apply_patches_multiple() {
        let mut ps = PatchSet::new();
        ps.add(ByteRange::new(1, 1), vec![0xFF], "p1".into(), 10)
            .unwrap();
        ps.add(ByteRange::new(4, 2), vec![0xEE, 0xDD], "p2".into(), 10)
            .unwrap();

        let mut buf = [0, 1, 2, 3, 4, 5, 6];
        ps.apply_patches(&mut buf, 0);
        assert_eq!(buf, [0, 0xFF, 2, 3, 0xEE, 0xDD, 6]);
    }

    #[test]
    fn add_replacing_removes_overlap() {
        let mut ps = PatchSet::new();
        ps.add(
            ByteRange::new(2, 3),
            vec![0xAA, 0xBB, 0xCC],
            "old".into(),
            20,
        )
        .unwrap();
        ps.add(ByteRange::new(10, 1), vec![0xFF], "keep".into(), 20)
            .unwrap();

        // New patch overlapping [2..5) should replace the old one.
        let result = ps
            .add_replacing(ByteRange::new(1, 5), vec![1, 2, 3, 4, 5], "new".into(), 20)
            .unwrap();
        assert_eq!(result.displaced.len(), 1);
        assert_eq!(result.displaced[0].label, "old");
        // "keep" + "new" remain (no fragments since old was fully covered).
        assert_eq!(ps.len(), 2);
    }

    #[test]
    fn add_replacing_splits_partial_overlap() {
        let mut ps = PatchSet::new();
        ps.add(
            ByteRange::new(2, 5),
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            "wide".into(),
            20,
        )
        .unwrap();

        // Edit only the middle byte [4..5). Should create fragments for
        // [2..4) and [5..7).
        let result = ps
            .add_replacing(ByteRange::new(4, 1), vec![0xFF], "narrow".into(), 20)
            .unwrap();
        assert_eq!(result.displaced.len(), 1);
        assert_eq!(result.fragment_ids.len(), 2);
        // 2 fragments + 1 new edit = 3 patches.
        assert_eq!(ps.len(), 3);

        // Verify fragment contents.
        let mut buf = [0u8; 7];
        buf.copy_from_slice(&[2, 3, 4, 5, 6, 7, 8]); // base data [2..9)
        ps.apply_patches(&mut buf, 2);
        assert_eq!(buf, [0xAA, 0xBB, 0xFF, 0xDD, 0xEE, 7, 8]);
    }

    #[test]
    fn clear_patches() {
        let mut ps = PatchSet::new();
        ps.add(ByteRange::new(0, 1), vec![0xFF], "x".into(), 10)
            .unwrap();
        ps.add(ByteRange::new(5, 1), vec![0xEE], "y".into(), 10)
            .unwrap();
        ps.clear();
        assert!(ps.is_empty());
    }
}
