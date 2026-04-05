use tinkerspark_core_types::{ByteRange, PatchId};

use crate::error::PatchError;
use crate::patch::{Patch, PatchSet};

/// A single history entry recording what an edit did.
struct HistoryEntry {
    /// The patch that was applied.
    applied: Patch,
    /// Original patches that were removed because they overlapped.
    displaced: Vec<Patch>,
    /// IDs of fragment patches created from splitting partially overlapping
    /// patches. These need to be removed on undo and re-created on redo.
    fragment_ids: Vec<PatchId>,
}

/// Manages a PatchSet with undo/redo history.
///
/// Each edit is recorded as a compound `HistoryEntry` that tracks the applied
/// patch, displaced originals, and any fragment patches created from splits.
/// Undo reverses the full entry. Redo replays it.
pub struct PatchHistory {
    active: PatchSet,
    undo_stack: Vec<HistoryEntry>,
    redo_stack: Vec<HistoryEntry>,
    file_len: u64,
}

impl PatchHistory {
    pub fn new(file_len: u64) -> Self {
        Self {
            active: PatchSet::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            file_len,
        }
    }

    pub fn patches(&self) -> &PatchSet {
        &self.active
    }

    pub fn is_dirty(&self) -> bool {
        !self.active.is_empty()
    }

    pub fn patch_count(&self) -> usize {
        self.active.len()
    }

    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Apply a new patch. Any existing patches that overlap the new range
    /// are split: non-overlapping fragments are preserved, fully covered
    /// patches are removed. All changes are recorded for undo.
    /// Clears the redo stack.
    pub fn apply(
        &mut self,
        range: ByteRange,
        replacement: Vec<u8>,
        label: String,
    ) -> Result<(), PatchError> {
        let result = self
            .active
            .add_replacing(range, replacement, label, self.file_len)?;

        let applied = self
            .active
            .patches()
            .iter()
            .find(|p| p.id == result.new_id)
            .unwrap()
            .clone();

        self.undo_stack.push(HistoryEntry {
            applied,
            displaced: result.displaced,
            fragment_ids: result.fragment_ids,
        });

        self.redo_stack.clear();
        Ok(())
    }

    /// Undo the most recent edit:
    /// 1. Remove the applied patch.
    /// 2. Remove any fragment patches created by the split.
    /// 3. Restore the original displaced patches.
    pub fn undo(&mut self) -> bool {
        let Some(entry) = self.undo_stack.pop() else {
            return false;
        };

        self.active.remove(entry.applied.id);

        for frag_id in &entry.fragment_ids {
            self.active.remove(*frag_id);
        }

        for patch in &entry.displaced {
            self.active.restore(patch.clone());
        }

        self.redo_stack.push(entry);
        true
    }

    /// Redo the most recently undone edit. The displaced patches are still
    /// in the active set (restored by undo), so `add_replacing` will find
    /// and split them again.
    pub fn redo(&mut self) -> bool {
        let Some(mut entry) = self.redo_stack.pop() else {
            return false;
        };

        // Re-apply the edit. add_replacing will find the displaced patches
        // (which undo restored) and split them, creating new fragments.
        let result = self.active.add_replacing(
            entry.applied.range,
            entry.applied.replacement.clone(),
            entry.applied.label.clone(),
            self.file_len,
        );

        match result {
            Ok(r) => {
                entry.applied = self
                    .active
                    .patches()
                    .iter()
                    .find(|p| p.id == r.new_id)
                    .unwrap()
                    .clone();
                entry.displaced = r.displaced;
                entry.fragment_ids = r.fragment_ids;
                self.undo_stack.push(entry);
                true
            }
            Err(_) => {
                // Should not happen since this was a valid edit before.
                false
            }
        }
    }

    /// Revert all patches and clear history.
    pub fn revert_all(&mut self) {
        self.active.clear();
        self.undo_stack.clear();
        self.redo_stack.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_and_dirty() {
        let mut h = PatchHistory::new(10);
        assert!(!h.is_dirty());
        h.apply(ByteRange::new(0, 2), vec![0xAA, 0xBB], "edit1".into())
            .unwrap();
        assert!(h.is_dirty());
        assert_eq!(h.patch_count(), 1);
    }

    #[test]
    fn undo_redo_basic() {
        let mut h = PatchHistory::new(10);
        h.apply(ByteRange::new(0, 1), vec![0xFF], "e1".into())
            .unwrap();
        h.apply(ByteRange::new(5, 1), vec![0xEE], "e2".into())
            .unwrap();
        assert_eq!(h.patch_count(), 2);

        assert!(h.undo());
        assert_eq!(h.patch_count(), 1);
        assert!(h.can_redo());

        assert!(h.redo());
        assert_eq!(h.patch_count(), 2);
        assert!(!h.can_redo());
    }

    #[test]
    fn new_edit_clears_redo() {
        let mut h = PatchHistory::new(10);
        h.apply(ByteRange::new(0, 1), vec![0xFF], "e1".into())
            .unwrap();
        h.apply(ByteRange::new(5, 1), vec![0xEE], "e2".into())
            .unwrap();

        h.undo();
        assert!(h.can_redo());

        h.apply(ByteRange::new(8, 1), vec![0xDD], "e3".into())
            .unwrap();
        assert!(!h.can_redo());
    }

    #[test]
    fn undo_empty() {
        let mut h = PatchHistory::new(10);
        assert!(!h.undo());
    }

    #[test]
    fn redo_empty() {
        let mut h = PatchHistory::new(10);
        assert!(!h.redo());
    }

    #[test]
    fn revert_all() {
        let mut h = PatchHistory::new(10);
        h.apply(ByteRange::new(0, 1), vec![0xFF], "e1".into())
            .unwrap();
        h.apply(ByteRange::new(5, 1), vec![0xEE], "e2".into())
            .unwrap();
        h.undo();

        h.revert_all();
        assert!(!h.is_dirty());
        assert!(!h.can_undo());
        assert!(!h.can_redo());
    }

    #[test]
    fn re_edit_same_region() {
        let mut h = PatchHistory::new(10);
        h.apply(ByteRange::new(2, 3), vec![0xAA, 0xBB, 0xCC], "e1".into())
            .unwrap();

        h.apply(ByteRange::new(2, 3), vec![0x11, 0x22, 0x33], "e2".into())
            .unwrap();
        assert_eq!(h.patch_count(), 1);
        assert_eq!(h.patches().patches()[0].label, "e2");
    }

    #[test]
    fn undo_re_edit_restores_displaced_patch() {
        let mut h = PatchHistory::new(10);
        h.apply(ByteRange::new(2, 3), vec![0xAA, 0xBB, 0xCC], "e1".into())
            .unwrap();

        h.apply(ByteRange::new(2, 3), vec![0x11, 0x22, 0x33], "e2".into())
            .unwrap();

        h.undo();
        assert_eq!(h.patch_count(), 1);
        assert_eq!(h.patches().patches()[0].label, "e1");
        assert_eq!(h.patches().patches()[0].replacement, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn redo_after_undo_re_edit() {
        let mut h = PatchHistory::new(10);
        h.apply(ByteRange::new(2, 3), vec![0xAA, 0xBB, 0xCC], "e1".into())
            .unwrap();
        h.apply(ByteRange::new(2, 3), vec![0x11, 0x22, 0x33], "e2".into())
            .unwrap();

        h.undo();
        assert_eq!(h.patches().patches()[0].label, "e1");

        h.redo();
        assert_eq!(h.patch_count(), 1);
        assert_eq!(h.patches().patches()[0].label, "e2");
    }

    #[test]
    fn partial_overlap_preserves_fragments() {
        use crate::PatchedView;
        use tinkerspark_core_bytes::{ByteSource, MemoryByteSource};

        let base_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let base = MemoryByteSource::new(base_data);

        let mut h = PatchHistory::new(10);
        // Patch bytes [2..5) to AA BB CC.
        h.apply(ByteRange::new(2, 3), vec![0xAA, 0xBB, 0xCC], "e1".into())
            .unwrap();

        // Edit only [3..4) to FF. Bytes 2 and 4 should keep their patched
        // values (AA and CC) via fragment patches, not revert to base.
        h.apply(ByteRange::new(3, 1), vec![0xFF], "e2".into())
            .unwrap();

        let view = PatchedView::new(&base, h.patches());
        let data = view.read_range(ByteRange::new(0, 10)).unwrap();
        assert_eq!(
            &*data,
            &[0, 1, 0xAA, 0xFF, 0xCC, 5, 6, 7, 8, 9],
            "fragments from split must preserve non-overlapping patched bytes"
        );

        // Undo should fully restore the original patch on [2..5).
        h.undo();
        let view = PatchedView::new(&base, h.patches());
        let data = view.read_range(ByteRange::new(0, 10)).unwrap();
        assert_eq!(&*data, &[0, 1, 0xAA, 0xBB, 0xCC, 5, 6, 7, 8, 9]);

        // Redo should re-apply the split.
        h.redo();
        let view = PatchedView::new(&base, h.patches());
        let data = view.read_range(ByteRange::new(0, 10)).unwrap();
        assert_eq!(&*data, &[0, 1, 0xAA, 0xFF, 0xCC, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn undo_after_redo_preserves_id() {
        let mut h = PatchHistory::new(10);
        h.apply(ByteRange::new(0, 1), vec![0xFF], "e1".into())
            .unwrap();

        h.undo();
        h.redo();
        assert!(h.undo());
        assert_eq!(h.patch_count(), 0);
        assert!(h.redo());
        assert_eq!(h.patch_count(), 1);
    }

    #[test]
    fn multiple_undo_redo_cycles() {
        let mut h = PatchHistory::new(20);
        h.apply(ByteRange::new(0, 1), vec![0xAA], "e1".into())
            .unwrap();
        h.apply(ByteRange::new(5, 1), vec![0xBB], "e2".into())
            .unwrap();
        h.apply(ByteRange::new(10, 1), vec![0xCC], "e3".into())
            .unwrap();

        assert!(h.undo());
        assert!(h.undo());
        assert!(h.undo());
        assert!(!h.undo());
        assert_eq!(h.patch_count(), 0);

        assert!(h.redo());
        assert!(h.redo());
        assert!(h.redo());
        assert!(!h.redo());
        assert_eq!(h.patch_count(), 3);
    }
}
