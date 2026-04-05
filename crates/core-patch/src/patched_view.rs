use std::borrow::Cow;

use tinkerspark_core_bytes::{ByteSource, ReadError};
use tinkerspark_core_types::ByteRange;

use crate::patch::PatchSet;

/// A read-only view over a base ByteSource with patches applied.
///
/// Implements `ByteSource` so consumers (hex view, search, analyzers) see
/// patched bytes transparently. The base source is never modified.
///
/// Reads are efficient: only patches overlapping the requested range are
/// consulted. There is no materialized copy of the full patched file.
pub struct PatchedView<'a> {
    base: &'a dyn ByteSource,
    patches: &'a PatchSet,
}

impl<'a> PatchedView<'a> {
    pub fn new(base: &'a dyn ByteSource, patches: &'a PatchSet) -> Self {
        Self { base, patches }
    }
}

impl ByteSource for PatchedView<'_> {
    fn len(&self) -> u64 {
        // Same-length patches don't change file size.
        self.base.len()
    }

    fn read_range(&self, range: ByteRange) -> Result<Cow<'_, [u8]>, ReadError> {
        if range.is_empty() {
            return Ok(Cow::Borrowed(&[]));
        }

        // If no patches, delegate directly to base (zero-copy).
        if self.patches.is_empty() {
            return self.base.read_range(range);
        }

        // Read base bytes into an owned buffer, then overlay patches in place.
        let base_data = self.base.read_range(range)?;
        let mut buf = base_data.into_owned();
        self.patches.apply_patches(&mut buf, range.offset());
        Ok(Cow::Owned(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tinkerspark_core_bytes::MemoryByteSource;

    #[test]
    fn patched_view_no_patches() {
        let data = vec![0, 1, 2, 3, 4, 5];
        let base = MemoryByteSource::new(data);
        let ps = PatchSet::new();
        let view = PatchedView::new(&base, &ps);

        let result = view.read_range(ByteRange::new(1, 3)).unwrap();
        assert_eq!(&*result, &[1, 2, 3]);
        // Should borrow since no patches.
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn patched_view_with_patch() {
        let data = vec![0, 1, 2, 3, 4, 5];
        let base = MemoryByteSource::new(data);
        let mut ps = PatchSet::new();
        ps.add(ByteRange::new(2, 2), vec![0xAA, 0xBB], "p".into(), 6)
            .unwrap();

        let view = PatchedView::new(&base, &ps);
        let result = view.read_range(ByteRange::new(0, 6)).unwrap();
        assert_eq!(&*result, &[0, 1, 0xAA, 0xBB, 4, 5]);
    }

    #[test]
    fn patched_view_partial_overlap() {
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let base = MemoryByteSource::new(data);
        let mut ps = PatchSet::new();
        ps.add(ByteRange::new(3, 3), vec![0xAA, 0xBB, 0xCC], "p".into(), 8)
            .unwrap();

        let view = PatchedView::new(&base, &ps);
        // Read [2..6) — partially overlaps patch [3..6).
        let result = view.read_range(ByteRange::new(2, 4)).unwrap();
        assert_eq!(&*result, &[2, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn patched_view_len_unchanged() {
        let data = vec![0; 100];
        let base = MemoryByteSource::new(data);
        let mut ps = PatchSet::new();
        ps.add(ByteRange::new(50, 5), vec![0xFF; 5], "p".into(), 100)
            .unwrap();

        let view = PatchedView::new(&base, &ps);
        assert_eq!(view.len(), 100);
    }

    #[test]
    fn patched_view_multiple_patches() {
        let data = vec![0; 20];
        let base = MemoryByteSource::new(data);
        let mut ps = PatchSet::new();
        ps.add(ByteRange::new(0, 2), vec![0xAA, 0xBB], "p1".into(), 20)
            .unwrap();
        ps.add(
            ByteRange::new(10, 3),
            vec![0xCC, 0xDD, 0xEE],
            "p2".into(),
            20,
        )
        .unwrap();

        let view = PatchedView::new(&base, &ps);
        let full = view.read_range(ByteRange::new(0, 20)).unwrap();
        assert_eq!(full[0], 0xAA);
        assert_eq!(full[1], 0xBB);
        assert_eq!(full[2], 0x00);
        assert_eq!(full[10], 0xCC);
        assert_eq!(full[11], 0xDD);
        assert_eq!(full[12], 0xEE);
        assert_eq!(full[13], 0x00);
    }

    #[test]
    fn patched_view_empty_range() {
        let data = vec![0; 10];
        let base = MemoryByteSource::new(data);
        let ps = PatchSet::new();
        let view = PatchedView::new(&base, &ps);

        let result = view.read_range(ByteRange::new(0, 0)).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn patched_view_at_file_boundaries() {
        let data = vec![0, 1, 2, 3, 4];
        let base = MemoryByteSource::new(data);
        let mut ps = PatchSet::new();
        // Patch first byte.
        ps.add(ByteRange::new(0, 1), vec![0xFF], "start".into(), 5)
            .unwrap();
        // Patch last byte.
        ps.add(ByteRange::new(4, 1), vec![0xEE], "end".into(), 5)
            .unwrap();

        let view = PatchedView::new(&base, &ps);
        let full = view.read_range(ByteRange::new(0, 5)).unwrap();
        assert_eq!(&*full, &[0xFF, 1, 2, 3, 0xEE]);
    }
}
