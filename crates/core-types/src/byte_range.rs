use serde::{Deserialize, Serialize};

/// An inclusive-start, exclusive-end byte range within a file.
///
/// Invariant: `offset + length` never overflows `u64`. This is enforced by
/// the constructor so that `end()` is always safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ByteRange {
    offset: u64,
    length: u64,
}

impl ByteRange {
    /// Create a new byte range.
    ///
    /// # Panics
    ///
    /// Panics if `offset + length` overflows `u64`. Use [`try_new`](Self::try_new)
    /// when dealing with untrusted input.
    pub fn new(offset: u64, length: u64) -> Self {
        match Self::try_new(offset, length) {
            Some(r) => r,
            None => {
                panic!("ByteRange overflow: offset {offset} + length {length} exceeds u64::MAX")
            }
        }
    }

    /// Try to create a new byte range, returning `None` if `offset + length`
    /// would overflow `u64`.
    pub fn try_new(offset: u64, length: u64) -> Option<Self> {
        offset.checked_add(length)?;
        Some(Self { offset, length })
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    /// Exclusive end of the range. Always safe because the constructor
    /// guarantees `offset + length` does not overflow.
    pub fn end(&self) -> u64 {
        // Invariant: checked at construction time.
        self.offset + self.length
    }

    pub fn contains(&self, pos: u64) -> bool {
        pos >= self.offset && pos < self.end()
    }

    pub fn overlaps(&self, other: &ByteRange) -> bool {
        self.offset < other.end() && other.offset < self.end()
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_is_offset_plus_length() {
        let r = ByteRange::new(10, 20);
        assert_eq!(r.end(), 30);
    }

    #[test]
    fn contains_works() {
        let r = ByteRange::new(10, 5);
        assert!(r.contains(10));
        assert!(r.contains(14));
        assert!(!r.contains(15));
        assert!(!r.contains(9));
    }

    #[test]
    fn overlaps_works() {
        let a = ByteRange::new(10, 10);
        let b = ByteRange::new(15, 10);
        let c = ByteRange::new(20, 5);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn empty_range() {
        let r = ByteRange::new(0, 0);
        assert!(r.is_empty());
        assert!(!r.contains(0));
    }

    #[test]
    fn try_new_rejects_overflow() {
        assert!(ByteRange::try_new(u64::MAX, 1).is_none());
        assert!(ByteRange::try_new(u64::MAX / 2 + 1, u64::MAX / 2 + 1).is_none());
    }

    #[test]
    fn try_new_accepts_max_valid() {
        // offset=0, length=u64::MAX is valid (end = u64::MAX, no overflow in the add).
        let r = ByteRange::try_new(0, u64::MAX).unwrap();
        assert_eq!(r.end(), u64::MAX);
    }

    #[test]
    #[should_panic(expected = "ByteRange overflow")]
    fn new_panics_on_overflow() {
        ByteRange::new(u64::MAX, 1);
    }

    #[test]
    fn accessors() {
        let r = ByteRange::new(42, 100);
        assert_eq!(r.offset(), 42);
        assert_eq!(r.length(), 100);
    }
}
