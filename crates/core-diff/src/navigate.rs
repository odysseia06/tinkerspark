use crate::DiffResult;

/// Stateful navigator over the changes in a DiffResult.
///
/// Tracks a "current change" index and provides first/next/prev/last
/// navigation. The index is `None` when no change has been focused yet.
#[derive(Debug, Clone)]
pub struct DiffNavigator {
    current: Option<usize>,
    count: usize,
}

impl DiffNavigator {
    pub fn new(result: &DiffResult) -> Self {
        Self {
            current: None,
            count: result.change_count(),
        }
    }

    /// The index of the currently focused change, if any.
    pub fn current_index(&self) -> Option<usize> {
        self.current
    }

    /// Total number of changes.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Jump to the first change. Returns the new index, or None if empty.
    pub fn first(&mut self) -> Option<usize> {
        if self.count == 0 {
            self.current = None;
        } else {
            self.current = Some(0);
        }
        self.current
    }

    /// Jump to the last change. Returns the new index, or None if empty.
    pub fn last(&mut self) -> Option<usize> {
        if self.count == 0 {
            self.current = None;
        } else {
            self.current = Some(self.count - 1);
        }
        self.current
    }

    /// Move to the next change. Wraps around from last to first.
    /// If no change is focused, goes to the first.
    pub fn next_change(&mut self) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        self.current = Some(match self.current {
            Some(i) => (i + 1) % self.count,
            None => 0,
        });
        self.current
    }

    /// Move to the previous change. Wraps around from first to last.
    /// If no change is focused, goes to the last.
    pub fn prev_change(&mut self) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        self.current = Some(match self.current {
            Some(0) => self.count - 1,
            Some(i) => i - 1,
            None => self.count - 1,
        });
        self.current
    }

    /// Jump to a specific index. Clamps to valid range.
    pub fn go_to(&mut self, index: usize) -> Option<usize> {
        if self.count == 0 {
            self.current = None;
        } else {
            self.current = Some(index.min(self.count - 1));
        }
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChangedRange, DiffResult};
    use tinkerspark_core_types::ByteRange;

    fn make_result(n: usize) -> DiffResult {
        let changes = (0..n)
            .map(|i| {
                let offset = (i * 10) as u64;
                ChangedRange {
                    left: ByteRange::new(offset, 5),
                    right: ByteRange::new(offset, 5),
                }
            })
            .collect();
        DiffResult {
            changes,
            left_len: 100,
            right_len: 100,
        }
    }

    #[test]
    fn empty_result() {
        let result = make_result(0);
        let mut nav = DiffNavigator::new(&result);
        assert_eq!(nav.first(), None);
        assert_eq!(nav.next_change(), None);
        assert_eq!(nav.prev_change(), None);
        assert_eq!(nav.last(), None);
    }

    #[test]
    fn single_change() {
        let result = make_result(1);
        let mut nav = DiffNavigator::new(&result);
        assert_eq!(nav.first(), Some(0));
        assert_eq!(nav.next_change(), Some(0)); // wraps
        assert_eq!(nav.prev_change(), Some(0)); // wraps
    }

    #[test]
    fn forward_navigation() {
        let result = make_result(3);
        let mut nav = DiffNavigator::new(&result);
        assert_eq!(nav.next_change(), Some(0));
        assert_eq!(nav.next_change(), Some(1));
        assert_eq!(nav.next_change(), Some(2));
        assert_eq!(nav.next_change(), Some(0)); // wrap
    }

    #[test]
    fn backward_navigation() {
        let result = make_result(3);
        let mut nav = DiffNavigator::new(&result);
        assert_eq!(nav.prev_change(), Some(2)); // starts at last
        assert_eq!(nav.prev_change(), Some(1));
        assert_eq!(nav.prev_change(), Some(0));
        assert_eq!(nav.prev_change(), Some(2)); // wrap
    }

    #[test]
    fn first_and_last() {
        let result = make_result(5);
        let mut nav = DiffNavigator::new(&result);
        assert_eq!(nav.last(), Some(4));
        assert_eq!(nav.first(), Some(0));
    }

    #[test]
    fn go_to() {
        let result = make_result(5);
        let mut nav = DiffNavigator::new(&result);
        assert_eq!(nav.go_to(3), Some(3));
        assert_eq!(nav.go_to(100), Some(4)); // clamped
    }
}
