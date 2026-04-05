/// A byte selection in the hex view.
///
/// `anchor` is the byte where the selection started. `end` is the byte where
/// it currently extends to. The actual selected range is from
/// `min(anchor, end)` to `max(anchor, end)` inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    pub anchor: u64,
    pub end: u64,
}

impl Selection {
    pub fn start(&self) -> u64 {
        self.anchor.min(self.end)
    }

    pub fn end_inclusive(&self) -> u64 {
        self.anchor.max(self.end)
    }

    pub fn len(&self) -> u64 {
        self.end_inclusive() - self.start() + 1
    }

    /// A selection always covers at least one byte.
    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.start() && offset <= self.end_inclusive()
    }
}

/// Computed metadata about the current selection, for display in the UI.
#[derive(Debug, Clone)]
pub struct SelectionMeta {
    pub start: u64,
    pub end_inclusive: u64,
    pub length: u64,
    pub hex_preview: String,
    pub ascii_preview: String,
    pub u8_val: Option<u8>,
    pub u16_le: Option<u16>,
    pub u16_be: Option<u16>,
    pub u32_le: Option<u32>,
    pub u32_be: Option<u32>,
    pub u64_le: Option<u64>,
    pub u64_be: Option<u64>,
}

impl SelectionMeta {
    /// Compute selection metadata from the selected bytes.
    /// `bytes` must be exactly `selection.len()` bytes long.
    pub fn from_bytes(selection: &Selection, bytes: &[u8]) -> Self {
        let start = selection.start();
        let end_inclusive = selection.end_inclusive();
        let length = selection.len();

        // Hex preview (capped to avoid huge strings).
        let preview_limit = 64;
        let hex_preview = bytes
            .iter()
            .take(preview_limit)
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        let hex_preview = if bytes.len() > preview_limit {
            format!("{hex_preview} ...")
        } else {
            hex_preview
        };

        // ASCII preview.
        let ascii_preview: String = bytes
            .iter()
            .take(preview_limit)
            .map(|&b| crate::viewport::ascii_char(b))
            .collect();
        let ascii_preview = if bytes.len() > preview_limit {
            format!("{ascii_preview}...")
        } else {
            ascii_preview
        };

        // Integer interpretations.
        let u8_val = if !bytes.is_empty() {
            Some(bytes[0])
        } else {
            None
        };
        let u16_le = bytes
            .get(..2)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_le_bytes);
        let u16_be = bytes
            .get(..2)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_be_bytes);
        let u32_le = bytes
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes);
        let u32_be = bytes
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_be_bytes);
        let u64_le = bytes
            .get(..8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes);
        let u64_be = bytes
            .get(..8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_be_bytes);

        Self {
            start,
            end_inclusive,
            length,
            hex_preview,
            ascii_preview,
            u8_val,
            u16_le,
            u16_be,
            u32_le,
            u32_be,
            u64_le,
            u64_be,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_forward() {
        let sel = Selection { anchor: 5, end: 10 };
        assert_eq!(sel.start(), 5);
        assert_eq!(sel.end_inclusive(), 10);
        assert_eq!(sel.len(), 6);
        assert!(sel.contains(5));
        assert!(sel.contains(10));
        assert!(!sel.contains(4));
        assert!(!sel.contains(11));
    }

    #[test]
    fn selection_backward() {
        let sel = Selection { anchor: 10, end: 5 };
        assert_eq!(sel.start(), 5);
        assert_eq!(sel.end_inclusive(), 10);
        assert_eq!(sel.len(), 6);
    }

    #[test]
    fn selection_single_byte() {
        let sel = Selection { anchor: 7, end: 7 };
        assert_eq!(sel.len(), 1);
        assert!(sel.contains(7));
    }

    #[test]
    fn selection_meta_basic() {
        let sel = Selection { anchor: 0, end: 3 };
        let bytes = &[0x01, 0x02, 0x03, 0x04];
        let meta = SelectionMeta::from_bytes(&sel, bytes);
        assert_eq!(meta.start, 0);
        assert_eq!(meta.end_inclusive, 3);
        assert_eq!(meta.length, 4);
        assert_eq!(meta.u8_val, Some(0x01));
        assert_eq!(meta.u16_le, Some(0x0201));
        assert_eq!(meta.u16_be, Some(0x0102));
        assert_eq!(meta.u32_le, Some(0x04030201));
        assert_eq!(meta.u32_be, Some(0x01020304));
        assert!(meta.hex_preview.contains("01 02 03 04"));
    }

    #[test]
    fn selection_meta_single_byte() {
        let sel = Selection {
            anchor: 10,
            end: 10,
        };
        let bytes = &[0xFF];
        let meta = SelectionMeta::from_bytes(&sel, bytes);
        assert_eq!(meta.u8_val, Some(0xFF));
        assert_eq!(meta.u16_le, None);
        assert_eq!(meta.u32_le, None);
        assert_eq!(meta.u64_le, None);
    }
}
