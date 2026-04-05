use tinkerspark_core_types::ByteRange;

/// Configuration for how hex rows are rendered.
#[derive(Debug, Clone)]
pub struct HexViewConfig {
    /// Number of bytes displayed per row. Must be >= 1.
    pub bytes_per_row: usize,
}

impl Default for HexViewConfig {
    fn default() -> Self {
        Self { bytes_per_row: 16 }
    }
}

/// A single row in the hex view.
#[derive(Debug, Clone)]
pub struct HexRow {
    /// File offset of the first byte in this row.
    pub offset: u64,
    /// The bytes in this row (may be shorter than bytes_per_row for the last row).
    pub bytes: Vec<u8>,
}

/// Mutable state for a hex view tied to one open file.
pub struct HexViewState {
    pub config: HexViewConfig,
    pub file_len: u64,
    /// The file offset of the first byte visible in the viewport.
    pub scroll_offset: u64,
    /// Cursor position (byte offset within the file). Always < file_len when file is non-empty.
    pub cursor: u64,
    /// Active selection, if any.
    pub selection: Option<crate::Selection>,
    /// Drag anchor — set on mouse-down, cleared on mouse-up.
    /// While set, mouse movement extends the selection.
    pub drag_anchor: Option<u64>,
}

impl HexViewState {
    pub fn new(file_len: u64) -> Self {
        Self {
            config: HexViewConfig::default(),
            file_len,
            scroll_offset: 0,
            cursor: 0,
            selection: None,
            drag_anchor: None,
        }
    }

    pub fn bytes_per_row(&self) -> usize {
        self.config.bytes_per_row.max(1)
    }

    pub fn total_rows(&self) -> u64 {
        let bpr = self.bytes_per_row() as u64;
        if self.file_len == 0 {
            return 0;
        }
        self.file_len.div_ceil(bpr)
    }

    /// Move cursor by `delta` bytes, clamping to file bounds.
    /// If `extend_selection` is true, extends/creates a selection from the anchor.
    pub fn move_cursor(&mut self, delta: i64, extend_selection: bool) {
        if self.file_len == 0 {
            return;
        }
        let old = self.cursor;
        if delta < 0 {
            self.cursor = self.cursor.saturating_sub(delta.unsigned_abs());
        } else {
            self.cursor = self
                .cursor
                .saturating_add(delta as u64)
                .min(self.file_len - 1);
        }

        if extend_selection {
            match &mut self.selection {
                Some(sel) => sel.end = self.cursor,
                None => {
                    self.selection = Some(crate::Selection {
                        anchor: old,
                        end: self.cursor,
                    })
                }
            }
        } else {
            self.selection = None;
        }
    }

    /// Set cursor to an absolute offset, clamped to file bounds.
    pub fn set_cursor(&mut self, offset: u64) {
        if self.file_len == 0 {
            self.cursor = 0;
            return;
        }
        self.cursor = offset.min(self.file_len - 1);
        self.selection = None;
    }

    /// Jump to a specific offset. Returns true if the offset was valid.
    pub fn jump_to(&mut self, offset: u64) -> bool {
        if self.file_len == 0 {
            return false;
        }
        if offset >= self.file_len {
            return false;
        }
        self.cursor = offset;
        self.selection = None;
        self.ensure_cursor_visible(0);
        true
    }

    /// Parse a jump target string. Supports decimal and "0x" hex prefix.
    pub fn parse_jump_target(input: &str) -> Option<u64> {
        let s = input.trim();
        if s.is_empty() {
            return None;
        }
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()
        } else {
            s.parse::<u64>().ok()
        }
    }

    /// Ensure the cursor is visible within the viewport.
    /// `visible_rows` is the number of rows currently visible on screen.
    pub fn ensure_cursor_visible(&mut self, visible_rows: usize) {
        let bpr = self.bytes_per_row() as u64;
        let cursor_row = self.cursor / bpr;
        let scroll_row = self.scroll_offset / bpr;

        if cursor_row < scroll_row {
            self.scroll_offset = cursor_row * bpr;
        } else if visible_rows > 0 && cursor_row >= scroll_row + visible_rows as u64 {
            self.scroll_offset = (cursor_row - visible_rows as u64 + 1) * bpr;
        }
    }

    /// Scroll to a specific row, clamped to valid bounds.
    pub fn scroll_to_row(&mut self, row: u64) {
        let bpr = self.bytes_per_row() as u64;
        let max_row = self.total_rows().saturating_sub(1);
        self.scroll_offset = row.min(max_row) * bpr;
    }

    /// Start or extend selection from the cursor to a target offset.
    pub fn select_to(&mut self, target: u64) {
        if self.file_len == 0 {
            return;
        }
        let target = target.min(self.file_len - 1);
        match &mut self.selection {
            Some(sel) => sel.end = target,
            None => {
                self.selection = Some(crate::Selection {
                    anchor: self.cursor,
                    end: target,
                })
            }
        }
        self.cursor = target;
    }

    /// Select all bytes in the file.
    pub fn select_all(&mut self) {
        if self.file_len == 0 {
            return;
        }
        self.selection = Some(crate::Selection {
            anchor: 0,
            end: self.file_len - 1,
        });
    }

    /// Begin a mouse drag at the given byte offset.
    pub fn begin_drag(&mut self, offset: u64) {
        if self.file_len == 0 {
            return;
        }
        let offset = offset.min(self.file_len - 1);
        self.cursor = offset;
        self.selection = None;
        self.drag_anchor = Some(offset);
    }

    /// Update an in-progress drag. Extends selection from the drag anchor
    /// to the current offset. No-op if no drag is active.
    pub fn update_drag(&mut self, offset: u64) {
        let Some(anchor) = self.drag_anchor else {
            return;
        };
        if self.file_len == 0 {
            return;
        }
        let offset = offset.min(self.file_len - 1);
        self.cursor = offset;
        self.selection = Some(crate::Selection {
            anchor,
            end: offset,
        });
    }

    /// End a drag. If no movement occurred, produce a single-byte selection
    /// at the anchor so single-click selects one byte. The drag anchor is cleared.
    pub fn end_drag(&mut self) {
        if let Some(anchor) = self.drag_anchor.take() {
            if self.selection.is_none() {
                // Click without drag — select the single byte.
                self.selection = Some(crate::Selection {
                    anchor,
                    end: anchor,
                });
            }
        }
    }
}

/// Compute which byte range is visible given a scroll offset and viewport height.
///
/// The range is clamped to `file_len`. Returns an empty range if `bytes_per_row`
/// or `visible_rows` is zero.
pub fn visible_range(
    scroll_offset: u64,
    visible_rows: usize,
    bytes_per_row: usize,
    file_len: u64,
) -> ByteRange {
    if bytes_per_row == 0 || visible_rows == 0 || file_len == 0 {
        return ByteRange::new(scroll_offset.min(file_len), 0);
    }
    let bpr = bytes_per_row as u64;
    let row_start = scroll_offset / bpr;
    let byte_offset = row_start * bpr;
    let length = (visible_rows as u64).saturating_mul(bpr);
    // Clamp to file bounds.
    let clamped_len = length.min(file_len.saturating_sub(byte_offset));
    ByteRange::new(byte_offset, clamped_len)
}

/// Build hex rows from raw bytes at a given starting offset.
pub fn build_rows(offset: u64, data: &[u8], bytes_per_row: usize) -> Vec<HexRow> {
    let bpr = bytes_per_row.max(1);
    data.chunks(bpr)
        .enumerate()
        .map(|(i, chunk)| HexRow {
            offset: offset + (i * bpr) as u64,
            bytes: chunk.to_vec(),
        })
        .collect()
}

/// Format a byte as a two-character hex string.
pub fn format_hex_byte(b: u8) -> [u8; 2] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    [HEX[(b >> 4) as usize], HEX[(b & 0x0F) as usize]]
}

/// Convert a byte to its ASCII display character, or '.' for non-printable.
pub fn ascii_char(b: u8) -> char {
    if b.is_ascii_graphic() || b == b' ' {
        b as char
    } else {
        '.'
    }
}

/// Number of hex characters used for the offset gutter, based on file size.
pub fn offset_gutter_chars(file_len: u64) -> usize {
    if file_len <= 0xFFFF_FFFF {
        8
    } else {
        16
    }
}

/// Format an offset as a hex string with appropriate width for the file size.
pub fn format_offset(offset: u64, file_len: u64) -> String {
    let width = offset_gutter_chars(file_len);
    format!("{offset:0>width$X}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_range_basic() {
        let range = visible_range(0, 10, 16, 1000);
        assert_eq!(range.offset(), 0);
        assert_eq!(range.length(), 160);
    }

    #[test]
    fn visible_range_scrolled() {
        let range = visible_range(32, 5, 16, 1000);
        assert_eq!(range.offset(), 32);
        assert_eq!(range.length(), 80);
    }

    #[test]
    fn visible_range_clamps_to_file_len() {
        let range = visible_range(0, 100, 16, 50);
        assert_eq!(range.offset(), 0);
        assert_eq!(range.length(), 50);
    }

    #[test]
    fn visible_range_zero_bytes_per_row() {
        let range = visible_range(100, 10, 0, 1000);
        assert_eq!(range.length(), 0);
    }

    #[test]
    fn visible_range_zero_rows() {
        let range = visible_range(0, 0, 16, 1000);
        assert_eq!(range.length(), 0);
    }

    #[test]
    fn visible_range_empty_file() {
        let range = visible_range(0, 10, 16, 0);
        assert_eq!(range.length(), 0);
    }

    #[test]
    fn build_rows_basic() {
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let rows = build_rows(0, &data, 4);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].offset, 0);
        assert_eq!(rows[0].bytes, vec![0, 1, 2, 3]);
        assert_eq!(rows[1].offset, 4);
        assert_eq!(rows[1].bytes, vec![4, 5, 6, 7]);
        assert_eq!(rows[2].offset, 8);
        assert_eq!(rows[2].bytes, vec![8, 9]);
    }

    #[test]
    fn build_rows_with_offset() {
        let data = vec![0xAA, 0xBB];
        let rows = build_rows(0x100, &data, 16);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].offset, 0x100);
    }

    #[test]
    fn build_rows_empty() {
        let rows = build_rows(0, &[], 16);
        assert!(rows.is_empty());
    }

    #[test]
    fn format_hex_byte_works() {
        assert_eq!(&format_hex_byte(0x00), b"00");
        assert_eq!(&format_hex_byte(0xFF), b"FF");
        assert_eq!(&format_hex_byte(0x0A), b"0A");
        assert_eq!(&format_hex_byte(0xAB), b"AB");
    }

    #[test]
    fn ascii_char_works() {
        assert_eq!(ascii_char(b'A'), 'A');
        assert_eq!(ascii_char(b' '), ' ');
        assert_eq!(ascii_char(0x00), '.');
        assert_eq!(ascii_char(0xFF), '.');
        assert_eq!(ascii_char(0x7F), '.');
    }

    #[test]
    fn format_offset_works() {
        assert_eq!(format_offset(0, 256), "00000000");
        assert_eq!(format_offset(0xFF, 256), "000000FF");
        assert_eq!(
            format_offset(0x1_0000_0000, 0x2_0000_0000),
            "0000000100000000"
        );
    }

    #[test]
    fn total_rows() {
        let s = HexViewState::new(100);
        assert_eq!(s.total_rows(), 7); // ceil(100/16)

        let s2 = HexViewState::new(0);
        assert_eq!(s2.total_rows(), 0);

        let s3 = HexViewState::new(16);
        assert_eq!(s3.total_rows(), 1);

        let s4 = HexViewState::new(17);
        assert_eq!(s4.total_rows(), 2);
    }

    #[test]
    fn move_cursor_basic() {
        let mut s = HexViewState::new(100);
        s.move_cursor(5, false);
        assert_eq!(s.cursor, 5);
        assert!(s.selection.is_none());

        s.move_cursor(-3, false);
        assert_eq!(s.cursor, 2);
    }

    #[test]
    fn move_cursor_clamps() {
        let mut s = HexViewState::new(10);
        s.move_cursor(100, false);
        assert_eq!(s.cursor, 9);

        s.move_cursor(-100, false);
        assert_eq!(s.cursor, 0);
    }

    #[test]
    fn move_cursor_empty_file() {
        let mut s = HexViewState::new(0);
        s.move_cursor(5, false);
        assert_eq!(s.cursor, 0);
    }

    #[test]
    fn move_cursor_with_selection() {
        let mut s = HexViewState::new(100);
        s.cursor = 10;
        s.move_cursor(5, true);
        assert_eq!(s.cursor, 15);
        let sel = s.selection.unwrap();
        assert_eq!(sel.anchor, 10);
        assert_eq!(sel.end, 15);

        // Extend further
        s.move_cursor(3, true);
        assert_eq!(s.cursor, 18);
        let sel = s.selection.unwrap();
        assert_eq!(sel.anchor, 10);
        assert_eq!(sel.end, 18);
    }

    #[test]
    fn jump_to_works() {
        let mut s = HexViewState::new(100);
        assert!(s.jump_to(50));
        assert_eq!(s.cursor, 50);
        assert!(s.selection.is_none());

        assert!(!s.jump_to(100));
        assert_eq!(s.cursor, 50); // unchanged
    }

    #[test]
    fn parse_jump_target_works() {
        assert_eq!(HexViewState::parse_jump_target("100"), Some(100));
        assert_eq!(HexViewState::parse_jump_target("0xFF"), Some(255));
        assert_eq!(HexViewState::parse_jump_target("0X10"), Some(16));
        assert_eq!(HexViewState::parse_jump_target("  42  "), Some(42));
        assert_eq!(HexViewState::parse_jump_target(""), None);
        assert_eq!(HexViewState::parse_jump_target("xyz"), None);
    }

    #[test]
    fn ensure_cursor_visible_scrolls_down() {
        let mut s = HexViewState::new(1000);
        s.cursor = 200;
        s.scroll_offset = 0;
        s.ensure_cursor_visible(10);
        // cursor is at row 12 (200/16), viewport shows rows 0-9
        // should scroll so cursor is in view
        assert!(s.scroll_offset <= 200);
        let scroll_row = s.scroll_offset / 16;
        let cursor_row = 200 / 16;
        assert!(cursor_row >= scroll_row);
        assert!(cursor_row < scroll_row + 10);
    }

    #[test]
    fn ensure_cursor_visible_scrolls_up() {
        let mut s = HexViewState::new(1000);
        s.cursor = 0;
        s.scroll_offset = 160; // row 10
        s.ensure_cursor_visible(10);
        assert_eq!(s.scroll_offset, 0);
    }

    #[test]
    fn select_all_works() {
        let mut s = HexViewState::new(100);
        s.select_all();
        let sel = s.selection.unwrap();
        assert_eq!(sel.anchor, 0);
        assert_eq!(sel.end, 99);
    }

    #[test]
    fn select_all_empty_file() {
        let mut s = HexViewState::new(0);
        s.select_all();
        assert!(s.selection.is_none());
    }

    #[test]
    fn click_produces_single_byte_selection() {
        let mut s = HexViewState::new(100);
        // Simulate a click: begin_drag, then immediately end_drag (no movement).
        s.begin_drag(5);
        s.end_drag();
        let sel = s.selection.unwrap();
        assert_eq!(sel.start(), 5);
        assert_eq!(sel.end_inclusive(), 5);
        assert_eq!(sel.len(), 1);
    }

    #[test]
    fn drag_produces_multi_byte_selection() {
        let mut s = HexViewState::new(100);
        s.begin_drag(5);
        s.update_drag(10);
        s.end_drag();
        let sel = s.selection.unwrap();
        assert_eq!(sel.start(), 5);
        assert_eq!(sel.end_inclusive(), 10);
        assert_eq!(sel.len(), 6);
    }
}
