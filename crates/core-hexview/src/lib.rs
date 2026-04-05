pub mod search;
mod selection;
mod viewport;

pub use search::{parse_hex_pattern, SearchDirection, SearchHit, SearchQuery};
pub use selection::{Selection, SelectionMeta};
pub use viewport::{
    ascii_char, build_rows, format_hex_byte, format_offset, offset_gutter_chars, visible_range,
    HexRow, HexViewConfig, HexViewState,
};
