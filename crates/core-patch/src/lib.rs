mod error;
mod history;
mod patch;
mod patched_view;

pub use error::PatchError;
pub use history::PatchHistory;
pub use patch::{Patch, PatchSet};
pub use patched_view::PatchedView;
