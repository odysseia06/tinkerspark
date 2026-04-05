mod error;
mod kind_sniff;
mod source;

pub use error::ReadError;
pub use kind_sniff::sniff_kind;
pub use source::{open_file, BackendKind, ByteSource, MemoryByteSource};
