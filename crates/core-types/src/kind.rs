use serde::{Deserialize, Serialize};
use std::fmt;

/// The detected kind of a binary file, determined by content sniffing first,
/// extension second.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectedKind {
    /// ASCII-armored OpenPGP data (detected by header content).
    OpenPgpArmored,
    /// Binary OpenPGP data (detected by content magic or extension).
    OpenPgpBinary,
    /// OpenPGP candidate detected by file extension only.
    OpenPgpByExtension,
    /// Unknown binary data.
    Binary,
    /// Appears to be mostly text/ASCII content.
    Text,
    /// Empty file.
    Empty,
}

impl fmt::Display for DetectedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenPgpArmored => write!(f, "OpenPGP (armored)"),
            Self::OpenPgpBinary => write!(f, "OpenPGP (binary)"),
            Self::OpenPgpByExtension => write!(f, "OpenPGP (by extension)"),
            Self::Binary => write!(f, "Binary"),
            Self::Text => write!(f, "Text"),
            Self::Empty => write!(f, "Empty"),
        }
    }
}
