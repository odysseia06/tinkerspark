use tinkerspark_core_bytes::ReadError;

/// Which side of the diff produced the error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffSide {
    Left,
    Right,
}

impl std::fmt::Display for DiffSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiffSide::Left => write!(f, "left"),
            DiffSide::Right => write!(f, "right"),
        }
    }
}

/// Error from the diff engine.
#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    #[error("read error on {side} source at offset {offset}: {source}")]
    Read {
        side: DiffSide,
        offset: u64,
        source: ReadError,
    },
}
