use tinkerspark_core_types::ByteRange;

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("range {range:?} exceeds file length {file_len}")]
    OutOfBounds { range: ByteRange, file_len: u64 },

    #[error("range {range:?} too large for addressable memory")]
    RangeTooLarge { range: ByteRange },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
