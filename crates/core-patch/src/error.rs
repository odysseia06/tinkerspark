use tinkerspark_core_types::ByteRange;

#[derive(Debug, thiserror::Error)]
pub enum PatchError {
    #[error("patch range {range:?} exceeds file length {file_len}")]
    OutOfBounds { range: ByteRange, file_len: u64 },

    #[error("patch at {new:?} overlaps existing patch at {existing:?}")]
    Conflict { existing: ByteRange, new: ByteRange },

    #[error("replacement length {replacement_len} differs from range length {range_len} (same-length replacement required)")]
    LengthMismatch {
        range_len: u64,
        replacement_len: usize,
    },

    #[error("empty replacement")]
    EmptyPatch,
}
