#[derive(Debug, thiserror::Error)]
pub enum AnalyzeError {
    #[error("read error: {0}")]
    Read(#[from] tinkerspark_core_bytes::ReadError),

    #[error("parse error: {message}")]
    Parse { message: String },

    #[error("unsupported format")]
    Unsupported,
}
