use crate::{DetectedKind, FileId};
use std::path::PathBuf;

/// Metadata about an open file.
#[derive(Debug, Clone)]
pub struct FileHandle {
    pub id: FileId,
    pub path: PathBuf,
    pub size: u64,
    pub kind: DetectedKind,
}
