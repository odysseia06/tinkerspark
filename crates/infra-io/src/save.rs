use std::fs;
use std::io::Write;
use std::path::Path;

use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_patch::{PatchSet, PatchedView};
use tinkerspark_core_types::ByteRange;

#[derive(Debug, thiserror::Error)]
pub enum SaveError {
    #[error("target path is the same as the source file")]
    TargetIsSource,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("read error: {0}")]
    Read(#[from] tinkerspark_core_bytes::ReadError),
}

/// Write a patched copy of the file to `target_path`.
///
/// Safety guarantees:
/// - The original source file is never modified.
/// - If `target_path` resolves to the same file as `source_path`, the
///   operation is rejected.
/// - The write goes to a temp file in the target directory first, then
///   is atomically renamed into place.
/// - On failure, any temp file is cleaned up and no partial output remains.
pub fn save_patched_copy(
    source: &dyn ByteSource,
    patches: &PatchSet,
    source_path: &Path,
    target_path: &Path,
) -> Result<(), SaveError> {
    // Prevent overwriting the original file.
    if paths_refer_to_same_file(source_path, target_path) {
        return Err(SaveError::TargetIsSource);
    }

    let view = PatchedView::new(source, patches);
    let file_len = view.len();

    // Create a temp file in the same directory as the target so the rename
    // is atomic (same filesystem).
    let target_dir = target_path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(target_dir)?;

    // Stream the patched content in chunks.
    const CHUNK_SIZE: u64 = 256 * 1024;
    let mut offset = 0u64;
    while offset < file_len {
        let len = CHUNK_SIZE.min(file_len - offset);
        let range = ByteRange::new(offset, len);
        let data = view.read_range(range)?;
        tmp.write_all(&data)?;
        offset += len;
    }
    tmp.flush()?;

    // Atomic rename into place. On Windows, persist() handles the
    // cross-volume fallback internally.
    tmp.persist(target_path).map_err(|e| e.error)?;

    Ok(())
}

/// Check if two paths refer to the same file on disk.
fn paths_refer_to_same_file(a: &Path, b: &Path) -> bool {
    // Try canonicalization for reliable comparison.
    let ca = fs::canonicalize(a);
    let cb = fs::canonicalize(b);
    match (ca, cb) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => {
            // If either fails (e.g., target doesn't exist yet), they
            // can't be the same existing file.
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tinkerspark_core_bytes::MemoryByteSource;

    #[test]
    fn save_no_patches() {
        let data = b"hello world".to_vec();
        let source = MemoryByteSource::new(data.clone());
        let patches = PatchSet::new();

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("output.bin");

        save_patched_copy(&source, &patches, Path::new("fake_source.bin"), &target).unwrap();

        let saved = fs::read(&target).unwrap();
        assert_eq!(saved, data);
    }

    #[test]
    fn save_with_patches() {
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let source = MemoryByteSource::new(data);
        let mut patches = PatchSet::new();
        patches
            .add(
                ByteRange::new(2, 3),
                vec![0xAA, 0xBB, 0xCC],
                "edit".into(),
                10,
            )
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("patched.bin");

        save_patched_copy(&source, &patches, Path::new("src.bin"), &target).unwrap();

        let saved = fs::read(&target).unwrap();
        assert_eq!(saved, vec![0, 1, 0xAA, 0xBB, 0xCC, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn save_rejects_source_path() {
        let data = b"test".to_vec();
        let source = MemoryByteSource::new(data);
        let patches = PatchSet::new();

        // Write a real file so canonicalize works.
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("original.bin");
        fs::write(&file_path, b"test").unwrap();

        let result = save_patched_copy(&source, &patches, &file_path, &file_path);
        assert!(matches!(result, Err(SaveError::TargetIsSource)));
    }

    #[test]
    fn save_to_new_path_when_source_does_not_exist() {
        // Source path doesn't exist on disk (e.g., piped input). Should succeed.
        let data = b"data".to_vec();
        let source = MemoryByteSource::new(data.clone());
        let patches = PatchSet::new();

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.bin");

        save_patched_copy(&source, &patches, Path::new("nonexistent"), &target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), data);
    }

    #[test]
    fn save_overwrites_existing_target() {
        let data = b"new content".to_vec();
        let source = MemoryByteSource::new(data.clone());
        let patches = PatchSet::new();

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("existing.bin");
        fs::write(&target, b"old content").unwrap();

        save_patched_copy(&source, &patches, Path::new("src.bin"), &target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), data);
    }

    #[test]
    fn save_empty_file() {
        let source = MemoryByteSource::new(Vec::new());
        let patches = PatchSet::new();

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("empty.bin");

        save_patched_copy(&source, &patches, Path::new("src.bin"), &target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn original_file_unchanged_after_save() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("original.bin");
        let target_path = dir.path().join("copy.bin");

        let original_data = vec![0, 1, 2, 3, 4, 5];
        fs::write(&source_path, &original_data).unwrap();

        let source = MemoryByteSource::new(original_data.clone());
        let mut patches = PatchSet::new();
        patches
            .add(ByteRange::new(0, 2), vec![0xFF, 0xFE], "p".into(), 6)
            .unwrap();

        save_patched_copy(&source, &patches, &source_path, &target_path).unwrap();

        // Original unchanged.
        assert_eq!(fs::read(&source_path).unwrap(), original_data);
        // Copy has patches.
        let saved = fs::read(&target_path).unwrap();
        assert_eq!(saved, vec![0xFF, 0xFE, 2, 3, 4, 5]);
    }
}
