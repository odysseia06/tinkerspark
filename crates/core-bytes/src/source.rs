use std::borrow::Cow;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use memmap2::Mmap;
use tracing::{info, warn};

use tinkerspark_core_types::{ByteRange, FileHandle, FileId};

use crate::error::ReadError;
use crate::kind_sniff::sniff_kind;

/// Which backend strategy is used for file access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Mmap,
    Buffered,
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendKind::Mmap => write!(f, "mmap"),
            BackendKind::Buffered => write!(f, "buffered"),
        }
    }
}

/// Read-only byte source backed by a file.
///
/// `read_range` returns `Cow<[u8]>`: both backends borrow directly from their
/// backing store (mmap region or in-memory buffer) — zero-copy, zero-alloc.
/// Use `read_range_into` when you have a pre-allocated buffer.
///
/// # Snapshot semantics
///
/// The **buffered** backend is a true snapshot: the file is read in full at
/// open time and later changes to the file on disk are not visible.
///
/// The **mmap** backend reflects the OS page cache and may see changes made
/// to the underlying file by other processes. This is inherent to how memory
/// mapping works and is acceptable for this tool's use case: inspecting files
/// selected by the user, not racing concurrent writers. Callers that need
/// strict snapshot isolation should check `BackendKind`.
pub trait ByteSource: Send + Sync {
    fn len(&self) -> u64;

    /// Read bytes from the source. Returns borrowed data (zero-copy).
    fn read_range(&self, range: ByteRange) -> Result<Cow<'_, [u8]>, ReadError>;

    /// Read bytes into a caller-provided buffer. The buffer length must
    /// equal `range.length()`. This avoids allocation for both backends.
    fn read_range_into(&self, range: ByteRange, buf: &mut [u8]) -> Result<(), ReadError> {
        let data = self.read_range(range)?;
        buf.copy_from_slice(&data);
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A file-backed ByteSource.
///
/// - **Mmap**: zero-copy reads from the OS page cache. Efficient for large
///   files. Not a snapshot — external modifications may be visible. If the
///   file is truncated, reads beyond the new length may fault. On Windows the
///   OS locks the file while mapped, providing stronger protection.
///
/// - **Buffered**: the entire file is read into memory at open time, creating
///   a true immutable snapshot. Used as fallback when mmap is unavailable
///   (empty files, special filesystems, OS limits).
pub struct FileByteSource {
    // Stored for diagnostics and potential future display; not read through
    // the ByteSource trait, which is the primary access path.
    #[allow(dead_code)]
    path: PathBuf,
    size: u64,
    backend: Backend,
}

enum Backend {
    Mmap(Mmap),
    /// Full file contents read into memory at open time.
    Buffered(Vec<u8>),
}

impl Backend {
    /// Actual byte length held by this backend.
    fn len(&self) -> u64 {
        match self {
            Backend::Mmap(mmap) => mmap.len() as u64,
            Backend::Buffered(data) => data.len() as u64,
        }
    }
}

/// Validate range against file length and convert to usize, including the
/// end offset. Returns (start, len) on success, where start + len is
/// guaranteed not to overflow usize.
fn validate_range(range: ByteRange, file_len: u64) -> Result<(usize, usize), ReadError> {
    if range.end() > file_len {
        return Err(ReadError::OutOfBounds { range, file_len });
    }
    let start = usize::try_from(range.offset()).map_err(|_| ReadError::RangeTooLarge { range })?;
    let len = usize::try_from(range.length()).map_err(|_| ReadError::RangeTooLarge { range })?;
    // Verify start + len doesn't overflow usize. This matters on platforms
    // where usize is smaller than u64 (e.g., 32-bit): offset and length may
    // each fit in usize while their sum does not.
    start
        .checked_add(len)
        .ok_or(ReadError::RangeTooLarge { range })?;
    Ok((start, len))
}

impl ByteSource for FileByteSource {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_range(&self, range: ByteRange) -> Result<Cow<'_, [u8]>, ReadError> {
        if range.is_empty() {
            return Ok(Cow::Borrowed(&[]));
        }
        let (start, len) = validate_range(range, self.size)?;

        match &self.backend {
            Backend::Mmap(mmap) => Ok(Cow::Borrowed(&mmap[start..start + len])),
            Backend::Buffered(data) => Ok(Cow::Borrowed(&data[start..start + len])),
        }
    }

    fn read_range_into(&self, range: ByteRange, buf: &mut [u8]) -> Result<(), ReadError> {
        if range.is_empty() {
            return Ok(());
        }
        let (start, len) = validate_range(range, self.size)?;
        assert_eq!(
            buf.len(),
            len,
            "buffer length {} does not match range length {}",
            buf.len(),
            len
        );

        match &self.backend {
            Backend::Mmap(mmap) => {
                buf.copy_from_slice(&mmap[start..start + len]);
            }
            Backend::Buffered(data) => {
                buf.copy_from_slice(&data[start..start + len]);
            }
        }
        Ok(())
    }
}

/// Open a file and return a ByteSource + FileHandle.
///
/// - **Mmap** (primary): memory-mapped region for zero-copy reads. Not a
///   snapshot — see [`ByteSource`] docs for caveats.
/// - **Buffered** (fallback): entire file read into memory. True snapshot.
///
/// The returned `size` and kind metadata are derived from the backend's
/// actual content, not from stale filesystem metadata.
pub fn open_file(path: &Path) -> Result<(Box<dyn ByteSource>, FileHandle, BackendKind), ReadError> {
    // Use canonical path for I/O (mmap, buffered reads) but keep the
    // user-supplied path for display. On Windows, canonicalize() returns
    // UNC extended-length paths (\\?\C:\...) which are ugly in a UI.
    let io_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let display_path = path.to_path_buf();

    // Stat the file to decide on backend strategy. The metadata size is
    // only used to choose mmap vs buffered — the authoritative size comes
    // from the backend itself (mmap.len() or data.len()) to avoid races.
    let stat_size = fs::metadata(path)?.len();

    let (backend, backend_kind) = if stat_size == 0 {
        info!(?path, "empty file, using buffered backend");
        (Backend::Buffered(Vec::new()), BackendKind::Buffered)
    } else {
        match try_mmap(&io_path) {
            Ok(mmap) => {
                info!(?path, "opened with mmap backend");
                (Backend::Mmap(mmap), BackendKind::Mmap)
            }
            Err(e) => {
                warn!(?path, error = %e, "mmap failed, reading file into memory");
                let data = read_full(&io_path)?;
                (Backend::Buffered(data), BackendKind::Buffered)
            }
        }
    };

    // Derive size from the backend's actual content, not from the stat
    // we did earlier. If the file changed between stat and open, this
    // keeps size consistent with what we'll actually serve from reads.
    let size = backend.len();

    // Sniff kind from the backend's content. No additional I/O.
    let header = backend_header(&backend, size);
    let kind = sniff_kind(&header, &display_path, size);

    info!(?path, %size, %kind, %backend_kind, "file opened");

    let source = FileByteSource {
        path: io_path,
        size,
        backend,
    };

    let handle = FileHandle {
        id: FileId::new(),
        path: display_path,
        size,
        kind,
    };

    Ok((Box::new(source), handle, backend_kind))
}

fn try_mmap(path: &Path) -> Result<Mmap, std::io::Error> {
    let file = File::open(path)?;
    // SAFETY: We treat the mapped region as read-only and assume the file
    // is not truncated while we hold the mapping. This is documented as a
    // requirement for using Tinkerspark.
    unsafe { Mmap::map(&file) }
}

/// Read the entire file into memory. Used as the buffered fallback when
/// mmap is unavailable.
fn read_full(path: &Path) -> Result<Vec<u8>, ReadError> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Extract the first up to 512 bytes from the already-captured backend
/// for kind sniffing. No additional I/O.
fn backend_header(backend: &Backend, size: u64) -> Vec<u8> {
    let header_len = std::cmp::min(size, 512) as usize;
    if header_len == 0 {
        return Vec::new();
    }
    match backend {
        Backend::Mmap(mmap) => mmap[..header_len].to_vec(),
        Backend::Buffered(data) => data[..header_len].to_vec(),
    }
}

/// ByteSource backed by an in-memory buffer. Useful for testing.
pub struct MemoryByteSource {
    data: Vec<u8>,
}

impl MemoryByteSource {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl ByteSource for MemoryByteSource {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_range(&self, range: ByteRange) -> Result<Cow<'_, [u8]>, ReadError> {
        if range.is_empty() {
            return Ok(Cow::Borrowed(&[]));
        }
        let file_len = self.data.len() as u64;
        let (start, len) = validate_range(range, file_len)?;
        Ok(Cow::Borrowed(&self.data[start..start + len]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tinkerspark_core_types::DetectedKind;

    #[test]
    fn memory_source_read_range() {
        let src = MemoryByteSource::new(vec![0, 1, 2, 3, 4, 5]);
        let data = src.read_range(ByteRange::new(2, 3)).unwrap();
        assert_eq!(&*data, &[2, 3, 4]);
    }

    #[test]
    fn memory_source_out_of_bounds() {
        let src = MemoryByteSource::new(vec![0, 1, 2]);
        let result = src.read_range(ByteRange::new(2, 5));
        assert!(result.is_err());
    }

    #[test]
    fn memory_source_empty_range() {
        let src = MemoryByteSource::new(vec![0, 1, 2]);
        let data = src.read_range(ByteRange::new(1, 0)).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn memory_source_borrows() {
        let src = MemoryByteSource::new(vec![0, 1, 2, 3]);
        let data = src.read_range(ByteRange::new(0, 4)).unwrap();
        assert!(
            matches!(data, Cow::Borrowed(_)),
            "MemoryByteSource should borrow"
        );
    }

    #[test]
    fn read_range_into_works() {
        let src = MemoryByteSource::new(vec![10, 20, 30, 40, 50]);
        let mut buf = [0u8; 3];
        src.read_range_into(ByteRange::new(1, 3), &mut buf).unwrap();
        assert_eq!(buf, [20, 30, 40]);
    }

    #[test]
    fn open_file_works() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"Hello, world!").unwrap();
        tmp.flush().unwrap();

        let (source, handle, _backend) = open_file(tmp.path()).unwrap();
        assert_eq!(source.len(), 13);
        assert_eq!(handle.size, 13);
        assert_eq!(handle.kind, DetectedKind::Text);

        let data = source.read_range(ByteRange::new(0, 5)).unwrap();
        assert_eq!(&*data, b"Hello");
    }

    #[test]
    fn open_file_mmap_borrows() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"test data for mmap").unwrap();
        tmp.flush().unwrap();

        let (source, _handle, backend) = open_file(tmp.path()).unwrap();
        let data = source.read_range(ByteRange::new(0, 4)).unwrap();
        if backend == BackendKind::Mmap {
            assert!(
                matches!(data, Cow::Borrowed(_)),
                "mmap backend should borrow"
            );
        }
    }

    #[test]
    fn buffered_backend_is_true_snapshot() {
        // Backend::Buffered reads from its in-memory Vec, not from disk.
        // Prove this by using a nonexistent path.
        let src = FileByteSource {
            path: PathBuf::from("nonexistent-file-that-must-not-be-opened"),
            size: 5,
            backend: Backend::Buffered(b"hello".to_vec()),
        };
        let data = src.read_range(ByteRange::new(0, 5)).unwrap();
        assert_eq!(&*data, b"hello");
        assert!(
            matches!(data, Cow::Borrowed(_)),
            "buffered should borrow from snapshot"
        );
    }

    #[test]
    fn buffered_size_matches_actual_data() {
        // If file shrinks between stat and read_full, size must reflect
        // the actual data length, not the stale stat size.
        let src = FileByteSource {
            path: PathBuf::from("irrelevant"),
            size: 3,
            backend: Backend::Buffered(b"abc".to_vec()),
        };
        assert_eq!(src.len(), 3);

        // Simulate what open_file does: size comes from backend.len().
        let backend = Backend::Buffered(b"ab".to_vec());
        let size = backend.len();
        assert_eq!(size, 2, "size must come from actual data, not metadata");
    }

    #[test]
    fn open_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let (source, handle, _backend) = open_file(tmp.path()).unwrap();
        assert_eq!(source.len(), 0);
        assert_eq!(handle.kind, DetectedKind::Empty);
    }

    #[test]
    fn open_file_detects_armored_pgp() {
        let mut tmp = tempfile::Builder::new().suffix(".asc").tempfile().unwrap();
        tmp.write_all(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\ndata")
            .unwrap();
        tmp.flush().unwrap();

        let (_source, handle, _backend) = open_file(tmp.path()).unwrap();
        assert_eq!(handle.kind, DetectedKind::OpenPgpArmored);
    }
}
