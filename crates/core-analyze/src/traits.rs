use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::FileHandle;

use crate::{AnalysisReport, AnalyzeError};

/// How confident an analyzer is that it can handle a given file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnalyzerConfidence {
    /// Cannot analyze this file.
    None,
    /// Might be able to analyze (e.g., extension match only).
    Low,
    /// Likely match (e.g., magic bytes match).
    Medium,
    /// Definite match (e.g., full header validation).
    High,
}

/// Trait implemented by format-specific analyzers.
///
/// Analyzers receive a read-only `ByteSource` and the associated `FileHandle`
/// (which carries path, size, and pre-sniffed kind). They produce a tree of
/// `AnalysisNode`s with byte ranges that map back to the raw file.
pub trait Analyzer: Send + Sync {
    /// Unique identifier for this analyzer (e.g., "openpgp").
    fn id(&self) -> &'static str;

    /// Sniff whether this analyzer can handle the given file.
    ///
    /// `handle` provides path and detected-kind context so the analyzer can
    /// use both content-based and extension-based signals.
    fn can_analyze(&self, handle: &FileHandle, src: &dyn ByteSource) -> AnalyzerConfidence;

    /// Run analysis and produce a report.
    fn analyze(
        &self,
        handle: &FileHandle,
        src: &dyn ByteSource,
    ) -> Result<AnalysisReport, AnalyzeError>;
}
