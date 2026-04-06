use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::FileHandle;

use crate::{AnalysisReport, AnalyzeError, Analyzer, AnalyzerConfidence};

/// Registry of available analyzers.
///
/// When a file is opened, the registry is asked to find the best analyzer
/// for the file's detected kind. The analyzer with the highest confidence
/// wins. Ties are broken by registration order (first registered wins).
pub struct AnalyzerRegistry {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl AnalyzerRegistry {
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
        }
    }

    pub fn register(&mut self, analyzer: Box<dyn Analyzer>) {
        self.analyzers.push(analyzer);
    }

    /// Find the best analyzer for the given file, if any.
    /// Returns the analyzer ID and confidence level.
    pub fn best_match(
        &self,
        handle: &FileHandle,
        src: &dyn ByteSource,
    ) -> Option<(&dyn Analyzer, AnalyzerConfidence)> {
        let mut best: Option<(&dyn Analyzer, AnalyzerConfidence)> = None;

        for analyzer in &self.analyzers {
            let confidence = analyzer.can_analyze(handle, src);
            if confidence == AnalyzerConfidence::None {
                continue;
            }
            match &best {
                Some((_, best_conf)) if *best_conf >= confidence => {}
                _ => best = Some((analyzer.as_ref(), confidence)),
            }
        }

        best
    }

    /// Run the best matching analyzer on the given file.
    /// Returns None if no analyzer matches.
    ///
    /// If the best-match analyzer returns a parse error, the registry tries
    /// the next-best analyzer (and so on) so that the generic fallback can
    /// still provide useful output for files that a dedicated analyzer rejects.
    pub fn auto_analyze(
        &self,
        handle: &FileHandle,
        src: &dyn ByteSource,
    ) -> Option<Result<AnalysisReport, AnalyzeError>> {
        // Collect all analyzers that express interest, sorted by confidence descending.
        let mut candidates: Vec<(&dyn Analyzer, AnalyzerConfidence)> = self
            .analyzers
            .iter()
            .filter_map(|a| {
                let c = a.can_analyze(handle, src);
                if c == AnalyzerConfidence::None {
                    None
                } else {
                    Some((a.as_ref(), c))
                }
            })
            .collect();
        // Stable sort descending — preserves registration order for ties.
        candidates.sort_by(|a, b| b.1.cmp(&a.1));

        let mut last_err = None;
        for (analyzer, _) in &candidates {
            match analyzer.analyze(handle, src) {
                Ok(report) => return Some(Ok(report)),
                Err(e) => {
                    tracing::debug!(
                        analyzer = analyzer.id(),
                        error = %e,
                        "analyzer failed, trying next candidate"
                    );
                    last_err = Some(e);
                }
            }
        }

        last_err.map(Err)
    }
}

impl Default for AnalyzerRegistry {
    fn default() -> Self {
        Self::new()
    }
}
