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
    pub fn auto_analyze(
        &self,
        handle: &FileHandle,
        src: &dyn ByteSource,
    ) -> Option<Result<AnalysisReport, AnalyzeError>> {
        let (analyzer, _confidence) = self.best_match(handle, src)?;
        Some(analyzer.analyze(handle, src))
    }
}

impl Default for AnalyzerRegistry {
    fn default() -> Self {
        Self::new()
    }
}
