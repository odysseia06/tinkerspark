// core-analyze: Analyzer plugin boundary.
//
// Defines the trait that format-specific analyzers implement,
// and the generic analysis result model.

mod error;
mod model;
mod registry;
mod traits;

pub use error::AnalyzeError;
pub use model::{AnalysisNode, AnalysisReport, FieldView};
pub use registry::AnalyzerRegistry;
pub use traits::{Analyzer, AnalyzerConfidence};
