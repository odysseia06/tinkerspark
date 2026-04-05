use tinkerspark_core_types::{ByteRange, Diagnostic, NodeId};

/// A tree node representing a parsed structure element.
#[derive(Debug, Clone)]
pub struct AnalysisNode {
    pub id: NodeId,
    pub label: String,
    pub kind: String,
    pub range: ByteRange,
    pub children: Vec<AnalysisNode>,
    pub fields: Vec<FieldView>,
    pub diagnostics: Vec<Diagnostic>,
}

/// A single key-value field within an analysis node.
#[derive(Debug, Clone)]
pub struct FieldView {
    pub name: String,
    pub value: String,
    pub range: Option<ByteRange>,
}

/// The top-level result of running an analyzer on a byte source.
#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub analyzer_id: String,
    pub root_nodes: Vec<AnalysisNode>,
    pub diagnostics: Vec<Diagnostic>,
}
