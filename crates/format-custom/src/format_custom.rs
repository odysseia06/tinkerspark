mod parser;
pub mod template;

use std::path::{Path, PathBuf};

use tinkerspark_core_analyze::{
    AnalysisReport, AnalyzeError, Analyzer, AnalyzerConfidence, FieldView,
};
use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::{ByteRange, Diagnostic, FileHandle, NodeId, Severity};

use template::ValidatedTemplate;

// ── Public API ──────────────────────────────────────────────────────────

pub use template::validate;

/// An analyzer driven by a user-defined TOML template.
pub struct CustomAnalyzer {
    template: ValidatedTemplate,
    id_string: String,
}

impl CustomAnalyzer {
    pub fn new(template: ValidatedTemplate) -> Self {
        let id_string = format!("custom:{}", template.file.template.name);
        Self {
            template,
            id_string,
        }
    }
}

impl Analyzer for CustomAnalyzer {
    fn id(&self) -> &str {
        &self.id_string
    }

    fn can_analyze(&self, handle: &FileHandle, src: &dyn ByteSource) -> AnalyzerConfidence {
        let has_magic = !self.template.parsed_magic.is_empty();
        if has_magic && magic_matches(&self.template.parsed_magic, src) {
            return AnalyzerConfidence::Medium;
        }
        if extension_matches(&self.template.file.r#match.extensions, handle) {
            return AnalyzerConfidence::Low;
        }
        // Template with no match rules is a universal fallback.
        if !has_magic && self.template.file.r#match.extensions.is_empty() {
            return AnalyzerConfidence::Low;
        }
        AnalyzerConfidence::None
    }

    fn analyze(
        &self,
        _handle: &FileHandle,
        src: &dyn ByteSource,
    ) -> Result<AnalysisReport, AnalyzeError> {
        let (nodes, field_diagnostics) = parser::parse(&self.template, src);

        let file_len = src.len();
        // Wrap all field nodes under a single root node for the template.
        let root_range = ByteRange::new(0, file_len);
        let root = tinkerspark_core_analyze::AnalysisNode {
            id: NodeId::new(),
            label: self.template.file.template.name.clone(),
            kind: "custom_template".into(),
            range: root_range,
            children: nodes,
            fields: vec![
                FieldView {
                    name: "Template".into(),
                    value: self.template.file.template.name.clone(),
                    range: None,
                },
                FieldView {
                    name: "Endianness".into(),
                    value: match self.template.file.template.endian {
                        template::Endian::Big => "Big-endian".into(),
                        template::Endian::Little => "Little-endian".into(),
                    },
                    range: None,
                },
            ],
            diagnostics: Vec::new(),
        };

        let mut diagnostics = vec![Diagnostic {
            severity: Severity::Info,
            message: format!(
                "Analyzed by user-defined template \"{}\". Results are structural guidance, \
                 not authoritative parsing.",
                self.template.file.template.name
            ),
            range: None,
        }];
        diagnostics.extend(field_diagnostics);

        Ok(AnalysisReport {
            analyzer_id: self.id_string.clone(),
            root_nodes: vec![root],
            diagnostics,
        })
    }
}

fn magic_matches(rules: &[(u64, Vec<u8>)], src: &dyn ByteSource) -> bool {
    let file_len = src.len();
    for (offset, expected) in rules {
        let end = offset.saturating_add(expected.len() as u64);
        if end > file_len {
            return false;
        }
        let Some(range) = ByteRange::try_new(*offset, expected.len() as u64) else {
            return false;
        };
        let Ok(data) = src.read_range(range) else {
            return false;
        };
        if data.as_ref() != expected.as_slice() {
            return false;
        }
    }
    // All rules matched (AND semantics).
    !rules.is_empty()
}

fn extension_matches(extensions: &[String], handle: &FileHandle) -> bool {
    if extensions.is_empty() {
        return false;
    }
    let Some(ext) = handle.path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let ext_lower = ext.to_ascii_lowercase();
    extensions
        .iter()
        .any(|e| e.to_ascii_lowercase() == ext_lower)
}

// ── Template loading ────────────────────────────────────────────────────

/// Default template directory: `~/.tinkerspark/templates/`.
pub fn template_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".tinkerspark").join("templates"))
}

/// Load and validate all `.toml` templates from the default template directory.
/// Invalid or unreadable templates are logged and skipped.
pub fn load_templates() -> Vec<ValidatedTemplate> {
    let Some(dir) = template_dir() else {
        return Vec::new();
    };
    load_templates_from(&dir)
}

/// Load templates from a specific directory (used by tests).
pub fn load_templates_from(dir: &Path) -> Vec<ValidatedTemplate> {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };
    let mut templates = Vec::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        match load_one(&path) {
            Ok(t) => {
                tracing::info!(
                    template = %t.file.template.name,
                    path = %path.display(),
                    "loaded custom template"
                );
                templates.push(t);
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "skipping invalid template"
                );
            }
        }
    }
    templates
}

fn load_one(path: &Path) -> Result<ValidatedTemplate, LoadError> {
    let text = std::fs::read_to_string(path)?;
    let file: template::TemplateFile = toml::from_str(&text)?;
    let validated = template::validate(file)?;
    Ok(validated)
}

#[derive(Debug)]
enum LoadError {
    Io(std::io::Error),
    Toml(toml::de::Error),
    Validation(template::ValidationError),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Toml(e) => write!(f, "{e}"),
            Self::Validation(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<std::io::Error> for LoadError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<toml::de::Error> for LoadError {
    fn from(e: toml::de::Error) -> Self {
        Self::Toml(e)
    }
}

impl From<template::ValidationError> for LoadError {
    fn from(e: template::ValidationError) -> Self {
        Self::Validation(e)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tinkerspark_core_bytes::MemoryByteSource;
    use tinkerspark_core_types::{DetectedKind, FileId};

    fn make_handle(ext: &str) -> FileHandle {
        FileHandle {
            id: FileId::new(),
            path: PathBuf::from(format!("test.{}", ext)),
            size: 0,
            kind: DetectedKind::Binary,
        }
    }

    fn simple_template() -> ValidatedTemplate {
        let file: template::TemplateFile = toml::from_str(
            r#"
[template]
name = "Simple"

[match]
magic = [{ offset = 0, bytes = "AB CD" }]
extensions = ["sim"]

[[fields]]
name = "Magic"
type = "bytes"
size = 2

[[fields]]
name = "Version"
type = "u8"
"#,
        )
        .expect("test TOML");
        template::validate(file).expect("validate")
    }

    #[test]
    fn can_analyze_magic_match() {
        let analyzer = CustomAnalyzer::new(simple_template());
        let src = MemoryByteSource::new(vec![0xAB, 0xCD, 0x01]);
        let handle = make_handle("bin");
        assert_eq!(
            analyzer.can_analyze(&handle, &src),
            AnalyzerConfidence::Medium
        );
    }

    #[test]
    fn can_analyze_magic_no_match() {
        let analyzer = CustomAnalyzer::new(simple_template());
        let src = MemoryByteSource::new(vec![0x00, 0x00, 0x01]);
        let handle = make_handle("bin");
        assert_eq!(
            analyzer.can_analyze(&handle, &src),
            AnalyzerConfidence::None
        );
    }

    #[test]
    fn can_analyze_extension_match() {
        let analyzer = CustomAnalyzer::new(simple_template());
        let src = MemoryByteSource::new(vec![0x00, 0x00]); // no magic match
        let handle = make_handle("sim");
        assert_eq!(analyzer.can_analyze(&handle, &src), AnalyzerConfidence::Low);
    }

    #[test]
    fn can_analyze_no_match() {
        let analyzer = CustomAnalyzer::new(simple_template());
        let src = MemoryByteSource::new(vec![0x00, 0x00]);
        let handle = make_handle("xyz");
        assert_eq!(
            analyzer.can_analyze(&handle, &src),
            AnalyzerConfidence::None
        );
    }

    #[test]
    fn can_analyze_no_rules_matches_everything() {
        let file: template::TemplateFile = toml::from_str(
            r#"
[template]
name = "Universal"
"#,
        )
        .unwrap();
        let template = template::validate(file).unwrap();
        let analyzer = CustomAnalyzer::new(template);
        let src = MemoryByteSource::new(vec![0x01]);
        let handle = make_handle("anything");
        assert_eq!(analyzer.can_analyze(&handle, &src), AnalyzerConfidence::Low);
    }

    #[test]
    fn can_analyze_short_source_for_magic() {
        let analyzer = CustomAnalyzer::new(simple_template());
        let src = MemoryByteSource::new(vec![0xAB]); // only 1 byte, magic needs 2
        let handle = make_handle("bin");
        // Magic can't match (source too short), extension doesn't match either
        assert_eq!(
            analyzer.can_analyze(&handle, &src),
            AnalyzerConfidence::None
        );
    }

    #[test]
    fn analyze_produces_advisory_diagnostic() {
        let analyzer = CustomAnalyzer::new(simple_template());
        let src = MemoryByteSource::new(vec![0xAB, 0xCD, 0x01]);
        let handle = make_handle("sim");
        let report = analyzer.analyze(&handle, &src).unwrap();
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("structural guidance")));
    }

    #[test]
    fn analyze_partial_on_short_data() {
        let analyzer = CustomAnalyzer::new(simple_template());
        let src = MemoryByteSource::new(vec![0xAB, 0xCD]); // Magic OK, but no byte for Version
        let handle = make_handle("sim");
        let report = analyzer.analyze(&handle, &src).unwrap();
        // Root node with 1 child (Magic parsed), Version caused a diagnostic
        let root = &report.root_nodes[0];
        assert_eq!(root.children.len(), 1);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("needs 1 bytes")));
    }

    #[test]
    fn analyze_full_parse() {
        let analyzer = CustomAnalyzer::new(simple_template());
        let src = MemoryByteSource::new(vec![0xAB, 0xCD, 0x05]);
        let handle = make_handle("sim");
        let report = analyzer.analyze(&handle, &src).unwrap();
        let root = &report.root_nodes[0];
        assert_eq!(root.children.len(), 2);
        assert_eq!(root.children[0].label, "Magic");
        assert_eq!(root.children[1].label, "Version");
        assert_eq!(root.children[1].fields[0].value, "5 (0x5)");
    }

    #[test]
    fn id_contains_template_name() {
        let analyzer = CustomAnalyzer::new(simple_template());
        assert_eq!(analyzer.id(), "custom:Simple");
    }

    #[test]
    fn load_templates_from_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let templates = load_templates_from(dir.path());
        assert!(templates.is_empty());
    }

    #[test]
    fn load_templates_from_mixed_dir() {
        let dir = tempfile::tempdir().unwrap();
        // Valid template
        std::fs::write(
            dir.path().join("good.toml"),
            r#"
[template]
name = "Good"
[[fields]]
name = "Tag"
type = "u8"
"#,
        )
        .unwrap();
        // Invalid template (empty name)
        std::fs::write(
            dir.path().join("bad.toml"),
            r#"
[template]
name = ""
"#,
        )
        .unwrap();
        // Non-TOML file (ignored)
        std::fs::write(dir.path().join("readme.txt"), "not a template").unwrap();

        let templates = load_templates_from(dir.path());
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].file.template.name, "Good");
    }

    #[test]
    fn load_templates_nonexistent_dir() {
        let templates = load_templates_from(Path::new("/nonexistent/path"));
        assert!(templates.is_empty());
    }
}
