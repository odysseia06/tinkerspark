use std::collections::HashMap;

/// Raw TOML template file, deserialized directly.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TemplateFile {
    pub template: TemplateMeta,
    #[serde(default)]
    pub r#match: MatchRules,
    #[serde(default)]
    pub fields: Vec<FieldDef>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TemplateMeta {
    pub name: String,
    #[serde(default)]
    pub endian: Endian,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    #[default]
    Big,
    Little,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct MatchRules {
    #[serde(default)]
    pub magic: Vec<MagicRule>,
    #[serde(default)]
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct MagicRule {
    pub offset: u64,
    pub bytes: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct FieldDef {
    pub name: String,
    pub r#type: FieldType,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub size_from: Option<String>,
    #[serde(default)]
    pub known_values: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    Bytes,
    Utf8,
}

impl FieldType {
    /// Fixed byte width for integer types, None for variable-size types.
    pub fn fixed_size(self) -> Option<u64> {
        match self {
            Self::U8 | Self::I8 => Some(1),
            Self::U16 | Self::I16 => Some(2),
            Self::U32 | Self::I32 => Some(4),
            Self::U64 | Self::I64 => Some(8),
            Self::Bytes | Self::Utf8 => None,
        }
    }

    pub fn is_unsigned_integer(self) -> bool {
        matches!(self, Self::U8 | Self::U16 | Self::U32 | Self::U64)
    }

    pub fn is_integer(self) -> bool {
        self.fixed_size().is_some()
    }
}

/// A template that has passed validation, with pre-parsed magic bytes.
#[derive(Debug, Clone)]
pub struct ValidatedTemplate {
    pub file: TemplateFile,
    pub parsed_magic: Vec<(u64, Vec<u8>)>,
}

impl ValidatedTemplate {
    /// Whether this template has at least one match rule (magic or extension).
    /// Templates without rules cannot identify which files they apply to and
    /// are rejected by the auto-loader to prevent accidental universal fallback.
    pub fn has_match_rules(&self) -> bool {
        !self.parsed_magic.is_empty() || !self.file.r#match.extensions.is_empty()
    }
}

/// Parse a hex string like `"AB CD EF"` or `"ABCDEF"` into bytes.
fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>, ValidationError> {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(ValidationError::InvalidMagicHex(hex.to_string()));
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(chunk)
            .map_err(|_| ValidationError::InvalidMagicHex(hex.to_string()))?;
        let byte = u8::from_str_radix(pair, 16)
            .map_err(|_| ValidationError::InvalidMagicHex(hex.to_string()))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

pub fn validate(file: TemplateFile) -> Result<ValidatedTemplate, ValidationError> {
    if file.template.name.trim().is_empty() {
        return Err(ValidationError::EmptyName);
    }

    // Parse magic hex strings.
    let mut parsed_magic = Vec::with_capacity(file.r#match.magic.len());
    for rule in &file.r#match.magic {
        let bytes = parse_hex_bytes(&rule.bytes)?;
        if bytes.is_empty() {
            return Err(ValidationError::EmptyMagicBytes);
        }
        parsed_magic.push((rule.offset, bytes));
    }

    // Check for duplicate field names.
    let mut seen_names: HashMap<&str, usize> = HashMap::new();
    for (index, field) in file.fields.iter().enumerate() {
        if let Some(prev) = seen_names.insert(&field.name, index) {
            return Err(ValidationError::DuplicateFieldName {
                name: field.name.clone(),
                first: prev,
                second: index,
            });
        }
    }

    // Validate size_from references.
    for (index, field) in file.fields.iter().enumerate() {
        if let Some(ref source_name) = field.size_from {
            // size_from only valid on bytes/utf8
            if field.r#type.is_integer() {
                return Err(ValidationError::SizeFromOnInteger {
                    field: field.name.clone(),
                });
            }
            // Source must appear before this field
            match seen_names.get(source_name.as_str()) {
                Some(&source_index) if source_index < index => {
                    // Source must be an unsigned integer
                    let source_field = &file.fields[source_index];
                    if !source_field.r#type.is_unsigned_integer() {
                        return Err(ValidationError::SizeFromNonInteger {
                            field: field.name.clone(),
                            source: source_name.clone(),
                        });
                    }
                }
                Some(_) => {
                    return Err(ValidationError::SizeFromForwardRef {
                        field: field.name.clone(),
                        source: source_name.clone(),
                    });
                }
                None => {
                    return Err(ValidationError::SizeFromNotFound {
                        field: field.name.clone(),
                        source: source_name.clone(),
                    });
                }
            }
        }
    }

    Ok(ValidatedTemplate { file, parsed_magic })
}

#[derive(Debug)]
pub enum ValidationError {
    EmptyName,
    InvalidMagicHex(String),
    EmptyMagicBytes,
    DuplicateFieldName {
        name: String,
        first: usize,
        second: usize,
    },
    SizeFromOnInteger {
        field: String,
    },
    SizeFromNonInteger {
        field: String,
        source: String,
    },
    SizeFromForwardRef {
        field: String,
        source: String,
    },
    SizeFromNotFound {
        field: String,
        source: String,
    },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyName => write!(f, "template name must not be empty"),
            Self::InvalidMagicHex(s) => write!(f, "invalid hex in magic bytes: {s}"),
            Self::EmptyMagicBytes => write!(f, "magic bytes must not be empty"),
            Self::DuplicateFieldName {
                name,
                first,
                second,
            } => {
                write!(
                    f,
                    "duplicate field name \"{name}\" at positions {first} and {second}"
                )
            }
            Self::SizeFromOnInteger { field } => {
                write!(f, "size_from on integer field \"{field}\"")
            }
            Self::SizeFromNonInteger { field, source } => {
                write!(f, "size_from in \"{field}\" references \"{source}\" which is not an unsigned integer")
            }
            Self::SizeFromForwardRef { field, source } => {
                write!(
                    f,
                    "size_from in \"{field}\" references \"{source}\" which appears after it"
                )
            }
            Self::SizeFromNotFound { field, source } => {
                write!(
                    f,
                    "size_from in \"{field}\" references unknown field \"{source}\""
                )
            }
        }
    }
}

impl std::error::Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_toml(extra: &str) -> String {
        format!(
            r#"
[template]
name = "Test"
{extra}
"#
        )
    }

    #[test]
    fn valid_minimal_template() {
        let t: TemplateFile = toml::from_str(&minimal_toml("")).unwrap();
        validate(t).unwrap();
    }

    #[test]
    fn empty_name_rejected() {
        let t: TemplateFile = toml::from_str(
            r#"
[template]
name = "  "
"#,
        )
        .unwrap();
        assert!(matches!(validate(t), Err(ValidationError::EmptyName)));
    }

    #[test]
    fn duplicate_field_names_rejected() {
        let t: TemplateFile = toml::from_str(
            r#"
[template]
name = "Test"
[[fields]]
name = "Foo"
type = "u8"
[[fields]]
name = "Foo"
type = "u16"
"#,
        )
        .unwrap();
        assert!(matches!(
            validate(t),
            Err(ValidationError::DuplicateFieldName { .. })
        ));
    }

    #[test]
    fn size_from_forward_reference_rejected() {
        let t: TemplateFile = toml::from_str(
            r#"
[template]
name = "Test"
[[fields]]
name = "Data"
type = "bytes"
size_from = "Length"
[[fields]]
name = "Length"
type = "u32"
"#,
        )
        .unwrap();
        assert!(matches!(
            validate(t),
            Err(ValidationError::SizeFromForwardRef { .. })
        ));
    }

    #[test]
    fn size_from_non_integer_source_rejected() {
        let t: TemplateFile = toml::from_str(
            r#"
[template]
name = "Test"
[[fields]]
name = "Tag"
type = "bytes"
size = 2
[[fields]]
name = "Data"
type = "bytes"
size_from = "Tag"
"#,
        )
        .unwrap();
        assert!(matches!(
            validate(t),
            Err(ValidationError::SizeFromNonInteger { .. })
        ));
    }

    #[test]
    fn size_from_on_integer_field_rejected() {
        let t: TemplateFile = toml::from_str(
            r#"
[template]
name = "Test"
[[fields]]
name = "Len"
type = "u8"
[[fields]]
name = "Version"
type = "u16"
size_from = "Len"
"#,
        )
        .unwrap();
        assert!(matches!(
            validate(t),
            Err(ValidationError::SizeFromOnInteger { .. })
        ));
    }

    #[test]
    fn size_from_unknown_field_rejected() {
        let t: TemplateFile = toml::from_str(
            r#"
[template]
name = "Test"
[[fields]]
name = "Data"
type = "bytes"
size_from = "NoSuchField"
"#,
        )
        .unwrap();
        assert!(matches!(
            validate(t),
            Err(ValidationError::SizeFromNotFound { .. })
        ));
    }

    #[test]
    fn magic_hex_parses() {
        let bytes = parse_hex_bytes("AB CD EF").unwrap();
        assert_eq!(bytes, vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn magic_hex_compact_parses() {
        let bytes = parse_hex_bytes("ABCDEF").unwrap();
        assert_eq!(bytes, vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn invalid_magic_hex_rejected() {
        assert!(parse_hex_bytes("GG").is_err());
        assert!(parse_hex_bytes("ABC").is_err());
    }

    #[test]
    fn valid_template_with_fields_and_magic() {
        let t: TemplateFile = toml::from_str(
            r#"
[template]
name = "My Proto"
endian = "little"

[match]
magic = [{ offset = 0, bytes = "AB CD" }]
extensions = ["proto"]

[[fields]]
name = "Magic"
type = "bytes"
size = 2

[[fields]]
name = "Length"
type = "u32"

[[fields]]
name = "Payload"
type = "bytes"
size_from = "Length"
"#,
        )
        .unwrap();
        let v = validate(t).unwrap();
        assert_eq!(v.parsed_magic.len(), 1);
        assert_eq!(v.parsed_magic[0], (0, vec![0xAB, 0xCD]));
        assert_eq!(v.file.fields.len(), 3);
    }
}
