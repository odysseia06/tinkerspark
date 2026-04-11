use std::collections::HashMap;

use tinkerspark_core_analyze::{AnalysisNode, FieldView};
use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::{ByteRange, Diagnostic, NodeId, Severity};

use crate::template::{Endian, FieldDef, FieldType, ValidatedTemplate};

struct Cursor<'src> {
    src: &'src dyn ByteSource,
    pos: u64,
    file_len: u64,
}

impl<'src> Cursor<'src> {
    fn new(src: &'src dyn ByteSource) -> Self {
        Self {
            src,
            pos: 0,
            file_len: src.len(),
        }
    }

    fn remaining(&self) -> u64 {
        self.file_len.saturating_sub(self.pos)
    }

    fn read(&mut self, length: u64) -> Result<(Vec<u8>, ByteRange), ReadStop> {
        if length == 0 {
            let range = ByteRange::new(self.pos, 0);
            return Ok((Vec::new(), range));
        }
        if self.remaining() < length {
            return Err(ReadStop::DataShort {
                needed: length,
                available: self.remaining(),
            });
        }
        let range = ByteRange::new(self.pos, length);
        let data = self.src.read_range(range).map_err(ReadStop::Read)?;
        self.pos += length;
        Ok((data.into_owned(), range))
    }
}

enum ReadStop {
    DataShort { needed: u64, available: u64 },
    Read(tinkerspark_core_bytes::ReadError),
}

/// Parse a file according to a validated template, producing analysis nodes.
/// Always returns partial results — never panics on malformed input.
pub fn parse(
    template: &ValidatedTemplate,
    src: &dyn ByteSource,
) -> (Vec<AnalysisNode>, Vec<Diagnostic>) {
    let mut cursor = Cursor::new(src);
    let mut nodes = Vec::new();
    let mut diagnostics = Vec::new();
    let mut resolved: HashMap<&str, u64> = HashMap::new();
    let endian = template.file.template.endian;

    for field_def in &template.file.fields {
        let size = match compute_size(field_def, &resolved, cursor.remaining()) {
            Ok(size) => size,
            Err(message) => {
                diagnostics.push(Diagnostic {
                    severity: Severity::Error,
                    message,
                    range: None,
                });
                break;
            }
        };

        let (bytes, range) = match cursor.read(size) {
            Ok(pair) => pair,
            Err(ReadStop::DataShort { needed, available }) => {
                diagnostics.push(Diagnostic {
                    severity: Severity::Warning,
                    message: format!(
                        "Field \"{}\" needs {} bytes but only {} remain",
                        field_def.name, needed, available
                    ),
                    range: None,
                });
                break;
            }
            Err(ReadStop::Read(error)) => {
                diagnostics.push(Diagnostic {
                    severity: Severity::Error,
                    message: format!("Read error at field \"{}\": {}", field_def.name, error),
                    range: None,
                });
                break;
            }
        };

        let (value_str, int_value) = format_value(&bytes, field_def, endian);

        if let Some(val) = int_value {
            resolved.insert(&field_def.name, val);
        }

        let mut fields = vec![FieldView {
            name: "Value".into(),
            value: value_str.clone(),
            range: Some(range),
        }];

        // Look up known_values using the raw integer string (without hex annotation).
        let lookup_key = if let Some(val) = int_value {
            val.to_string()
        } else {
            value_str
        };
        if let Some(meaning) = field_def.known_values.get(&lookup_key) {
            fields.push(FieldView {
                name: "Meaning".into(),
                value: meaning.clone(),
                range: None,
            });
        }

        let kind = match field_def.r#type {
            FieldType::U8 => "u8",
            FieldType::U16 => "u16",
            FieldType::U32 => "u32",
            FieldType::U64 => "u64",
            FieldType::I8 => "i8",
            FieldType::I16 => "i16",
            FieldType::I32 => "i32",
            FieldType::I64 => "i64",
            FieldType::Bytes => "bytes",
            FieldType::Utf8 => "utf8",
        };

        let mut node_diagnostics = Vec::new();
        if field_def.r#type == FieldType::Utf8 && std::str::from_utf8(&bytes).is_err() {
            node_diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                message: "Contains invalid UTF-8 sequences (lossy replacement applied)".into(),
                range: Some(range),
            });
        }

        nodes.push(AnalysisNode {
            id: NodeId::new(),
            label: field_def.name.clone(),
            kind: kind.into(),
            range,
            children: Vec::new(),
            fields,
            diagnostics: node_diagnostics,
        });
    }

    (nodes, diagnostics)
}

fn compute_size(
    field: &FieldDef,
    resolved: &HashMap<&str, u64>,
    remaining: u64,
) -> Result<u64, String> {
    // Integer types have a fixed size.
    if let Some(fixed) = field.r#type.fixed_size() {
        return Ok(fixed);
    }

    // bytes/utf8: explicit size takes precedence.
    if let Some(size) = field.size {
        return Ok(size);
    }

    // Dynamic size from a previously parsed field.
    if let Some(ref source_name) = field.size_from {
        return resolved.get(source_name.as_str()).copied().ok_or_else(|| {
            format!(
                "Field \"{}\" references unresolved size_from \"{}\"",
                field.name, source_name
            )
        });
    }

    // No size specified — greedy, consume all remaining bytes.
    Ok(remaining)
}

fn format_value(bytes: &[u8], field: &FieldDef, endian: Endian) -> (String, Option<u64>) {
    match field.r#type {
        FieldType::U8 => {
            let val = bytes[0] as u64;
            (format!("{} (0x{:X})", val, val), Some(val))
        }
        FieldType::U16 => {
            let val = match endian {
                Endian::Big => u16::from_be_bytes([bytes[0], bytes[1]]) as u64,
                Endian::Little => u16::from_le_bytes([bytes[0], bytes[1]]) as u64,
            };
            (format!("{} (0x{:X})", val, val), Some(val))
        }
        FieldType::U32 => {
            let arr: [u8; 4] = bytes[..4].try_into().unwrap_or_default();
            let val = match endian {
                Endian::Big => u32::from_be_bytes(arr) as u64,
                Endian::Little => u32::from_le_bytes(arr) as u64,
            };
            (format!("{} (0x{:X})", val, val), Some(val))
        }
        FieldType::U64 => {
            let arr: [u8; 8] = bytes[..8].try_into().unwrap_or_default();
            let val = match endian {
                Endian::Big => u64::from_be_bytes(arr),
                Endian::Little => u64::from_le_bytes(arr),
            };
            (format!("{} (0x{:X})", val, val), Some(val))
        }
        FieldType::I8 => {
            let val = bytes[0] as i8;
            (format!("{} (0x{:02X})", val, bytes[0]), None)
        }
        FieldType::I16 => {
            let val = match endian {
                Endian::Big => i16::from_be_bytes([bytes[0], bytes[1]]),
                Endian::Little => i16::from_le_bytes([bytes[0], bytes[1]]),
            };
            let raw = match endian {
                Endian::Big => u16::from_be_bytes([bytes[0], bytes[1]]),
                Endian::Little => u16::from_le_bytes([bytes[0], bytes[1]]),
            };
            (format!("{} (0x{:X})", val, raw), None)
        }
        FieldType::I32 => {
            let arr: [u8; 4] = bytes[..4].try_into().unwrap_or_default();
            let val = match endian {
                Endian::Big => i32::from_be_bytes(arr),
                Endian::Little => i32::from_le_bytes(arr),
            };
            let raw = match endian {
                Endian::Big => u32::from_be_bytes(arr),
                Endian::Little => u32::from_le_bytes(arr),
            };
            (format!("{} (0x{:X})", val, raw), None)
        }
        FieldType::I64 => {
            let arr: [u8; 8] = bytes[..8].try_into().unwrap_or_default();
            let val = match endian {
                Endian::Big => i64::from_be_bytes(arr),
                Endian::Little => i64::from_le_bytes(arr),
            };
            let raw = match endian {
                Endian::Big => u64::from_be_bytes(arr),
                Endian::Little => u64::from_le_bytes(arr),
            };
            (format!("{} (0x{:X})", val, raw), None)
        }
        FieldType::Bytes => {
            let preview_len = bytes.len().min(16);
            let hex: String = bytes[..preview_len]
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            let suffix = if bytes.len() > 16 { " ..." } else { "" };
            (format!("<{} bytes> [{}{}]", bytes.len(), hex, suffix), None)
        }
        FieldType::Utf8 => {
            let text = String::from_utf8_lossy(bytes);
            let truncated = if text.len() > 64 {
                format!("{}...", &text[..64])
            } else {
                text.into_owned()
            };
            (truncated, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{validate, FieldDef, FieldType, TemplateFile};
    use tinkerspark_core_bytes::MemoryByteSource;

    fn make_template(fields: Vec<FieldDef>, endian: Endian) -> ValidatedTemplate {
        let file = TemplateFile {
            template: crate::template::TemplateMeta {
                name: "Test".into(),
                endian,
            },
            r#match: Default::default(),
            fields,
        };
        validate(file).expect("test template should validate")
    }

    fn field(name: &str, field_type: FieldType) -> FieldDef {
        FieldDef {
            name: name.into(),
            r#type: field_type,
            size: None,
            size_from: None,
            known_values: HashMap::new(),
        }
    }

    fn field_bytes(name: &str, size: u64) -> FieldDef {
        FieldDef {
            name: name.into(),
            r#type: FieldType::Bytes,
            size: Some(size),
            size_from: None,
            known_values: HashMap::new(),
        }
    }

    fn field_sized_from(name: &str, field_type: FieldType, source: &str) -> FieldDef {
        FieldDef {
            name: name.into(),
            r#type: field_type,
            size: None,
            size_from: Some(source.into()),
            known_values: HashMap::new(),
        }
    }

    #[test]
    fn parses_u8_field() {
        let template = make_template(vec![field("Tag", FieldType::U8)], Endian::Big);
        let src = MemoryByteSource::new(vec![0x42]);
        let (nodes, diags) = parse(&template, &src);
        assert!(diags.is_empty());
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].label, "Tag");
        assert_eq!(nodes[0].fields[0].value, "66 (0x42)");
        assert_eq!(nodes[0].range, ByteRange::new(0, 1));
    }

    #[test]
    fn parses_u32_big_endian() {
        let template = make_template(vec![field("Val", FieldType::U32)], Endian::Big);
        let src = MemoryByteSource::new(vec![0x00, 0x00, 0x01, 0x00]);
        let (nodes, _) = parse(&template, &src);
        assert_eq!(nodes[0].fields[0].value, "256 (0x100)");
    }

    #[test]
    fn parses_u32_little_endian() {
        let template = make_template(vec![field("Val", FieldType::U32)], Endian::Little);
        let src = MemoryByteSource::new(vec![0x00, 0x00, 0x01, 0x00]);
        let (nodes, _) = parse(&template, &src);
        assert_eq!(nodes[0].fields[0].value, "65536 (0x10000)");
    }

    #[test]
    fn parses_bytes_fixed_size() {
        let template = make_template(
            vec![field_bytes("Header", 3), field("Trail", FieldType::U8)],
            Endian::Big,
        );
        let src = MemoryByteSource::new(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        let (nodes, _) = parse(&template, &src);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].range, ByteRange::new(0, 3));
        assert_eq!(nodes[1].range, ByteRange::new(3, 1));
        assert_eq!(nodes[1].fields[0].value, "221 (0xDD)");
    }

    #[test]
    fn parses_bytes_greedy() {
        let template = make_template(
            vec![
                field("Tag", FieldType::U8),
                FieldDef {
                    name: "Rest".into(),
                    r#type: FieldType::Bytes,
                    size: None,
                    size_from: None,
                    known_values: HashMap::new(),
                },
            ],
            Endian::Big,
        );
        let src = MemoryByteSource::new(vec![0x01, 0x02, 0x03, 0x04, 0x05]);
        let (nodes, diags) = parse(&template, &src);
        assert!(diags.is_empty());
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[1].range, ByteRange::new(1, 4));
    }

    #[test]
    fn size_from_resolution() {
        let template = make_template(
            vec![
                field("Length", FieldType::U16),
                field_sized_from("Data", FieldType::Bytes, "Length"),
            ],
            Endian::Big,
        );
        let src = MemoryByteSource::new(vec![0x00, 0x03, 0xAA, 0xBB, 0xCC, 0xFF]);
        let (nodes, diags) = parse(&template, &src);
        assert!(diags.is_empty());
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].fields[0].value, "3 (0x3)");
        assert_eq!(nodes[1].range, ByteRange::new(2, 3));
    }

    #[test]
    fn known_values_matched() {
        let mut kv = HashMap::new();
        kv.insert("1".into(), "Request".into());
        kv.insert("2".into(), "Response".into());
        let template = make_template(
            vec![FieldDef {
                name: "Type".into(),
                r#type: FieldType::U8,
                size: None,
                size_from: None,
                known_values: kv,
            }],
            Endian::Big,
        );
        let src = MemoryByteSource::new(vec![0x01]);
        let (nodes, _) = parse(&template, &src);
        assert_eq!(nodes[0].fields.len(), 2);
        assert_eq!(nodes[0].fields[1].name, "Meaning");
        assert_eq!(nodes[0].fields[1].value, "Request");
    }

    #[test]
    fn data_too_short_produces_diagnostic() {
        let template = make_template(vec![field("Big", FieldType::U32)], Endian::Big);
        let src = MemoryByteSource::new(vec![0x01, 0x02]);
        let (nodes, diags) = parse(&template, &src);
        assert!(nodes.is_empty());
        assert_eq!(diags.len(), 1);
        assert!(diags[0].message.contains("needs 4 bytes"));
    }

    #[test]
    fn empty_source_produces_diagnostic() {
        let template = make_template(vec![field("Tag", FieldType::U8)], Endian::Big);
        let src = MemoryByteSource::new(vec![]);
        let (nodes, diags) = parse(&template, &src);
        assert!(nodes.is_empty());
        assert_eq!(diags.len(), 1);
    }

    #[test]
    fn utf8_valid() {
        let template = make_template(
            vec![FieldDef {
                name: "Text".into(),
                r#type: FieldType::Utf8,
                size: Some(5),
                size_from: None,
                known_values: HashMap::new(),
            }],
            Endian::Big,
        );
        let src = MemoryByteSource::new(b"Hello".to_vec());
        let (nodes, _) = parse(&template, &src);
        assert_eq!(nodes[0].fields[0].value, "Hello");
    }

    #[test]
    fn utf8_invalid_produces_diagnostic() {
        let template = make_template(
            vec![FieldDef {
                name: "Text".into(),
                r#type: FieldType::Utf8,
                size: Some(2),
                size_from: None,
                known_values: HashMap::new(),
            }],
            Endian::Big,
        );
        let src = MemoryByteSource::new(vec![0xFF, 0xFE]);
        let (nodes, _) = parse(&template, &src);
        assert_eq!(nodes.len(), 1);
        assert!(!nodes[0].diagnostics.is_empty());
        assert!(nodes[0].diagnostics[0].message.contains("invalid UTF-8"));
    }

    #[test]
    fn i16_signed_negative() {
        let template = make_template(vec![field("Temp", FieldType::I16)], Endian::Big);
        // -1 in big-endian i16
        let src = MemoryByteSource::new(vec![0xFF, 0xFF]);
        let (nodes, _) = parse(&template, &src);
        assert_eq!(nodes[0].fields[0].value, "-1 (0xFFFF)");
    }

    #[test]
    fn multiple_fields_sequential_offsets() {
        let template = make_template(
            vec![
                field("A", FieldType::U8),
                field("B", FieldType::U16),
                field("C", FieldType::U32),
            ],
            Endian::Big,
        );
        let src = MemoryByteSource::new(vec![0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03]);
        let (nodes, diags) = parse(&template, &src);
        assert!(diags.is_empty());
        assert_eq!(nodes[0].range, ByteRange::new(0, 1));
        assert_eq!(nodes[1].range, ByteRange::new(1, 2));
        assert_eq!(nodes[2].range, ByteRange::new(3, 4));
    }
}
