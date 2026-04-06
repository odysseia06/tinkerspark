//! X.509 certificate analyzer for Tinkerspark.
//!
//! Supports both DER-encoded and PEM-encoded certificates.
//! Parses certificate structure, extracts fields, and maps them
//! back to byte ranges in the source data.

mod pem_decode;
mod tree_builder;

use tinkerspark_core_analyze::{AnalysisReport, AnalyzeError, Analyzer, AnalyzerConfidence};
use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::{ByteRange, DetectedKind, Diagnostic, FileHandle, Severity};

pub struct X509Analyzer;

impl Analyzer for X509Analyzer {
    fn id(&self) -> &'static str {
        "x509"
    }

    fn can_analyze(&self, handle: &FileHandle, src: &dyn ByteSource) -> AnalyzerConfidence {
        match &handle.kind {
            DetectedKind::X509Pem | DetectedKind::X509Der => AnalyzerConfidence::High,
            // Generic PEM might be an X.509 cert we didn't specifically match.
            // Only claim actual certificate labels — not CRLs or CSRs.
            // Match the full closing dashes to avoid "BEGIN CERTIFICATE" matching
            // inside "BEGIN CERTIFICATE REQUEST".
            DetectedKind::Pem => {
                if let Ok(data) = src.read_range(ByteRange::new(0, src.len().min(256))) {
                    if data.windows(22).any(|w| w == b"BEGIN CERTIFICATE-----") {
                        return AnalyzerConfidence::High;
                    }
                }
                AnalyzerConfidence::None
            }
            // Binary files starting with 0x30 could be DER, but we only
            // claim them if the kind sniffer already identified them as X509Der.
            // Claiming generic Binary with 0x30 at Low ties with generic and
            // blocks the fallback analyzer for any ASN.1/BER/TLV blob.
            _ => AnalyzerConfidence::None,
        }
    }

    fn analyze(
        &self,
        _handle: &FileHandle,
        src: &dyn ByteSource,
    ) -> Result<AnalysisReport, AnalyzeError> {
        let file_len = src.len();
        let data = src.read_range(ByteRange::new(0, file_len))?;

        let mut report_diagnostics = Vec::new();

        // Determine if PEM and extract DER bytes.
        let (der_bytes, is_pem, pem_label) = match pem_decode::try_decode_pem(&data) {
            Some(decoded) => {
                report_diagnostics.push(Diagnostic {
                    severity: Severity::Info,
                    message: format!(
                        "File is PEM-encoded (label: \"{}\"). \
                         Byte ranges in the structure tree refer to the decoded DER content, \
                         not the original PEM text.",
                        decoded.label
                    ),
                    range: None,
                });
                (decoded.der_bytes, true, Some(decoded.label))
            }
            None => (data.to_vec(), false, None),
        };

        // Try to parse certificate(s).
        let mut root_nodes = Vec::new();
        let mut offset = 0;

        // Handle certificate chains: parse multiple certs from the same data.
        // For PEM, there might be multiple PEM blocks — we handle the first one here.
        // For DER, the file might contain concatenated certificates.
        loop {
            if offset >= der_bytes.len() {
                break;
            }

            let remaining = &der_bytes[offset..];
            if remaining.is_empty() || remaining[0] != 0x30 {
                break;
            }

            match x509_parser::parse_x509_certificate(remaining) {
                Ok((rest, cert)) => {
                    let cert_len = remaining.len() - rest.len();
                    let cert_range = ByteRange::new(offset as u64, cert_len as u64);

                    let cert_index = root_nodes.len();
                    let label = if pem_label.as_deref() == Some("CERTIFICATE REQUEST") {
                        format!("Certificate Request {}", cert_index)
                    } else {
                        format!("Certificate {}", cert_index)
                    };

                    let node =
                        tree_builder::build_cert_tree(&cert, remaining, cert_range, &label, is_pem);
                    root_nodes.push(node);

                    offset += cert_len;
                }
                Err(e) => {
                    report_diagnostics.push(Diagnostic {
                        severity: Severity::Error,
                        message: format!(
                            "Failed to parse certificate at offset 0x{:X}: {}",
                            offset, e
                        ),
                        range: Some(ByteRange::new(
                            offset as u64,
                            (der_bytes.len() - offset) as u64,
                        )),
                    });
                    break;
                }
            }
        }

        if root_nodes.is_empty() {
            return Err(AnalyzeError::Parse {
                message: "No valid X.509 certificates found in data".into(),
            });
        }

        if root_nodes.len() > 1 {
            report_diagnostics.push(Diagnostic {
                severity: Severity::Info,
                message: format!("Certificate chain: {} certificates found", root_nodes.len()),
                range: None,
            });
        }

        Ok(AnalysisReport {
            analyzer_id: "x509".into(),
            root_nodes,
            diagnostics: report_diagnostics,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tinkerspark_core_bytes::MemoryByteSource;
    use tinkerspark_core_types::FileId;

    fn make_handle(kind: DetectedKind, size: u64) -> FileHandle {
        FileHandle {
            id: FileId::new(),
            path: PathBuf::from("test.pem"),
            size,
            kind,
        }
    }

    #[test]
    fn confidence_high_for_x509_pem() {
        let analyzer = X509Analyzer;
        let src = MemoryByteSource::new(vec![0]);
        let handle = make_handle(DetectedKind::X509Pem, 1);
        assert_eq!(
            analyzer.can_analyze(&handle, &src),
            AnalyzerConfidence::High
        );
    }

    #[test]
    fn confidence_high_for_x509_der() {
        let analyzer = X509Analyzer;
        let src = MemoryByteSource::new(vec![0]);
        let handle = make_handle(DetectedKind::X509Der, 1);
        assert_eq!(
            analyzer.can_analyze(&handle, &src),
            AnalyzerConfidence::High
        );
    }

    #[test]
    fn confidence_none_for_openpgp() {
        let analyzer = X509Analyzer;
        let src = MemoryByteSource::new(vec![0]);
        let handle = make_handle(DetectedKind::OpenPgpBinary, 1);
        assert_eq!(
            analyzer.can_analyze(&handle, &src),
            AnalyzerConfidence::None
        );
    }
}
