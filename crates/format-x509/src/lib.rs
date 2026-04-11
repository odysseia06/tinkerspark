//! X.509 certificate analyzer for Tinkerspark.
//!
//! Supports both DER-encoded and PEM-encoded certificates.
//! Parses certificate structure, extracts fields, and maps them
//! back to byte ranges in the source data.

mod der_spans;
mod pem_decode;
mod tree_builder;

use tinkerspark_core_analyze::{AnalysisReport, AnalyzeError, Analyzer, AnalyzerConfidence};
use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_types::{ByteRange, DetectedKind, Diagnostic, FileHandle, Severity};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;

pub struct X509Analyzer;

/// PEM labels we recognize as X.509 artifacts. The trailing closing dashes
/// matter so a `BEGIN CERTIFICATE` prefix doesn't false-match the inside of
/// `BEGIN CERTIFICATE REQUEST`.
const X509_PEM_LABELS: &[&[u8]] = &[
    b"BEGIN CERTIFICATE-----",
    b"BEGIN TRUSTED CERTIFICATE-----",
    b"BEGIN CERTIFICATE REQUEST-----",
    b"BEGIN NEW CERTIFICATE REQUEST-----",
    b"BEGIN X509 CRL-----",
];

/// What kind of X.509 artifact a PEM label represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X509Kind {
    Certificate,
    CertificationRequest,
    CertificateRevocationList,
}

impl X509Kind {
    fn from_pem_label(label: &str) -> Option<Self> {
        match label {
            "CERTIFICATE" | "TRUSTED CERTIFICATE" => Some(Self::Certificate),
            "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => Some(Self::CertificationRequest),
            "X509 CRL" => Some(Self::CertificateRevocationList),
            _ => None,
        }
    }
}

impl Analyzer for X509Analyzer {
    fn id(&self) -> &str {
        "x509"
    }

    fn can_analyze(&self, handle: &FileHandle, src: &dyn ByteSource) -> AnalyzerConfidence {
        match &handle.kind {
            DetectedKind::X509Pem | DetectedKind::X509Der => AnalyzerConfidence::High,
            // Generic PEM might be a certificate, CSR, or CRL that the sniffer
            // didn't tag as X509Pem. Match the full closing dashes so a
            // `BEGIN CERTIFICATE` prefix doesn't false-match the inside of
            // `BEGIN CERTIFICATE REQUEST`.
            DetectedKind::Pem => {
                if let Ok(data) = src.read_range(ByteRange::new(0, src.len().min(256))) {
                    for label in X509_PEM_LABELS {
                        if data.windows(label.len()).any(|w| w == *label) {
                            return AnalyzerConfidence::High;
                        }
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

        // Decide the artifact type. PEM labels are authoritative when
        // present; for raw DER we fall back to attempting each parser in
        // order until one succeeds (cert is the common case).
        let kind = match pem_label.as_deref().and_then(X509Kind::from_pem_label) {
            Some(k) => k,
            None => sniff_der_kind(&der_bytes),
        };

        let mut root_nodes = Vec::new();

        match kind {
            X509Kind::Certificate => {
                parse_certificate_chain(
                    &der_bytes,
                    is_pem,
                    &mut root_nodes,
                    &mut report_diagnostics,
                );
            }
            X509Kind::CertificationRequest => {
                parse_csr(&der_bytes, is_pem, &mut root_nodes, &mut report_diagnostics);
            }
            X509Kind::CertificateRevocationList => {
                parse_crl(&der_bytes, is_pem, &mut root_nodes, &mut report_diagnostics);
            }
        }

        if root_nodes.is_empty() {
            // Fold any accumulated Error diagnostics into the parse error so
            // detailed reasons (e.g. trailing-byte offsets from
            // parse_csr / parse_crl) reach the caller instead of being
            // silently dropped along with `report_diagnostics`.
            let detail = report_diagnostics
                .iter()
                .filter(|d| d.severity == Severity::Error)
                .map(|d| d.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            let message = if detail.is_empty() {
                "No valid X.509 certificate, CSR, or CRL found in data".into()
            } else {
                detail
            };
            return Err(AnalyzeError::Parse { message });
        }

        Ok(AnalysisReport {
            analyzer_id: "x509".into(),
            root_nodes,
            diagnostics: report_diagnostics,
        })
    }
}

/// Best-effort kind detection for raw DER input. The sniffer's job is only
/// to pick which parser dispatches; the strict full-input-consumption check
/// for CSR/CRL lives in [`parse_csr`] and [`parse_crl`] so that a
/// valid-CSR-prefix + trailing junk file routes to the CSR parser and
/// surfaces a precise trailing-bytes error instead of falling through to
/// the certificate path and producing a misleading "failed to parse
/// certificate" message.
fn sniff_der_kind(der: &[u8]) -> X509Kind {
    if x509_parser::parse_x509_certificate(der).is_ok() {
        X509Kind::Certificate
    } else if X509CertificationRequest::from_der(der).is_ok() {
        X509Kind::CertificationRequest
    } else if CertificateRevocationList::from_der(der).is_ok() {
        X509Kind::CertificateRevocationList
    } else {
        // Default to certificate so the existing error path runs and the
        // user sees a parse error rather than a silent skip.
        X509Kind::Certificate
    }
}

fn parse_certificate_chain(
    der_bytes: &[u8],
    is_pem: bool,
    root_nodes: &mut Vec<tinkerspark_core_analyze::AnalysisNode>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut offset = 0;
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
                let label = format!("Certificate {}", root_nodes.len());
                let node =
                    tree_builder::build_cert_tree(&cert, remaining, cert_range, &label, is_pem);
                root_nodes.push(node);
                offset += cert_len;
            }
            Err(e) => {
                diagnostics.push(Diagnostic {
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
    if root_nodes.len() > 1 {
        diagnostics.push(Diagnostic {
            severity: Severity::Info,
            message: format!("Certificate chain: {} certificates found", root_nodes.len()),
            range: None,
        });
    }
}

fn parse_csr(
    der_bytes: &[u8],
    is_pem: bool,
    root_nodes: &mut Vec<tinkerspark_core_analyze::AnalysisNode>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match X509CertificationRequest::from_der(der_bytes) {
        Ok((rest, csr)) => {
            if !rest.is_empty() {
                let consumed = der_bytes.len() - rest.len();
                diagnostics.push(Diagnostic {
                    severity: Severity::Error,
                    message: format!(
                        "Certification request parser left {} trailing byte(s) at offset 0x{:X}; \
                         file is not a clean CSR.",
                        rest.len(),
                        consumed
                    ),
                    range: Some(ByteRange::new(consumed as u64, rest.len() as u64)),
                });
                return;
            }
            let range = ByteRange::new(0, der_bytes.len() as u64);
            let node = tree_builder::build_csr_tree(
                &csr,
                der_bytes,
                range,
                "Certificate Signing Request",
                is_pem,
            );
            root_nodes.push(node);
        }
        Err(e) => {
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                message: format!("Failed to parse certification request: {}", e),
                range: Some(ByteRange::new(0, der_bytes.len() as u64)),
            });
        }
    }
}

fn parse_crl(
    der_bytes: &[u8],
    is_pem: bool,
    root_nodes: &mut Vec<tinkerspark_core_analyze::AnalysisNode>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match CertificateRevocationList::from_der(der_bytes) {
        Ok((rest, crl)) => {
            if !rest.is_empty() {
                let consumed = der_bytes.len() - rest.len();
                diagnostics.push(Diagnostic {
                    severity: Severity::Error,
                    message: format!(
                        "Certificate revocation list parser left {} trailing byte(s) at offset 0x{:X}; \
                         file is not a clean CRL.",
                        rest.len(),
                        consumed
                    ),
                    range: Some(ByteRange::new(consumed as u64, rest.len() as u64)),
                });
                return;
            }
            let range = ByteRange::new(0, der_bytes.len() as u64);
            let node = tree_builder::build_crl_tree(
                &crl,
                der_bytes,
                range,
                "Certificate Revocation List",
                is_pem,
            );
            root_nodes.push(node);
        }
        Err(e) => {
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                message: format!("Failed to parse certificate revocation list: {}", e),
                range: Some(ByteRange::new(0, der_bytes.len() as u64)),
            });
        }
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
