use crate::der_spans;
use tinkerspark_core_analyze::{AnalysisNode, FieldView};
use tinkerspark_core_types::{ByteRange, Diagnostic, NodeId, Severity};
use x509_parser::certificate::X509Certificate;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::prelude::*;
use x509_parser::revocation_list::CertificateRevocationList;

/// Build an analysis tree for a single X.509 certificate.
///
/// `cert_der` is the raw DER bytes for this certificate.
/// `cert_range` is the byte range within the file (or decoded PEM content).
pub fn build_cert_tree(
    cert: &X509Certificate<'_>,
    cert_der: &[u8],
    cert_range: ByteRange,
    label: &str,
    is_pem: bool,
) -> AnalysisNode {
    let tbs = &cert.tbs_certificate;
    let base = cert_range.offset();

    // Extract precise DER spans via TLV walking.
    let cert_spans = der_spans::extract_cert_spans(cert_der, base);
    let tbs_spans = cert_spans
        .as_ref()
        .map(|cs| der_spans::extract_tbs_spans(cert_der, cs.tbs, base));

    let mut children = Vec::new();
    let mut cert_fields = Vec::new();
    let mut cert_diagnostics = Vec::new();

    // ── Version ──
    cert_fields.push(FieldView {
        name: "Version".into(),
        value: format!("v{}", tbs.version.0 + 1),
        range: tbs_spans.as_ref().and_then(|s| s.version),
    });

    // ── Serial Number ──
    let serial_hex = tbs
        .raw_serial()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");
    cert_fields.push(FieldView {
        name: "Serial Number".into(),
        value: serial_hex,
        range: tbs_spans.as_ref().and_then(|s| s.serial),
    });

    // ── Signature Algorithm (TBS inner) ──
    cert_fields.push(FieldView {
        name: "Signature Algorithm".into(),
        value: oid_name(&tbs.signature.algorithm.to_id_string()),
        range: tbs_spans.as_ref().and_then(|s| s.signature),
    });

    // ── Issuer ──
    let issuer_str = format_x509_name(&tbs.issuer);
    let issuer_range = tbs_spans
        .as_ref()
        .and_then(|s| s.issuer)
        .unwrap_or(cert_range);
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: "Issuer".into(),
        kind: "x509_issuer".into(),
        range: issuer_range,
        children: Vec::new(),
        fields: name_fields(&tbs.issuer),
        diagnostics: Vec::new(),
    });
    cert_fields.push(FieldView {
        name: "Issuer".into(),
        value: issuer_str,
        range: tbs_spans.as_ref().and_then(|s| s.issuer),
    });

    // ── Validity ──
    let not_before = format!("{}", tbs.validity.not_before);
    let not_after = format!("{}", tbs.validity.not_after);
    let validity_range = tbs_spans
        .as_ref()
        .and_then(|s| s.validity)
        .unwrap_or(cert_range);
    let validity_sub = tbs_spans
        .as_ref()
        .and_then(|s| s.validity)
        .map(|vr| der_spans::extract_validity_spans(cert_der, vr, base));
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: "Validity Period".into(),
        kind: "x509_validity".into(),
        range: validity_range,
        children: Vec::new(),
        fields: vec![
            FieldView {
                name: "Not Before".into(),
                value: not_before,
                range: validity_sub.as_ref().and_then(|v| v.not_before),
            },
            FieldView {
                name: "Not After".into(),
                value: not_after,
                range: validity_sub.as_ref().and_then(|v| v.not_after),
            },
        ],
        diagnostics: Vec::new(),
    });

    // ── Subject ──
    let subject_str = format_x509_name(&tbs.subject);
    let subject_range = tbs_spans
        .as_ref()
        .and_then(|s| s.subject)
        .unwrap_or(cert_range);
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: "Subject".into(),
        kind: "x509_subject".into(),
        range: subject_range,
        children: Vec::new(),
        fields: name_fields(&tbs.subject),
        diagnostics: Vec::new(),
    });
    cert_fields.push(FieldView {
        name: "Subject".into(),
        value: subject_str,
        range: tbs_spans.as_ref().and_then(|s| s.subject),
    });

    // ── Subject Public Key Info ──
    let spki = &tbs.subject_pki;
    let pk_algo = oid_name(&spki.algorithm.algorithm.to_id_string());
    let pk_bits = spki.subject_public_key.data.len() * 8;
    let spki_range = tbs_spans
        .as_ref()
        .and_then(|s| s.subject_pki)
        .unwrap_or(cert_range);
    let spki_sub = tbs_spans
        .as_ref()
        .and_then(|s| s.subject_pki)
        .and_then(|sr| der_spans::extract_spki_spans(cert_der, sr, base));
    let mut spki_children = Vec::new();
    if let Some(ref ss) = spki_sub {
        spki_children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("Algorithm: {}", pk_algo),
            kind: "x509_spki_algorithm".into(),
            range: ss.algorithm,
            children: Vec::new(),
            fields: vec![FieldView {
                name: "Algorithm".into(),
                value: pk_algo.clone(),
                range: Some(ss.algorithm),
            }],
            diagnostics: Vec::new(),
        });
        spki_children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("Public Key Bits ({} bits)", pk_bits),
            kind: "x509_spki_key_bits".into(),
            range: ss.subject_public_key,
            children: Vec::new(),
            fields: vec![FieldView {
                name: "Size".into(),
                value: format!("{} bits", pk_bits),
                range: Some(ss.subject_public_key),
            }],
            diagnostics: Vec::new(),
        });
    }
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: "Subject Public Key".into(),
        kind: "x509_public_key".into(),
        range: spki_range,
        children: spki_children,
        fields: vec![
            FieldView {
                name: "Algorithm".into(),
                value: pk_algo.clone(),
                range: spki_sub.as_ref().map(|s| s.algorithm),
            },
            FieldView {
                name: "Key Size".into(),
                value: format!("{} bits", pk_bits),
                range: spki_sub.as_ref().map(|s| s.subject_public_key),
            },
        ],
        diagnostics: Vec::new(),
    });
    cert_fields.push(FieldView {
        name: "Public Key Algorithm".into(),
        value: pk_algo,
        range: tbs_spans.as_ref().and_then(|s| s.subject_pki),
    });

    // ── Extensions ──
    let extensions = tbs.extensions();
    if !extensions.is_empty() {
        // Get precise DER wrapper spans for each extension SEQUENCE.
        let ext_wrapper_spans = tbs_spans
            .as_ref()
            .and_then(|s| s.extensions)
            .map(|er| der_spans::extract_extension_spans(cert_der, er, base))
            .unwrap_or_default();

        let mut ext_children = Vec::new();
        for (idx, ext) in extensions.iter().enumerate() {
            let oid_str = oid_name(&ext.oid.to_id_string());
            let critical_str = if ext.critical { " (critical)" } else { "" };

            // Use the wrapper span if available, otherwise fall back to value bytes.
            let ext_range = ext_wrapper_spans
                .get(idx)
                .map(|es| es.wrapper)
                .or_else(|| compute_field_range(cert_der, ext.value, base))
                .unwrap_or(cert_range);

            let mut ext_fields = vec![
                FieldView {
                    name: "OID".into(),
                    value: ext.oid.to_id_string(),
                    range: None,
                },
                FieldView {
                    name: "Critical".into(),
                    value: ext.critical.to_string(),
                    range: None,
                },
                FieldView {
                    name: "Value Size".into(),
                    value: format!("{} bytes", ext.value.len()),
                    range: compute_field_range(cert_der, ext.value, base),
                },
            ];

            if let Some(parsed) = format_parsed_extension(ext) {
                ext_fields.push(FieldView {
                    name: "Parsed".into(),
                    value: parsed,
                    range: None,
                });
            }

            ext_children.push(AnalysisNode {
                id: NodeId::new(),
                label: format!("{}{}", oid_str, critical_str),
                kind: "x509_extension".into(),
                range: ext_range,
                children: Vec::new(),
                fields: ext_fields,
                diagnostics: Vec::new(),
            });
        }
        let extensions_range = tbs_spans
            .as_ref()
            .and_then(|s| s.extensions)
            .unwrap_or(cert_range);
        children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("Extensions ({})", extensions.len()),
            kind: "x509_extensions".into(),
            range: extensions_range,
            children: ext_children,
            fields: Vec::new(),
            diagnostics: Vec::new(),
        });
    }

    // ── Signature ──
    let sig_algo = oid_name(&cert.signature_algorithm.algorithm.to_id_string());
    let sig_algo_range = cert_spans.as_ref().map(|s| s.signature_algorithm);
    let sig_value_range = cert_spans.as_ref().map(|s| s.signature_value);
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: "Signature".into(),
        kind: "x509_signature".into(),
        range: sig_value_range.unwrap_or(cert_range),
        children: Vec::new(),
        fields: vec![
            FieldView {
                name: "Algorithm".into(),
                value: sig_algo,
                range: sig_algo_range,
            },
            FieldView {
                name: "Size".into(),
                value: format!("{} bytes", cert.signature_value.data.len()),
                range: sig_value_range,
            },
        ],
        diagnostics: Vec::new(),
    });

    if is_pem {
        cert_diagnostics.push(Diagnostic {
            severity: Severity::Info,
            message: "Byte ranges refer to decoded DER content, not PEM text".into(),
            range: None,
        });
    }

    AnalysisNode {
        id: NodeId::new(),
        label: label.into(),
        kind: "x509_certificate".into(),
        range: cert_spans
            .as_ref()
            .map(|s| s.certificate)
            .unwrap_or(cert_range),
        children,
        fields: cert_fields,
        diagnostics: cert_diagnostics,
    }
}

/// Compute a ByteRange for a field slice relative to the cert DER.
fn compute_field_range(cert_der: &[u8], field: &[u8], base_offset: u64) -> Option<ByteRange> {
    if field.is_empty() {
        return None;
    }
    let cert_start = cert_der.as_ptr() as usize;
    let field_start = field.as_ptr() as usize;
    if field_start < cert_start {
        return None;
    }
    let offset = field_start - cert_start;
    if offset + field.len() > cert_der.len() {
        return None;
    }
    ByteRange::try_new(base_offset + offset as u64, field.len() as u64)
}

/// Format an X.509 name as a single-line string.
fn format_x509_name(name: &X509Name<'_>) -> String {
    let parts: Vec<String> = name
        .iter()
        .flat_map(|rdn| rdn.iter())
        .map(|attr| {
            let oid_short = oid_name(&attr.attr_type().to_id_string());
            let val = attr.as_str().unwrap_or("[non-UTF8]");
            format!("{}={}", oid_short, val)
        })
        .collect();
    parts.join(", ")
}

/// Extract individual name fields for display.
fn name_fields(name: &X509Name<'_>) -> Vec<FieldView> {
    name.iter()
        .flat_map(|rdn| rdn.iter())
        .map(|attr| {
            let oid_short = oid_name(&attr.attr_type().to_id_string());
            let val = attr.as_str().unwrap_or("[non-UTF8]").to_string();
            FieldView {
                name: oid_short,
                value: val,
                range: None,
            }
        })
        .collect()
}

/// Map common OID strings to short human-readable names.
fn oid_name(oid_str: &str) -> String {
    match oid_str {
        "2.5.4.3" => "CN".into(),
        "2.5.4.6" => "C".into(),
        "2.5.4.7" => "L".into(),
        "2.5.4.8" => "ST".into(),
        "2.5.4.10" => "O".into(),
        "2.5.4.11" => "OU".into(),
        "2.5.4.5" => "serialNumber".into(),
        "1.2.840.113549.1.1.1" => "RSA".into(),
        "1.2.840.113549.1.1.5" => "SHA-1 with RSA".into(),
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA".into(),
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA".into(),
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA".into(),
        "1.2.840.10045.2.1" => "EC".into(),
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256".into(),
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384".into(),
        "1.3.101.112" => "Ed25519".into(),
        "1.3.101.113" => "Ed448".into(),
        "2.5.29.14" => "SubjectKeyIdentifier".into(),
        "2.5.29.15" => "KeyUsage".into(),
        "2.5.29.17" => "SubjectAlternativeName".into(),
        "2.5.29.19" => "BasicConstraints".into(),
        "2.5.29.35" => "AuthorityKeyIdentifier".into(),
        "2.5.29.37" => "ExtendedKeyUsage".into(),
        _ => oid_str.to_string(),
    }
}

/// Build an analysis tree for an X.509 certification request (CSR).
///
/// CSRs share the outer 3-element SEQUENCE shape of certificates
/// (`SEQUENCE { CertificationRequestInfo, signatureAlgorithm, signature }`),
/// so [`der_spans::extract_cert_spans`] is reused for the envelope and
/// `CertSpans::tbs` carries the CertificationRequestInfo span.
pub fn build_csr_tree(
    csr: &X509CertificationRequest<'_>,
    csr_der: &[u8],
    csr_range: ByteRange,
    label: &str,
    is_pem: bool,
) -> AnalysisNode {
    let info = &csr.certification_request_info;
    let base = csr_range.offset();

    let outer_spans = der_spans::extract_cert_spans(csr_der, base);
    let info_spans = outer_spans
        .as_ref()
        .map(|cs| der_spans::extract_csr_info_spans(csr_der, cs.tbs, base));

    let mut children = Vec::new();
    let mut top_fields = Vec::new();
    let mut top_diagnostics = Vec::new();

    // ── Version ──
    top_fields.push(FieldView {
        name: "Version".into(),
        value: format!("v{}", info.version.0 + 1),
        range: info_spans.as_ref().and_then(|s| s.version),
    });

    // ── Subject ──
    let subject_str = format_x509_name(&info.subject);
    let subject_range = info_spans
        .as_ref()
        .and_then(|s| s.subject)
        .unwrap_or(csr_range);
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: "Subject".into(),
        kind: "x509_csr_subject".into(),
        range: subject_range,
        children: Vec::new(),
        fields: name_fields(&info.subject),
        diagnostics: Vec::new(),
    });
    top_fields.push(FieldView {
        name: "Subject".into(),
        value: subject_str,
        range: info_spans.as_ref().and_then(|s| s.subject),
    });

    // ── Subject Public Key Info ──
    let spki = &info.subject_pki;
    let pk_algo = oid_name(&spki.algorithm.algorithm.to_id_string());
    let pk_bits = spki.subject_public_key.data.len() * 8;
    let spki_range = info_spans
        .as_ref()
        .and_then(|s| s.subject_pki)
        .unwrap_or(csr_range);
    let spki_sub = info_spans
        .as_ref()
        .and_then(|s| s.subject_pki)
        .and_then(|sr| der_spans::extract_spki_spans(csr_der, sr, base));
    let mut spki_children = Vec::new();
    if let Some(ref ss) = spki_sub {
        spki_children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("Algorithm: {}", pk_algo),
            kind: "x509_spki_algorithm".into(),
            range: ss.algorithm,
            children: Vec::new(),
            fields: vec![FieldView {
                name: "Algorithm".into(),
                value: pk_algo.clone(),
                range: Some(ss.algorithm),
            }],
            diagnostics: Vec::new(),
        });
        spki_children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("Public Key Bits ({} bits)", pk_bits),
            kind: "x509_spki_key_bits".into(),
            range: ss.subject_public_key,
            children: Vec::new(),
            fields: vec![FieldView {
                name: "Size".into(),
                value: format!("{} bits", pk_bits),
                range: Some(ss.subject_public_key),
            }],
            diagnostics: Vec::new(),
        });
    }
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: "Subject Public Key".into(),
        kind: "x509_csr_public_key".into(),
        range: spki_range,
        children: spki_children,
        fields: vec![
            FieldView {
                name: "Algorithm".into(),
                value: pk_algo.clone(),
                range: spki_sub.as_ref().map(|s| s.algorithm),
            },
            FieldView {
                name: "Key Size".into(),
                value: format!("{} bits", pk_bits),
                range: spki_sub.as_ref().map(|s| s.subject_public_key),
            },
        ],
        diagnostics: Vec::new(),
    });
    top_fields.push(FieldView {
        name: "Public Key Algorithm".into(),
        value: pk_algo,
        range: info_spans.as_ref().and_then(|s| s.subject_pki),
    });

    // ── Attributes (CSR equivalent of cert extensions) ──
    let attrs = info.attributes();
    if !attrs.is_empty() {
        let attrs_range = info_spans
            .as_ref()
            .and_then(|s| s.attributes)
            .unwrap_or(csr_range);
        // Per-attribute SEQUENCE wrapper spans, so each attribute child
        // points at its own DER bytes instead of the shared [0] wrapper.
        let attr_wrapper_spans = info_spans
            .as_ref()
            .and_then(|s| s.attributes)
            .map(|ar| der_spans::extract_csr_attribute_spans(csr_der, ar, base))
            .unwrap_or_default();

        let attr_children: Vec<AnalysisNode> = attrs
            .iter()
            .enumerate()
            .map(|(idx, attr)| {
                let oid = attr.oid.to_id_string();
                let range = attr_wrapper_spans.get(idx).copied().unwrap_or(attrs_range);
                AnalysisNode {
                    id: NodeId::new(),
                    label: oid_name(&oid),
                    kind: "x509_csr_attribute".into(),
                    range,
                    children: Vec::new(),
                    fields: vec![FieldView {
                        name: "OID".into(),
                        value: oid,
                        range: Some(range),
                    }],
                    diagnostics: Vec::new(),
                }
            })
            .collect();
        children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("Attributes ({})", attrs.len()),
            kind: "x509_csr_attributes".into(),
            range: attrs_range,
            children: attr_children,
            fields: Vec::new(),
            diagnostics: Vec::new(),
        });
    }

    // ── Signature ──
    let sig_algo = oid_name(&csr.signature_algorithm.algorithm.to_id_string());
    let sig_algo_range = outer_spans.as_ref().map(|s| s.signature_algorithm);
    let sig_value_range = outer_spans.as_ref().map(|s| s.signature_value);
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: "Signature".into(),
        kind: "x509_csr_signature".into(),
        range: sig_value_range.unwrap_or(csr_range),
        children: Vec::new(),
        fields: vec![
            FieldView {
                name: "Algorithm".into(),
                value: sig_algo,
                range: sig_algo_range,
            },
            FieldView {
                name: "Size".into(),
                value: format!("{} bytes", csr.signature_value.data.len()),
                range: sig_value_range,
            },
        ],
        diagnostics: Vec::new(),
    });

    if is_pem {
        top_diagnostics.push(Diagnostic {
            severity: Severity::Info,
            message: "Byte ranges refer to decoded DER content, not PEM text".into(),
            range: None,
        });
    }

    AnalysisNode {
        id: NodeId::new(),
        label: label.into(),
        kind: "x509_csr".into(),
        range: outer_spans
            .as_ref()
            .map(|s| s.certificate)
            .unwrap_or(csr_range),
        children,
        fields: top_fields,
        diagnostics: top_diagnostics,
    }
}

/// Build an analysis tree for an X.509 certificate revocation list (CRL).
pub fn build_crl_tree(
    crl: &CertificateRevocationList<'_>,
    crl_der: &[u8],
    crl_range: ByteRange,
    label: &str,
    is_pem: bool,
) -> AnalysisNode {
    let tbs = &crl.tbs_cert_list;
    let base = crl_range.offset();

    let outer_spans = der_spans::extract_cert_spans(crl_der, base);
    let tbs_spans = outer_spans
        .as_ref()
        .map(|cs| der_spans::extract_tbs_cert_list_spans(crl_der, cs.tbs, base));

    let mut children = Vec::new();
    let mut top_fields = Vec::new();
    let mut top_diagnostics = Vec::new();

    // ── Version ──
    if let Some(version) = tbs.version {
        top_fields.push(FieldView {
            name: "Version".into(),
            value: format!("v{}", version.0 + 1),
            range: tbs_spans.as_ref().and_then(|s| s.version),
        });
    }

    // ── Signature Algorithm (TBS inner) ──
    top_fields.push(FieldView {
        name: "Signature Algorithm".into(),
        value: oid_name(&tbs.signature.algorithm.to_id_string()),
        range: tbs_spans.as_ref().and_then(|s| s.signature),
    });

    // ── Issuer ──
    let issuer_str = format_x509_name(&tbs.issuer);
    let issuer_range = tbs_spans
        .as_ref()
        .and_then(|s| s.issuer)
        .unwrap_or(crl_range);
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: "Issuer".into(),
        kind: "x509_crl_issuer".into(),
        range: issuer_range,
        children: Vec::new(),
        fields: name_fields(&tbs.issuer),
        diagnostics: Vec::new(),
    });
    top_fields.push(FieldView {
        name: "Issuer".into(),
        value: issuer_str,
        range: tbs_spans.as_ref().and_then(|s| s.issuer),
    });

    // ── Update Times ──
    let this_update = format!("{}", tbs.this_update);
    top_fields.push(FieldView {
        name: "This Update".into(),
        value: this_update,
        range: tbs_spans.as_ref().and_then(|s| s.this_update),
    });
    if let Some(next) = tbs.next_update {
        top_fields.push(FieldView {
            name: "Next Update".into(),
            value: format!("{}", next),
            range: tbs_spans.as_ref().and_then(|s| s.next_update),
        });
    }

    // ── Revoked Certificates ──
    let revoked: Vec<_> = crl.iter_revoked_certificates().collect();
    if !revoked.is_empty() {
        let revoked_range = tbs_spans
            .as_ref()
            .and_then(|s| s.revoked_certificates)
            .unwrap_or(crl_range);
        let entry_spans = tbs_spans
            .as_ref()
            .and_then(|s| s.revoked_certificates)
            .map(|rr| der_spans::extract_revoked_entry_spans(crl_der, rr, base))
            .unwrap_or_default();

        let entry_children: Vec<AnalysisNode> = revoked
            .iter()
            .enumerate()
            .map(|(idx, entry)| {
                let serial_hex = entry
                    .raw_serial()
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(":");
                let entry_span = entry_spans.get(idx);
                let wrapper_range = entry_span.map(|e| e.wrapper).unwrap_or(revoked_range);
                AnalysisNode {
                    id: NodeId::new(),
                    label: format!("Revoked: {}", serial_hex),
                    kind: "x509_crl_revoked".into(),
                    range: wrapper_range,
                    children: Vec::new(),
                    fields: vec![
                        FieldView {
                            name: "Serial".into(),
                            value: serial_hex,
                            range: entry_span.and_then(|e| e.serial),
                        },
                        FieldView {
                            name: "Revocation Date".into(),
                            value: format!("{}", entry.revocation_date),
                            range: entry_span.and_then(|e| e.revocation_date),
                        },
                    ],
                    diagnostics: Vec::new(),
                }
            })
            .collect();

        children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("Revoked Certificates ({})", revoked.len()),
            kind: "x509_crl_revoked_list".into(),
            range: revoked_range,
            children: entry_children,
            fields: vec![FieldView {
                name: "Count".into(),
                value: revoked.len().to_string(),
                range: None,
            }],
            diagnostics: Vec::new(),
        });
    }

    // ── CRL Extensions ──
    let extensions = tbs.extensions();
    if !extensions.is_empty() {
        let ext_wrapper_spans = tbs_spans
            .as_ref()
            .and_then(|s| s.extensions)
            .map(|er| der_spans::extract_extension_spans(crl_der, er, base))
            .unwrap_or_default();

        let mut ext_children = Vec::new();
        for (idx, ext) in extensions.iter().enumerate() {
            let oid_str = oid_name(&ext.oid.to_id_string());
            let critical_str = if ext.critical { " (critical)" } else { "" };
            let ext_range = ext_wrapper_spans
                .get(idx)
                .map(|es| es.wrapper)
                .or_else(|| compute_field_range(crl_der, ext.value, base))
                .unwrap_or(crl_range);
            ext_children.push(AnalysisNode {
                id: NodeId::new(),
                label: format!("{}{}", oid_str, critical_str),
                kind: "x509_crl_extension".into(),
                range: ext_range,
                children: Vec::new(),
                fields: vec![
                    FieldView {
                        name: "OID".into(),
                        value: ext.oid.to_id_string(),
                        range: None,
                    },
                    FieldView {
                        name: "Critical".into(),
                        value: ext.critical.to_string(),
                        range: None,
                    },
                ],
                diagnostics: Vec::new(),
            });
        }
        let extensions_range = tbs_spans
            .as_ref()
            .and_then(|s| s.extensions)
            .unwrap_or(crl_range);
        children.push(AnalysisNode {
            id: NodeId::new(),
            label: format!("CRL Extensions ({})", extensions.len()),
            kind: "x509_crl_extensions".into(),
            range: extensions_range,
            children: ext_children,
            fields: Vec::new(),
            diagnostics: Vec::new(),
        });
    }

    // ── Outer Signature ──
    let sig_algo = oid_name(&crl.signature_algorithm.algorithm.to_id_string());
    let sig_algo_range = outer_spans.as_ref().map(|s| s.signature_algorithm);
    let sig_value_range = outer_spans.as_ref().map(|s| s.signature_value);
    children.push(AnalysisNode {
        id: NodeId::new(),
        label: "Signature".into(),
        kind: "x509_crl_signature".into(),
        range: sig_value_range.unwrap_or(crl_range),
        children: Vec::new(),
        fields: vec![
            FieldView {
                name: "Algorithm".into(),
                value: sig_algo,
                range: sig_algo_range,
            },
            FieldView {
                name: "Size".into(),
                value: format!("{} bytes", crl.signature_value.data.len()),
                range: sig_value_range,
            },
        ],
        diagnostics: Vec::new(),
    });

    if is_pem {
        top_diagnostics.push(Diagnostic {
            severity: Severity::Info,
            message: "Byte ranges refer to decoded DER content, not PEM text".into(),
            range: None,
        });
    }

    AnalysisNode {
        id: NodeId::new(),
        label: label.into(),
        kind: "x509_crl".into(),
        range: outer_spans
            .as_ref()
            .map(|s| s.certificate)
            .unwrap_or(crl_range),
        children,
        fields: top_fields,
        diagnostics: top_diagnostics,
    }
}

/// Format a parsed extension value into a human-readable string.
fn format_parsed_extension(ext: &X509Extension<'_>) -> Option<String> {
    match ext.parsed_extension() {
        ParsedExtension::BasicConstraints(bc) => Some(format!(
            "CA={}, pathLen={}",
            bc.ca,
            bc.path_len_constraint
                .map(|n| n.to_string())
                .unwrap_or_else(|| "none".into())
        )),
        ParsedExtension::KeyUsage(ku) => {
            let mut usages = Vec::new();
            if ku.digital_signature() {
                usages.push("digitalSignature");
            }
            if ku.non_repudiation() {
                usages.push("nonRepudiation");
            }
            if ku.key_encipherment() {
                usages.push("keyEncipherment");
            }
            if ku.data_encipherment() {
                usages.push("dataEncipherment");
            }
            if ku.key_agreement() {
                usages.push("keyAgreement");
            }
            if ku.key_cert_sign() {
                usages.push("keyCertSign");
            }
            if ku.crl_sign() {
                usages.push("cRLSign");
            }
            Some(usages.join(", "))
        }
        ParsedExtension::SubjectAlternativeName(san) => {
            let names: Vec<String> = san
                .general_names
                .iter()
                .map(|gn| match gn {
                    GeneralName::DNSName(s) => format!("DNS:{}", s),
                    GeneralName::IPAddress(b) => {
                        if b.len() == 4 {
                            format!("IP:{}.{}.{}.{}", b[0], b[1], b[2], b[3])
                        } else {
                            format!("IP:[{} bytes]", b.len())
                        }
                    }
                    GeneralName::RFC822Name(s) => format!("email:{}", s),
                    GeneralName::URI(s) => format!("URI:{}", s),
                    other => format!("{:?}", other),
                })
                .collect();
            Some(names.join(", "))
        }
        ParsedExtension::ExtendedKeyUsage(eku) => {
            let mut usages = Vec::new();
            if eku.server_auth {
                usages.push("serverAuth");
            }
            if eku.client_auth {
                usages.push("clientAuth");
            }
            if eku.code_signing {
                usages.push("codeSigning");
            }
            if eku.email_protection {
                usages.push("emailProtection");
            }
            if eku.time_stamping {
                usages.push("timeStamping");
            }
            if eku.ocsp_signing {
                usages.push("ocspSigning");
            }
            if !eku.other.is_empty() {
                usages.push(&"[other]");
            }
            Some(usages.join(", "))
        }
        _ => None,
    }
}
