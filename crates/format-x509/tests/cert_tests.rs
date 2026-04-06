use std::path::PathBuf;
use tinkerspark_core_analyze::Analyzer;
use tinkerspark_core_bytes::MemoryByteSource;
use tinkerspark_core_types::{DetectedKind, FileHandle, FileId};

fn make_handle(kind: DetectedKind, size: u64) -> FileHandle {
    FileHandle {
        id: FileId::new(),
        path: PathBuf::from("test.pem"),
        size,
        kind,
    }
}

#[test]
fn parses_pem_certificate() {
    let data = std::fs::read("../../testdata/x509/self-signed.pem").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::X509Pem, data.len() as u64);

    let analyzer = tinkerspark_format_x509::X509Analyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();

    assert_eq!(report.analyzer_id, "x509");
    assert!(
        !report.root_nodes.is_empty(),
        "should parse at least one cert"
    );

    let cert = &report.root_nodes[0];
    assert_eq!(cert.kind, "x509_certificate");

    // Should have subject, issuer, validity, public key, signature children.
    let child_kinds: Vec<&str> = cert.children.iter().map(|c| c.kind.as_str()).collect();
    assert!(
        child_kinds.contains(&"x509_issuer"),
        "should have issuer node"
    );
    assert!(
        child_kinds.contains(&"x509_subject"),
        "should have subject node"
    );
    assert!(
        child_kinds.contains(&"x509_validity"),
        "should have validity node"
    );
    assert!(
        child_kinds.contains(&"x509_public_key"),
        "should have public key node"
    );
    assert!(
        child_kinds.contains(&"x509_signature"),
        "should have signature node"
    );

    // Should have PEM diagnostic.
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("PEM-encoded")),
        "should note PEM encoding"
    );

    // Check that fields contain expected data.
    assert!(
        cert.fields.iter().any(|f| f.name == "Subject"),
        "should have Subject field"
    );
    assert!(
        cert.fields.iter().any(|f| f.name == "Version"),
        "should have Version field"
    );
}

#[test]
fn rejects_garbage_data() {
    let data = vec![0xFF; 100];
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::X509Der, data.len() as u64);

    let analyzer = tinkerspark_format_x509::X509Analyzer;
    let result = analyzer.analyze(&handle, &src);
    assert!(result.is_err(), "should fail on garbage data");
}

#[test]
fn parses_der_certificate_with_precise_spans() {
    let data = std::fs::read("../../testdata/x509/self-signed.der").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::X509Der, data.len() as u64);

    let analyzer = tinkerspark_format_x509::X509Analyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();

    assert_eq!(report.analyzer_id, "x509");
    let cert = &report.root_nodes[0];
    assert_eq!(cert.kind, "x509_certificate");

    // Certificate range should span the entire DER file.
    assert_eq!(cert.range.offset(), 0);
    assert_eq!(cert.range.length(), data.len() as u64);

    // Each major child node should have a non-cert-range span
    // (i.e. a precise sub-range, not the whole file).
    let issuer = cert
        .children
        .iter()
        .find(|c| c.kind == "x509_issuer")
        .unwrap();
    assert!(
        issuer.range.length() < cert.range.length(),
        "Issuer should have a precise sub-range, not the full cert"
    );
    assert!(issuer.range.offset() > 0);

    let subject = cert
        .children
        .iter()
        .find(|c| c.kind == "x509_subject")
        .unwrap();
    assert!(subject.range.length() < cert.range.length());

    let validity = cert
        .children
        .iter()
        .find(|c| c.kind == "x509_validity")
        .unwrap();
    assert!(validity.range.length() < cert.range.length());

    // Validity should have notBefore and notAfter with precise DER ranges.
    let not_before_field = validity
        .fields
        .iter()
        .find(|f| f.name == "Not Before")
        .unwrap();
    assert!(
        not_before_field.range.is_some(),
        "Not Before should have a DER span"
    );

    let not_after_field = validity
        .fields
        .iter()
        .find(|f| f.name == "Not After")
        .unwrap();
    assert!(
        not_after_field.range.is_some(),
        "Not After should have a DER span"
    );

    // notBefore and notAfter should be inside the Validity range.
    let nb = not_before_field.range.unwrap();
    let na = not_after_field.range.unwrap();
    assert!(
        nb.offset() >= validity.range.offset(),
        "notBefore should be within Validity"
    );
    assert!(
        na.end() <= validity.range.end(),
        "notAfter should be within Validity"
    );
    assert!(nb.end() <= na.offset(), "notBefore should precede notAfter");

    let pubkey = cert
        .children
        .iter()
        .find(|c| c.kind == "x509_public_key")
        .unwrap();
    assert!(pubkey.range.length() < cert.range.length());

    let sig = cert
        .children
        .iter()
        .find(|c| c.kind == "x509_signature")
        .unwrap();
    assert!(sig.range.length() < cert.range.length());

    // Extensions node range should also be precise (for v3 certs).
    if let Some(exts) = cert.children.iter().find(|c| c.kind == "x509_extensions") {
        assert!(exts.range.length() < cert.range.length());

        // Each individual extension should have a wrapper span that is
        // within the extensions range and smaller than the full cert.
        for ext_child in &exts.children {
            assert!(
                ext_child.range.length() < cert.range.length(),
                "extension '{}' should have a precise range",
                ext_child.label
            );
            assert!(
                ext_child.range.offset() >= exts.range.offset(),
                "extension '{}' should be within extensions range",
                ext_child.label
            );
        }
    }

    // No PEM diagnostic for DER input.
    assert!(
        !report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("PEM-encoded")),
        "DER cert should not have PEM diagnostic"
    );

    // Version field should have a range (from TLV walking).
    let version_field = cert.fields.iter().find(|f| f.name == "Version").unwrap();
    assert!(
        version_field.range.is_some(),
        "Version field should have a DER span"
    );

    // Serial field should have a range.
    let serial_field = cert
        .fields
        .iter()
        .find(|f| f.name == "Serial Number")
        .unwrap();
    assert!(
        serial_field.range.is_some(),
        "Serial field should have a DER span"
    );
}
