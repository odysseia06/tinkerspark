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

// ── CSR (issue #3) ──

#[test]
fn parses_csr_pem() {
    let data = std::fs::read("../../testdata/x509/csr.pem").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::Pem, data.len() as u64);

    let analyzer = tinkerspark_format_x509::X509Analyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();

    assert_eq!(report.analyzer_id, "x509");
    assert_eq!(report.root_nodes.len(), 1);
    let csr = &report.root_nodes[0];
    assert_eq!(csr.kind, "x509_csr");

    // CSR should have subject, public key, and signature children. No issuer.
    let kinds: Vec<&str> = csr.children.iter().map(|c| c.kind.as_str()).collect();
    assert!(kinds.contains(&"x509_csr_subject"));
    assert!(kinds.contains(&"x509_csr_public_key"));
    assert!(kinds.contains(&"x509_csr_signature"));
    assert!(
        !kinds.iter().any(|k| k.contains("issuer")),
        "CSRs have no issuer"
    );

    // Subject should match what we generated.
    let subject_field = csr.fields.iter().find(|f| f.name == "Subject").unwrap();
    assert!(subject_field.value.contains("CN=tinkerspark-test"));

    // PEM diagnostic must be present.
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("PEM-encoded")));
}

#[test]
fn parses_csr_der_with_precise_spans() {
    let data = std::fs::read("../../testdata/x509/csr.der").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::X509Der, data.len() as u64);

    let analyzer = tinkerspark_format_x509::X509Analyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();

    assert_eq!(report.analyzer_id, "x509");
    let csr = &report.root_nodes[0];
    assert_eq!(csr.kind, "x509_csr");
    assert_eq!(csr.range.offset(), 0);
    assert_eq!(csr.range.length(), data.len() as u64);

    // The subject child must have a precise sub-range, not the full CSR.
    let subject = csr
        .children
        .iter()
        .find(|c| c.kind == "x509_csr_subject")
        .unwrap();
    assert!(subject.range.length() < csr.range.length());
    assert!(subject.range.offset() > 0);

    // The public key child has its own SPKI sub-spans (algorithm + key bits).
    let pubkey = csr
        .children
        .iter()
        .find(|c| c.kind == "x509_csr_public_key")
        .unwrap();
    let spki_kinds: Vec<&str> = pubkey.children.iter().map(|c| c.kind.as_str()).collect();
    assert!(spki_kinds.contains(&"x509_spki_algorithm"));
    assert!(spki_kinds.contains(&"x509_spki_key_bits"));

    // Signature wraps the outer BIT STRING and must be inside the CSR range.
    let sig = csr
        .children
        .iter()
        .find(|c| c.kind == "x509_csr_signature")
        .unwrap();
    assert!(sig.range.length() < csr.range.length());
}

#[test]
fn csr_der_with_trailing_junk_is_rejected() {
    // Take the real CSR DER fixture and append garbage bytes. The parser
    // would otherwise consume the prefix and silently drop the tail; we
    // require full-input consumption so this must fail with a message
    // that names both the cause and the offset of the unconsumed tail.
    let mut data = std::fs::read("../../testdata/x509/csr.der").unwrap();
    let original_len = data.len();
    let trailing = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0xFF];
    data.extend_from_slice(&trailing);
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::X509Der, data.len() as u64);

    let analyzer = tinkerspark_format_x509::X509Analyzer;
    let err = analyzer
        .analyze(&handle, &src)
        .expect_err("valid CSR prefix + junk must error");
    let msg = err.to_string();
    assert!(
        msg.contains("trailing"),
        "error should name the trailing bytes; got: {msg}"
    );
    assert!(
        msg.contains(&format!("0x{:X}", original_len)),
        "error should mention the offset 0x{:X} where the tail starts; got: {msg}",
        original_len
    );
    assert!(
        msg.contains(&trailing.len().to_string()),
        "error should mention the trailing byte count {}; got: {msg}",
        trailing.len()
    );
}

#[test]
fn csr_attributes_have_distinct_per_attribute_spans() {
    // testdata/x509/csr-multi.{pem,der} is generated by openssl with both
    // a challengePassword attribute and an extensionRequest attribute, so
    // there are two distinct CSR attributes whose DER ranges must not
    // collapse to the shared [0] wrapper range.
    let data = std::fs::read("../../testdata/x509/csr-multi.der").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::X509Der, data.len() as u64);

    let analyzer = tinkerspark_format_x509::X509Analyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();
    let csr = &report.root_nodes[0];
    assert_eq!(csr.kind, "x509_csr");

    let attrs_node = csr
        .children
        .iter()
        .find(|c| c.kind == "x509_csr_attributes")
        .expect("multi-attribute CSR should expose an attributes node");
    assert!(
        attrs_node.children.len() >= 2,
        "fixture should have at least two CSR attributes; got {}",
        attrs_node.children.len()
    );

    // Each attribute child must have a range distinct from the wrapper and
    // strictly narrower than the full CSR.
    let wrapper = attrs_node.range;
    for child in &attrs_node.children {
        assert_eq!(child.kind, "x509_csr_attribute");
        assert!(
            child.range != wrapper,
            "attribute child must not point at the [0] wrapper range"
        );
        assert!(
            child.range.length() < wrapper.length(),
            "attribute child range should be a strict sub-range of the wrapper"
        );
        assert!(
            child.range.offset() >= wrapper.offset() && child.range.end() <= wrapper.end(),
            "attribute child range should sit inside the wrapper"
        );
    }

    // Sibling attributes must have distinct ranges.
    let mut offsets: Vec<u64> = attrs_node
        .children
        .iter()
        .map(|c| c.range.offset())
        .collect();
    offsets.sort_unstable();
    offsets.dedup();
    assert_eq!(
        offsets.len(),
        attrs_node.children.len(),
        "sibling attribute nodes must have distinct offsets"
    );
}

#[test]
fn malformed_csr_fails_gracefully() {
    let data =
        b"-----BEGIN CERTIFICATE REQUEST-----\nMIIBFake==\n-----END CERTIFICATE REQUEST-----\n";
    let src = MemoryByteSource::new(data.to_vec());
    let handle = make_handle(DetectedKind::Pem, data.len() as u64);

    let analyzer = tinkerspark_format_x509::X509Analyzer;
    let result = analyzer.analyze(&handle, &src);
    // Should fail (no parseable CSR), not panic.
    assert!(result.is_err());
}

// ── CRL (issue #3) ──

#[test]
fn parses_crl_pem() {
    let data = std::fs::read("../../testdata/x509/crl.pem").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::Pem, data.len() as u64);

    let analyzer = tinkerspark_format_x509::X509Analyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();

    assert_eq!(report.analyzer_id, "x509");
    let crl = &report.root_nodes[0];
    assert_eq!(crl.kind, "x509_crl");

    // CRL must have an issuer, a revoked-list (the fixture has one entry),
    // and a signature.
    let kinds: Vec<&str> = crl.children.iter().map(|c| c.kind.as_str()).collect();
    assert!(kinds.contains(&"x509_crl_issuer"));
    assert!(kinds.contains(&"x509_crl_revoked_list"));
    assert!(kinds.contains(&"x509_crl_signature"));

    // Top-level fields should include the update timestamps.
    let field_names: Vec<&str> = crl.fields.iter().map(|f| f.name.as_str()).collect();
    assert!(field_names.contains(&"This Update"));
    assert!(field_names.contains(&"Next Update"));
    assert!(field_names.contains(&"Issuer"));

    // The revoked list should have at least one entry (we revoked serial 01).
    let revoked = crl
        .children
        .iter()
        .find(|c| c.kind == "x509_crl_revoked_list")
        .unwrap();
    assert!(!revoked.children.is_empty());
    let entry = &revoked.children[0];
    assert_eq!(entry.kind, "x509_crl_revoked");
    let serial_field = entry.fields.iter().find(|f| f.name == "Serial").unwrap();
    assert!(serial_field.value.contains("01"));
}

#[test]
fn parses_crl_der_with_precise_spans() {
    let data = std::fs::read("../../testdata/x509/crl.der").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::X509Der, data.len() as u64);

    let analyzer = tinkerspark_format_x509::X509Analyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();

    assert_eq!(report.analyzer_id, "x509");
    let crl = &report.root_nodes[0];
    assert_eq!(crl.kind, "x509_crl");
    assert_eq!(crl.range.offset(), 0);
    assert_eq!(crl.range.length(), data.len() as u64);

    // Issuer span should be a strict sub-range of the CRL.
    let issuer = crl
        .children
        .iter()
        .find(|c| c.kind == "x509_crl_issuer")
        .unwrap();
    assert!(issuer.range.length() < crl.range.length());
    assert!(issuer.range.offset() > 0);

    // The revoked entry should have a wrapper span inside the CRL and a
    // non-empty serial sub-range.
    let revoked = crl
        .children
        .iter()
        .find(|c| c.kind == "x509_crl_revoked_list")
        .unwrap();
    assert!(revoked.range.length() < crl.range.length());
    let entry = &revoked.children[0];
    assert!(entry.range.length() < crl.range.length());
    assert!(entry.range.offset() >= revoked.range.offset());
    let serial_range = entry
        .fields
        .iter()
        .find(|f| f.name == "Serial")
        .unwrap()
        .range
        .expect("revoked serial should have a DER span");
    assert!(serial_range.length() > 0);

    // CRL extensions are present (we set crlNumber via openssl ca).
    let exts = crl
        .children
        .iter()
        .find(|c| c.kind == "x509_crl_extensions")
        .expect("openssl-generated CRL should have crlNumber extension");
    assert!(!exts.children.is_empty());
}

#[test]
fn crl_der_with_trailing_junk_is_rejected() {
    let mut data = std::fs::read("../../testdata/x509/crl.der").unwrap();
    let original_len = data.len();
    let trailing = [0xCA, 0xFE, 0xBA, 0xBE];
    data.extend_from_slice(&trailing);
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::X509Der, data.len() as u64);

    let analyzer = tinkerspark_format_x509::X509Analyzer;
    let err = analyzer
        .analyze(&handle, &src)
        .expect_err("valid CRL prefix + junk must error");
    let msg = err.to_string();
    assert!(
        msg.contains("trailing"),
        "error should name the trailing bytes; got: {msg}"
    );
    assert!(
        msg.contains(&format!("0x{:X}", original_len)),
        "error should mention the offset 0x{:X}; got: {msg}",
        original_len
    );
    assert!(
        msg.contains(&trailing.len().to_string()),
        "error should mention the trailing byte count {}; got: {msg}",
        trailing.len()
    );
}

#[test]
fn malformed_crl_fails_gracefully() {
    let data = b"-----BEGIN X509 CRL-----\nMIIBFake==\n-----END X509 CRL-----\n";
    let src = MemoryByteSource::new(data.to_vec());
    let handle = make_handle(DetectedKind::Pem, data.len() as u64);

    let analyzer = tinkerspark_format_x509::X509Analyzer;
    let result = analyzer.analyze(&handle, &src);
    assert!(result.is_err());
}

#[test]
fn x509_analyzer_claims_csr_and_crl_pem() {
    use tinkerspark_core_analyze::AnalyzerConfidence;

    let analyzer = tinkerspark_format_x509::X509Analyzer;

    let csr_data =
        b"-----BEGIN CERTIFICATE REQUEST-----\nMIIBFake==\n-----END CERTIFICATE REQUEST-----\n";
    let csr_src = MemoryByteSource::new(csr_data.to_vec());
    let csr_handle = make_handle(DetectedKind::Pem, csr_data.len() as u64);
    assert_eq!(
        analyzer.can_analyze(&csr_handle, &csr_src),
        AnalyzerConfidence::High
    );

    let crl_data = b"-----BEGIN X509 CRL-----\nMIIBFake==\n-----END X509 CRL-----\n";
    let crl_src = MemoryByteSource::new(crl_data.to_vec());
    let crl_handle = make_handle(DetectedKind::Pem, crl_data.len() as u64);
    assert_eq!(
        analyzer.can_analyze(&crl_handle, &crl_src),
        AnalyzerConfidence::High
    );

    // The closing-dashes filter must still reject `BEGIN CERTIFICATE` prefix
    // matches that come from inside an unrelated label.
    let unrelated = b"-----BEGIN UNRELATED CERTIFICATE FAKE-----\nx\n-----END UNRELATED CERTIFICATE FAKE-----\n";
    let unrelated_src = MemoryByteSource::new(unrelated.to_vec());
    let unrelated_handle = make_handle(DetectedKind::Pem, unrelated.len() as u64);
    assert_eq!(
        analyzer.can_analyze(&unrelated_handle, &unrelated_src),
        AnalyzerConfidence::None
    );
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

    // SPKI should have child nodes for AlgorithmIdentifier and key bits.
    let spki_child_kinds: Vec<&str> = pubkey.children.iter().map(|c| c.kind.as_str()).collect();
    assert!(
        spki_child_kinds.contains(&"x509_spki_algorithm"),
        "SPKI should have algorithm child node"
    );
    assert!(
        spki_child_kinds.contains(&"x509_spki_key_bits"),
        "SPKI should have key bits child node"
    );

    // SPKI children should have ranges narrower than the SPKI parent.
    for child in &pubkey.children {
        assert!(
            child.range.length() < pubkey.range.length(),
            "SPKI child '{}' should have range narrower than SPKI parent",
            child.label
        );
        assert!(
            child.range.offset() >= pubkey.range.offset(),
            "SPKI child '{}' should start within SPKI",
            child.label
        );
        assert!(
            child.range.end() <= pubkey.range.end(),
            "SPKI child '{}' should end within SPKI",
            child.label
        );
    }

    // Algorithm and Key Size fields should now have precise DER ranges.
    let algo_field = pubkey
        .fields
        .iter()
        .find(|f| f.name == "Algorithm")
        .unwrap();
    assert!(
        algo_field.range.is_some(),
        "Algorithm field should have a DER span"
    );
    let size_field = pubkey.fields.iter().find(|f| f.name == "Key Size").unwrap();
    assert!(
        size_field.range.is_some(),
        "Key Size field should have a DER span"
    );

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
