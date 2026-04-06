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
