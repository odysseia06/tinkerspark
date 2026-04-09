use std::path::PathBuf;
use tinkerspark_core_analyze::{Analyzer, AnalyzerConfidence, AnalyzerRegistry};
use tinkerspark_core_bytes::MemoryByteSource;
use tinkerspark_core_types::{DetectedKind, FileHandle, FileId};

fn make_handle(path: &str, kind: DetectedKind, size: u64) -> FileHandle {
    FileHandle {
        id: FileId::new(),
        path: PathBuf::from(path),
        size,
        kind,
    }
}

fn build_registry() -> AnalyzerRegistry {
    let mut registry = AnalyzerRegistry::new();
    registry.register(Box::new(tinkerspark_format_openpgp::OpenPgpAnalyzer));
    registry.register(Box::new(tinkerspark_format_x509::X509Analyzer));
    registry.register(Box::new(tinkerspark_format_ssh::SshAnalyzer));
    registry.register(Box::new(tinkerspark_format_age::AgeAnalyzer));
    registry.register(Box::new(tinkerspark_format_jwk::JwkAnalyzer));
    // Generic fallback last.
    registry.register(Box::new(tinkerspark_format_generic::GenericAnalyzer::new()));
    registry
}

// ── Dedicated analyzer wins over generic fallback ──

#[test]
fn x509_pem_uses_dedicated_analyzer() {
    let data = std::fs::read("../../testdata/x509/self-signed.pem").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle("cert.pem", DetectedKind::X509Pem, data.len() as u64);
    let registry = build_registry();

    let (analyzer, confidence) = registry.best_match(&handle, &src).unwrap();
    assert_eq!(analyzer.id(), "x509");
    assert_eq!(confidence, AnalyzerConfidence::High);

    let report = analyzer.analyze(&handle, &src).unwrap();
    assert_eq!(report.analyzer_id, "x509");
    assert!(!report.root_nodes.is_empty());
    // Should have certificate node with subject/issuer.
    let cert_node = &report.root_nodes[0];
    assert!(cert_node.kind.contains("x509"));
}

#[test]
fn ssh_pubkey_uses_dedicated_analyzer() {
    let data = std::fs::read("../../testdata/ssh/id_ed25519.pub").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(
        "id_ed25519.pub",
        DetectedKind::SshPublicKey,
        data.len() as u64,
    );
    let registry = build_registry();

    let (analyzer, confidence) = registry.best_match(&handle, &src).unwrap();
    assert_eq!(analyzer.id(), "ssh");
    assert_eq!(confidence, AnalyzerConfidence::High);
}

#[test]
fn age_encrypted_uses_dedicated_analyzer() {
    let data = std::fs::read("../../testdata/age/encrypted.age").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle("secret.age", DetectedKind::AgeEncrypted, data.len() as u64);
    let registry = build_registry();

    let (analyzer, _) = registry.best_match(&handle, &src).unwrap();
    assert_eq!(analyzer.id(), "age");
}

#[test]
fn jwk_uses_dedicated_analyzer() {
    let data = std::fs::read("../../testdata/jwk/rsa-public.jwk").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle("key.jwk", DetectedKind::JsonWebKey, data.len() as u64);
    let registry = build_registry();

    let (analyzer, _) = registry.best_match(&handle, &src).unwrap();
    assert_eq!(analyzer.id(), "jwk");
}

// ── Unknown files get useful generic output ──

#[test]
fn unknown_binary_gets_generic_analysis() {
    let data = std::fs::read("../../testdata/generic/random.bin").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle("random.bin", DetectedKind::Binary, data.len() as u64);
    let registry = build_registry();

    let result = registry.auto_analyze(&handle, &src);
    assert!(result.is_some(), "generic should accept any binary file");
    let report = result.unwrap().unwrap();
    assert_eq!(report.analyzer_id, "generic");
    // Should have at least overview and entropy nodes.
    assert!(!report.root_nodes.is_empty());
    assert!(
        report.root_nodes.iter().any(|n| n.kind == "overview"),
        "generic report should have overview node"
    );
}

#[test]
fn png_binary_gets_generic_analysis_with_signature() {
    let data = std::fs::read("../../testdata/generic/tiny.png").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle("tiny.png", DetectedKind::Binary, data.len() as u64);
    let registry = build_registry();

    let report = registry.auto_analyze(&handle, &src).unwrap().unwrap();
    assert_eq!(report.analyzer_id, "generic");

    // Should detect PNG signature.
    let sig_node = report.root_nodes.iter().find(|n| n.kind == "signatures");
    assert!(sig_node.is_some(), "should detect PNG signature");
    let sig_node = sig_node.unwrap();
    assert!(
        sig_node.children.iter().any(|c| c.label.contains("PNG")),
        "should identify PNG format"
    );
}

// ── Heuristic coverage expansions (issue #2) ──

fn analyze_generic_balanced(data: Vec<u8>) -> tinkerspark_core_analyze::AnalysisReport {
    let handle = make_handle("synthetic.bin", DetectedKind::Binary, data.len() as u64);
    let src = MemoryByteSource::new(data);
    tinkerspark_format_generic::GenericAnalyzer::new()
        .analyze(&handle, &src)
        .unwrap()
}

#[test]
fn detects_le_tlv_chain_through_full_pipeline() {
    // Two 1-byte tag + 2-byte LE length records.
    let data = vec![
        0x10, 0x04, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, //
        0x11, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, //
    ];
    let report = analyze_generic_balanced(data);
    let tlv = report.root_nodes.iter().find(|n| n.kind == "tlv");
    assert!(tlv.is_some(), "should expose a tlv node");
    let tlv = tlv.unwrap();
    assert!(
        tlv.children
            .iter()
            .any(|c| c.label.contains("2-byte LE length")),
        "tlv chain children should mention LE encoding: {:?}",
        tlv.children.iter().map(|c| &c.label).collect::<Vec<_>>()
    );
}

#[test]
fn detects_varint_tlv_chain_through_full_pipeline() {
    // 4 elements: tag=0x42, varint len=2, 2 payload bytes.
    let data: Vec<u8> = vec![
        0x42, 0x02, 0xAA, 0xBB, //
        0x42, 0x02, 0xCC, 0xDD, //
        0x42, 0x02, 0xEE, 0xFF, //
        0x42, 0x02, 0x11, 0x22, //
    ];
    let report = analyze_generic_balanced(data);
    let tlv = report.root_nodes.iter().find(|n| n.kind == "tlv");
    assert!(tlv.is_some(), "should expose a tlv node for varint chain");
    assert!(
        tlv.unwrap()
            .children
            .iter()
            .any(|c| c.label.contains("varint")),
        "varint encoding should be labeled in the tlv chain"
    );
}

#[test]
fn detects_utf8_strings_through_full_pipeline() {
    // "héllo" (5 chars, 6 bytes) + padding so it sits inside binary.
    let mut data = vec![0x00; 16];
    data.extend_from_slice("héllo world".as_bytes());
    data.extend(vec![0x00; 16]);
    let report = analyze_generic_balanced(data);
    let utf8 = report.root_nodes.iter().find(|n| n.kind == "utf8_strings");
    assert!(utf8.is_some(), "should expose a utf8_strings node");
    assert!(
        utf8.unwrap()
            .children
            .iter()
            .any(|c| c.label.contains("héllo")),
        "utf8 children should include the non-ASCII string"
    );
}

#[test]
fn detects_key_value_patterns_through_full_pipeline() {
    // Three k=v lines separated by NULs so each becomes its own ASCII string.
    let mut data = Vec::new();
    for line in &["host=example.com", "port=8080", "user=alice"] {
        data.extend_from_slice(line.as_bytes());
        data.push(0x00);
    }
    let report = analyze_generic_balanced(data);
    let kv = report.root_nodes.iter().find(|n| n.kind == "kv_pairs");
    assert!(kv.is_some(), "should expose a kv_pairs node");
    let kv = kv.unwrap();
    assert_eq!(kv.children.len(), 3);
    assert!(kv.children.iter().any(|c| c.label.starts_with("host = ")));
    assert!(kv.children.iter().any(|c| c.label.starts_with("port = ")));
    assert!(kv.children.iter().any(|c| c.label.starts_with("user = ")));
}

#[test]
fn detects_encoded_sections_through_full_pipeline() {
    // A 32-char hex blob and a 24-char base64 blob, separated by NULs.
    let mut data = Vec::new();
    data.extend_from_slice(b"deadbeefcafebabe0123456789abcdef");
    data.push(0x00);
    data.extend_from_slice(b"SGVsbG8gV29ybGQgZm9vYmFy");
    data.push(0x00);
    let report = analyze_generic_balanced(data);
    let encoded = report
        .root_nodes
        .iter()
        .find(|n| n.kind == "encoded_sections");
    assert!(encoded.is_some(), "should expose an encoded_sections node");
    let encoded = encoded.unwrap();
    assert!(encoded.children.iter().any(|c| c.label.starts_with("Hex:")));
    assert!(encoded
        .children
        .iter()
        .any(|c| c.label.starts_with("Base64:")));
}

#[test]
fn random_bin_does_not_emit_kv_or_encoded_nodes_in_balanced() {
    // Acceptance criterion from the issue: keep the false-positive rate
    // acceptable in the default mode. random.bin is the canonical noise
    // sample — it must not produce key-value or encoded-section nodes
    // under Balanced sensitivity.
    let data = std::fs::read("../../testdata/generic/random.bin").unwrap();
    let report = analyze_generic_balanced(data);
    assert!(
        report.root_nodes.iter().all(|n| n.kind != "kv_pairs"),
        "random.bin should not yield key-value pairs in Balanced mode"
    );
    assert!(
        report
            .root_nodes
            .iter()
            .all(|n| n.kind != "encoded_sections"),
        "random.bin should not yield encoded sections in Balanced mode"
    );
}

// ── Malformed inputs degrade gracefully ──

#[test]
fn truncated_der_does_not_panic() {
    let data = std::fs::read("../../testdata/generic/truncated.bin").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle("truncated.bin", DetectedKind::X509Der, data.len() as u64);

    // X509 analyzer should fail gracefully.
    let result = tinkerspark_format_x509::X509Analyzer.analyze(&handle, &src);
    assert!(result.is_err(), "truncated DER should fail gracefully");

    // Generic analyzer should still produce output.
    let generic = tinkerspark_format_generic::GenericAnalyzer::new();
    let report = generic.analyze(&handle, &src).unwrap();
    assert!(
        !report.root_nodes.is_empty(),
        "generic should produce output for truncated data"
    );
}

#[test]
fn empty_file_generic_analysis() {
    let src = MemoryByteSource::new(Vec::new());
    let handle = make_handle("empty", DetectedKind::Empty, 0);

    let generic = tinkerspark_format_generic::GenericAnalyzer::new();
    let report = generic.analyze(&handle, &src).unwrap();
    assert!(
        !report.root_nodes.is_empty(),
        "should produce overview even for empty file"
    );
}

#[test]
fn malformed_jwt_does_not_panic() {
    let data = b"eyJhbGciOiJIUzI1.not-valid-base64.!!!";
    let src = MemoryByteSource::new(data.to_vec());
    let handle = make_handle("bad.jwt", DetectedKind::JsonWebToken, data.len() as u64);

    let analyzer = tinkerspark_format_jwk::JwkAnalyzer;
    // Should either produce a report with diagnostics or fail gracefully.
    let result = analyzer.analyze(&handle, &src);
    // Either way, no panic.
    match result {
        Ok(report) => {
            assert!(!report.root_nodes.is_empty() || !report.diagnostics.is_empty());
        }
        Err(_) => {} // Parse error is acceptable.
    }
}

#[test]
fn malformed_age_does_not_panic() {
    let data = b"age-encryption.org/v1\n-- truncated header";
    let src = MemoryByteSource::new(data.to_vec());
    let handle = make_handle("bad.age", DetectedKind::AgeEncrypted, data.len() as u64);

    let analyzer = tinkerspark_format_age::AgeAnalyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();
    // Should have warning about missing terminator.
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("truncated") || d.message.contains("terminator")),
        "should warn about truncated header"
    );
}

// ── Confidence ordering ──

#[test]
fn generic_always_has_low_confidence() {
    let generic = tinkerspark_format_generic::GenericAnalyzer::new();
    let data = vec![0x42; 100];
    let src = MemoryByteSource::new(data);
    let handle = make_handle("test.bin", DetectedKind::Binary, 100);
    assert_eq!(generic.can_analyze(&handle, &src), AnalyzerConfidence::Low);
}

#[test]
fn dedicated_analyzers_have_higher_confidence_than_generic() {
    let src = MemoryByteSource::new(vec![0]);

    let x509_handle = make_handle("cert.pem", DetectedKind::X509Pem, 1);
    let x509_conf = tinkerspark_format_x509::X509Analyzer.can_analyze(&x509_handle, &src);
    let generic_conf =
        tinkerspark_format_generic::GenericAnalyzer::new().can_analyze(&x509_handle, &src);
    assert!(
        x509_conf > generic_conf,
        "X509 confidence should beat generic"
    );

    let ssh_handle = make_handle("key.pub", DetectedKind::SshPublicKey, 1);
    let ssh_conf = tinkerspark_format_ssh::SshAnalyzer.can_analyze(&ssh_handle, &src);
    assert!(
        ssh_conf > generic_conf,
        "SSH confidence should beat generic"
    );

    let age_handle = make_handle("secret.age", DetectedKind::AgeEncrypted, 1);
    let age_conf = tinkerspark_format_age::AgeAnalyzer.can_analyze(&age_handle, &src);
    assert!(
        age_conf > generic_conf,
        "age confidence should beat generic"
    );

    let jwk_handle = make_handle("key.jwk", DetectedKind::JsonWebKey, 1);
    let jwk_conf = tinkerspark_format_jwk::JwkAnalyzer.can_analyze(&jwk_handle, &src);
    assert!(
        jwk_conf > generic_conf,
        "JWK confidence should beat generic"
    );
}

// ── Regression tests for review findings ──

// H1: CRL/CSR PEM should NOT be classified as X509Pem — they should fall
// through to generic Pem and be handled by the generic fallback (or a future
// dedicated analyzer), not black-holed by X509Analyzer.
#[test]
fn crl_pem_routes_to_generic_not_x509() {
    let data = b"-----BEGIN X509 CRL-----\nMIIBFake==\n-----END X509 CRL-----\n";
    let src = MemoryByteSource::new(data.to_vec());
    // Sniff kind to verify it's NOT X509Pem anymore.
    let kind = tinkerspark_core_bytes::sniff_kind(
        &data[..],
        std::path::Path::new("crl.pem"),
        data.len() as u64,
    );
    assert_ne!(kind, DetectedKind::X509Pem, "CRL PEM should not be X509Pem");
    assert_eq!(kind, DetectedKind::Pem, "CRL PEM should be generic Pem");

    let handle = make_handle("crl.pem", kind, data.len() as u64);
    let registry = build_registry();
    let result = registry.auto_analyze(&handle, &src);
    assert!(result.is_some(), "generic fallback should accept Pem files");
    let report = result.unwrap().unwrap();
    assert_eq!(
        report.analyzer_id, "generic",
        "CRL PEM should be analyzed by generic, not x509"
    );
}

#[test]
fn csr_pem_routes_to_generic_not_x509() {
    let data =
        b"-----BEGIN CERTIFICATE REQUEST-----\nMIIBFake==\n-----END CERTIFICATE REQUEST-----\n";
    let src = MemoryByteSource::new(data.to_vec());
    let kind = tinkerspark_core_bytes::sniff_kind(
        &data[..],
        std::path::Path::new("csr.pem"),
        data.len() as u64,
    );
    assert_ne!(kind, DetectedKind::X509Pem, "CSR PEM should not be X509Pem");
    assert_eq!(kind, DetectedKind::Pem, "CSR PEM should be generic Pem");

    let handle = make_handle("csr.pem", kind, data.len() as u64);
    let registry = build_registry();
    let report = registry.auto_analyze(&handle, &src).unwrap().unwrap();
    assert_eq!(
        report.analyzer_id, "generic",
        "CSR PEM should be analyzed by generic, not x509"
    );
}

// H2: A non-certificate ASN.1 blob (Binary with 0x30 lead) should reach the
// generic fallback, not be claimed and then dropped by X509.
#[test]
fn non_cert_asn1_binary_gets_generic_fallback() {
    // Valid-looking ASN.1 SEQUENCE that is NOT a certificate.
    // Two consecutive SEQUENCEs (a valid TLV chain the generic analyzer can show).
    let data: Vec<u8> = vec![
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, // SEQUENCE { INT 1, INT 2 }
        0x30, 0x06, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04, // SEQUENCE { INT 3, INT 4 }
    ];
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle("data.ber", DetectedKind::Binary, data.len() as u64);
    let registry = build_registry();

    // X509 should return None for Binary (no longer claims Low).
    let x509_conf = tinkerspark_format_x509::X509Analyzer.can_analyze(&handle, &src);
    assert_eq!(
        x509_conf,
        AnalyzerConfidence::None,
        "X509 should not claim generic Binary files"
    );

    // Registry should route to generic.
    let report = registry.auto_analyze(&handle, &src).unwrap().unwrap();
    assert_eq!(
        report.analyzer_id, "generic",
        "non-cert ASN.1 binary should reach generic fallback"
    );
}

// H2 continued: Registry fallback-on-error — if a dedicated analyzer fails,
// the registry should try the next candidate.
#[test]
fn registry_falls_back_on_parse_error() {
    // A file detected as X509Der but containing garbage that fails to parse.
    let data = vec![0x30, 0x82, 0x01, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle("bad.der", DetectedKind::X509Der, data.len() as u64);
    let registry = build_registry();

    // X509 claims High for X509Der, will attempt parse and fail.
    // Generic claims Low for anything. Registry should cascade.
    let result = registry.auto_analyze(&handle, &src);
    assert!(result.is_some(), "should have a result after fallback");
    let report = result.unwrap().unwrap();
    assert_eq!(
        report.analyzer_id, "generic",
        "after X509 parse failure, generic should take over"
    );
}

// M3: JWK nodes must have non-empty byte ranges.
#[test]
fn jwk_nodes_have_nonempty_ranges() {
    let jwk = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
    let src = MemoryByteSource::new(jwk.as_bytes().to_vec());
    let handle = make_handle("key.jwk", DetectedKind::JsonWebKey, jwk.len() as u64);

    let analyzer = tinkerspark_format_jwk::JwkAnalyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();
    for node in &report.root_nodes {
        assert!(
            !node.range.is_empty(),
            "root JWK node '{}' should have non-empty range, got {:?}",
            node.label,
            node.range
        );
    }
}

#[test]
fn jwk_set_children_have_nonempty_ranges() {
    let jwks = r#"{"keys":[{"kty":"EC","crv":"P-256","x":"abc","y":"def"},{"kty":"RSA","n":"ghi","e":"AQAB"}]}"#;
    let src = MemoryByteSource::new(jwks.as_bytes().to_vec());
    let handle = make_handle("keys.jwk", DetectedKind::JsonWebKey, jwks.len() as u64);

    let analyzer = tinkerspark_format_jwk::JwkAnalyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();
    let set_node = &report.root_nodes[0];
    assert!(
        !set_node.range.is_empty(),
        "JWK Set root should have non-empty range"
    );
    for child in &set_node.children {
        assert!(
            !child.range.is_empty(),
            "JWK Set child '{}' should have non-empty range, got {:?}",
            child.label,
            child.range
        );
    }
}

// Low: best_match() should not return x509 for CRL/CSR PEM.
#[test]
fn best_match_does_not_return_x509_for_crl_pem() {
    let data = b"-----BEGIN X509 CRL-----\nMIIBFake==\n-----END X509 CRL-----\n";
    let src = MemoryByteSource::new(data.to_vec());
    let handle = make_handle("crl.pem", DetectedKind::Pem, data.len() as u64);
    let registry = build_registry();

    let (analyzer, _) = registry.best_match(&handle, &src).unwrap();
    assert_ne!(
        analyzer.id(),
        "x509",
        "best_match should not return x509 for CRL PEM"
    );
}

#[test]
fn best_match_does_not_return_x509_for_csr_pem() {
    let data =
        b"-----BEGIN CERTIFICATE REQUEST-----\nMIIBFake==\n-----END CERTIFICATE REQUEST-----\n";
    let src = MemoryByteSource::new(data.to_vec());
    let handle = make_handle("csr.pem", DetectedKind::Pem, data.len() as u64);
    let registry = build_registry();

    let (analyzer, _) = registry.best_match(&handle, &src).unwrap();
    assert_ne!(
        analyzer.id(),
        "x509",
        "best_match should not return x509 for CSR PEM"
    );
}

// Medium: sniff_kind on non-certificate DER should not yield X509Der.
#[test]
fn sniff_kind_non_cert_der_not_x509() {
    // SEQUENCE { INTEGER 1, INTEGER 2 } — valid ASN.1, not a certificate.
    let data: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    let kind = tinkerspark_core_bytes::sniff_kind(data, std::path::Path::new("data.der"), 8);
    assert_ne!(
        kind,
        DetectedKind::X509Der,
        "non-certificate ASN.1 should not be sniffed as X509Der"
    );
}
