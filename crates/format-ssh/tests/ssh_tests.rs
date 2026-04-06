use std::path::PathBuf;
use tinkerspark_core_analyze::{Analyzer, AnalyzerConfidence};
use tinkerspark_core_bytes::MemoryByteSource;
use tinkerspark_core_types::{DetectedKind, FileHandle, FileId};

fn make_handle(kind: DetectedKind, size: u64) -> FileHandle {
    FileHandle {
        id: FileId::new(),
        path: PathBuf::from("key"),
        size,
        kind,
    }
}

// ── Unencrypted private key ──

#[test]
fn parses_unencrypted_ed25519_private_key() {
    let data = std::fs::read("../../testdata/ssh/id_ed25519_unencrypted").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::SshPrivateKey, data.len() as u64);

    let analyzer = tinkerspark_format_ssh::SshAnalyzer;
    assert_eq!(
        analyzer.can_analyze(&handle, &src),
        AnalyzerConfidence::High
    );

    let report = analyzer.analyze(&handle, &src).unwrap();
    assert_eq!(report.analyzer_id, "ssh");
    assert!(!report.root_nodes.is_empty());

    let root = &report.root_nodes[0];
    assert_eq!(root.kind, "ssh_private_key");

    // Should have child nodes for the binary container.
    let child_kinds: Vec<&str> = root.children.iter().map(|c| c.kind.as_str()).collect();

    assert!(
        child_kinds.contains(&"ssh_magic"),
        "should have auth magic node"
    );
    assert!(
        child_kinds.contains(&"ssh_cipher"),
        "should have cipher node"
    );
    assert!(child_kinds.contains(&"ssh_kdf"), "should have kdf node");
    assert!(
        child_kinds.contains(&"ssh_nkeys"),
        "should have key count node"
    );
    assert!(
        child_kinds.contains(&"ssh_public_key_blob"),
        "should have public key blob"
    );
    assert!(
        child_kinds.contains(&"ssh_private_unencrypted"),
        "should have unencrypted private section"
    );

    // The unencrypted private section should have check ints and key entries.
    let priv_section = root
        .children
        .iter()
        .find(|c| c.kind == "ssh_private_unencrypted")
        .unwrap();
    let priv_kinds: Vec<&str> = priv_section
        .children
        .iter()
        .map(|c| c.kind.as_str())
        .collect();
    assert!(
        priv_kinds.iter().filter(|&&k| k == "ssh_checkint").count() == 2,
        "should have two check int nodes"
    );
    assert!(
        priv_kinds.contains(&"ssh_private_key_entry"),
        "should have key entry"
    );

    // Key entry should have keytype and comment.
    let key_entry = priv_section
        .children
        .iter()
        .find(|c| c.kind == "ssh_private_key_entry")
        .unwrap();
    assert!(key_entry
        .fields
        .iter()
        .any(|f| f.name == "Algorithm" && f.value == "ssh-ed25519"));
    assert!(key_entry
        .fields
        .iter()
        .any(|f| f.name == "Comment" && f.value == "test@tinkerspark"));

    // Ed25519 key entry should have algorithm-specific child nodes.
    let entry_kinds: Vec<&str> = key_entry.children.iter().map(|c| c.kind.as_str()).collect();
    assert!(
        entry_kinds.contains(&"ssh_ed25519_pubkey"),
        "should have Ed25519 public key node, got: {:?}",
        entry_kinds
    );
    assert!(
        entry_kinds.contains(&"ssh_ed25519_private"),
        "should have Ed25519 private material node"
    );
    assert!(
        entry_kinds.contains(&"ssh_comment"),
        "should have comment node"
    );

    // Ed25519 public key should be 32 bytes.
    let pk_node = key_entry
        .children
        .iter()
        .find(|c| c.kind == "ssh_ed25519_pubkey")
        .unwrap();
    assert!(pk_node.label.contains("32 bytes"));
    assert!(!pk_node.range.is_empty());

    // Ed25519 private material should be 64 bytes.
    let priv_node = key_entry
        .children
        .iter()
        .find(|c| c.kind == "ssh_ed25519_private")
        .unwrap();
    assert!(priv_node.label.contains("64 bytes"));
    assert!(!priv_node.range.is_empty());

    // Root should report unencrypted.
    assert!(root
        .fields
        .iter()
        .any(|f| f.name == "Encrypted" && f.value == "No"));

    // Should have fingerprint from ssh-key crate.
    assert!(root
        .fields
        .iter()
        .any(|f| f.name == "Fingerprint (SHA-256)"));

    // All child nodes should have non-empty ranges.
    for child in &root.children {
        assert!(
            !child.range.is_empty(),
            "child '{}' should have non-empty range",
            child.label
        );
    }
}

// ── Encrypted private key ──

#[test]
fn parses_encrypted_ed25519_private_key() {
    let data = std::fs::read("../../testdata/ssh/id_ed25519_encrypted").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::SshPrivateKey, data.len() as u64);

    let analyzer = tinkerspark_format_ssh::SshAnalyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();
    let root = &report.root_nodes[0];

    // Should have container metadata.
    let child_kinds: Vec<&str> = root.children.iter().map(|c| c.kind.as_str()).collect();
    assert!(child_kinds.contains(&"ssh_magic"));
    assert!(child_kinds.contains(&"ssh_cipher"));
    assert!(child_kinds.contains(&"ssh_private_encrypted"));

    // Should report encrypted.
    assert!(root
        .fields
        .iter()
        .any(|f| f.name == "Encrypted" && f.value == "Yes"));

    // Cipher should not be "none".
    let cipher_field = root.fields.iter().find(|f| f.name == "Cipher").unwrap();
    assert_ne!(cipher_field.value, "none");

    // Encrypted section should have diagnostic about decryption.
    let enc_section = root
        .children
        .iter()
        .find(|c| c.kind == "ssh_private_encrypted")
        .unwrap();
    assert!(enc_section
        .diagnostics
        .iter()
        .any(|d| d.message.contains("encrypted")));
}

// ── Malformed / truncated key ──

#[test]
fn truncated_key_fails_gracefully() {
    let data = std::fs::read("../../testdata/ssh/truncated_key.pem").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::SshPrivateKey, data.len() as u64);

    let analyzer = tinkerspark_format_ssh::SshAnalyzer;
    let result = analyzer.analyze(&handle, &src);
    // Should fail with a parse error, not panic.
    assert!(result.is_err(), "truncated key should fail gracefully");
}

#[test]
fn garbage_data_fails_gracefully() {
    let data = b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
    let src = MemoryByteSource::new(data.to_vec());
    let handle = make_handle(DetectedKind::SshPrivateKey, data.len() as u64);

    let analyzer = tinkerspark_format_ssh::SshAnalyzer;
    let result = analyzer.analyze(&handle, &src);
    assert!(result.is_err(), "garbage key should fail gracefully");
}

// ── RSA private key ──

#[test]
fn parses_rsa_private_key_fields() {
    let data = std::fs::read("../../testdata/ssh/id_rsa_unencrypted").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::SshPrivateKey, data.len() as u64);

    let analyzer = tinkerspark_format_ssh::SshAnalyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();
    let root = &report.root_nodes[0];
    assert_eq!(root.kind, "ssh_private_key");

    let priv_section = root
        .children
        .iter()
        .find(|c| c.kind == "ssh_private_unencrypted")
        .unwrap();

    let key_entry = priv_section
        .children
        .iter()
        .find(|c| c.kind == "ssh_private_key_entry")
        .unwrap();

    assert!(key_entry
        .fields
        .iter()
        .any(|f| f.name == "Algorithm" && f.value == "ssh-rsa"));
    assert!(key_entry
        .fields
        .iter()
        .any(|f| f.name == "Comment" && f.value == "rsa@tinkerspark"));

    // RSA key entry should have algorithm-specific child nodes.
    let entry_kinds: Vec<&str> = key_entry.children.iter().map(|c| c.kind.as_str()).collect();
    assert!(
        entry_kinds.contains(&"ssh_rsa_n"),
        "should have modulus node"
    );
    assert!(
        entry_kinds.contains(&"ssh_rsa_e"),
        "should have public exponent node"
    );
    assert!(
        entry_kinds.contains(&"ssh_rsa_d"),
        "should have private exponent node"
    );
    assert!(
        entry_kinds.contains(&"ssh_rsa_iqmp"),
        "should have CRT coefficient node"
    );
    assert!(
        entry_kinds.contains(&"ssh_rsa_p"),
        "should have prime p node"
    );
    assert!(
        entry_kinds.contains(&"ssh_rsa_q"),
        "should have prime q node"
    );
    assert!(
        entry_kinds.contains(&"ssh_comment"),
        "should have comment node"
    );

    // All RSA field nodes should have non-empty ranges.
    for child in &key_entry.children {
        assert!(
            !child.range.is_empty(),
            "RSA child '{}' should have non-empty range",
            child.label
        );
    }
}

// ── ECDSA private key ──

#[test]
fn parses_ecdsa_private_key_fields() {
    let data = std::fs::read("../../testdata/ssh/id_ecdsa_unencrypted").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::SshPrivateKey, data.len() as u64);

    let analyzer = tinkerspark_format_ssh::SshAnalyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();
    let root = &report.root_nodes[0];
    assert_eq!(root.kind, "ssh_private_key");

    let priv_section = root
        .children
        .iter()
        .find(|c| c.kind == "ssh_private_unencrypted")
        .unwrap();

    let key_entry = priv_section
        .children
        .iter()
        .find(|c| c.kind == "ssh_private_key_entry")
        .unwrap();

    assert!(key_entry
        .fields
        .iter()
        .any(|f| f.name == "Algorithm" && f.value.starts_with("ecdsa-sha2-")));
    assert!(key_entry
        .fields
        .iter()
        .any(|f| f.name == "Comment" && f.value == "ecdsa@tinkerspark"));

    // ECDSA key entry should have algorithm-specific child nodes.
    let entry_kinds: Vec<&str> = key_entry.children.iter().map(|c| c.kind.as_str()).collect();
    assert!(
        entry_kinds.contains(&"ssh_ecdsa_curve"),
        "should have curve node"
    );
    assert!(
        entry_kinds.contains(&"ssh_ecdsa_pubkey"),
        "should have ECDSA public key node"
    );
    assert!(
        entry_kinds.contains(&"ssh_ecdsa_privkey"),
        "should have ECDSA private scalar node"
    );
    assert!(
        entry_kinds.contains(&"ssh_comment"),
        "should have comment node"
    );

    // All ECDSA field nodes should have non-empty ranges.
    for child in &key_entry.children {
        assert!(
            !child.range.is_empty(),
            "ECDSA child '{}' should have non-empty range",
            child.label
        );
    }
}

// ── Public key fixture ──

#[test]
fn parses_public_key_fixture() {
    let data = std::fs::read("../../testdata/ssh/id_ed25519.pub").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::SshPublicKey, data.len() as u64);

    let analyzer = tinkerspark_format_ssh::SshAnalyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();
    let root = &report.root_nodes[0];
    assert_eq!(root.kind, "ssh_public_key");
    assert!(root
        .fields
        .iter()
        .any(|f| f.name == "Algorithm" && f.value == "ssh-ed25519"));
}
