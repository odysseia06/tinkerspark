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

// ── authorized_keys (issue #4) ──

#[test]
fn parses_authorized_keys_fixture() {
    let data = std::fs::read("../../testdata/ssh/authorized_keys").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::SshAuthorizedKeys, data.len() as u64);

    let analyzer = tinkerspark_format_ssh::SshAnalyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();
    let root = &report.root_nodes[0];
    assert_eq!(root.kind, "ssh_authorized_keys");
    assert_eq!(root.range.offset(), 0);
    assert_eq!(root.range.length(), data.len() as u64);

    // Three well-formed entries (the malformed one becomes a diagnostic).
    assert_eq!(
        root.children.len(),
        3,
        "expected 3 entries; got: {:?}",
        root.children.iter().map(|c| &c.label).collect::<Vec<_>>()
    );
    for entry in &root.children {
        assert_eq!(entry.kind, "ssh_authorized_key_entry");
        assert!(!entry.range.is_empty());
        assert!(entry.fields.iter().any(|f| f.name == "Key Type"));
        assert!(entry.fields.iter().any(|f| f.name == "Key Data (base64)"));
    }

    // Entry 0: plain ed25519, no options.
    let alice = &root.children[0];
    assert!(alice
        .fields
        .iter()
        .any(|f| f.name == "Key Type" && f.value == "ssh-ed25519"));
    assert!(!alice.fields.iter().any(|f| f.name == "Options"));
    assert!(alice
        .fields
        .iter()
        .any(|f| f.name == "Comment" && f.value == "alice@example.com"));

    // Entry 1: ssh-rsa with options.
    let bob = &root.children[1];
    let bob_options = bob.fields.iter().find(|f| f.name == "Options").unwrap();
    assert!(bob_options.value.contains("no-port-forwarding"));
    assert!(bob_options.value.contains("from=\"10.0.0.1\""));
    assert!(bob
        .fields
        .iter()
        .any(|f| f.name == "Key Type" && f.value == "ssh-rsa"));

    // Entry 2: options containing a quoted space (`command="echo hello world"`)
    // — exercises the quote-aware options-end finder.
    let carol = &root.children[2];
    let carol_opts = carol.fields.iter().find(|f| f.name == "Options").unwrap();
    assert!(
        carol_opts.value.contains("echo hello world"),
        "options should preserve the full quoted string; got: {:?}",
        carol_opts.value
    );
    assert!(carol
        .fields
        .iter()
        .any(|f| f.name == "Key Type" && f.value == "ssh-ed25519"));

    // Sibling entries must have distinct byte ranges.
    let mut offsets: Vec<u64> = root.children.iter().map(|c| c.range.offset()).collect();
    offsets.sort_unstable();
    offsets.dedup();
    assert_eq!(offsets.len(), root.children.len());

    // The malformed line should produce a diagnostic, not crash the parse.
    assert!(
        root.diagnostics
            .iter()
            .any(|d| d.message.contains("not-a-real-algorithm")
                || d.message.contains("unrecognized")
                || d.message.contains("authorized_keys")),
        "expected a diagnostic for the malformed entry; got: {:?}",
        root.diagnostics
    );
}

// ── known_hosts (issue #4) ──

#[test]
fn parses_known_hosts_fixture() {
    let data = std::fs::read("../../testdata/ssh/known_hosts").unwrap();
    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::SshKnownHosts, data.len() as u64);

    let analyzer = tinkerspark_format_ssh::SshAnalyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();
    let root = &report.root_nodes[0];
    assert_eq!(root.kind, "ssh_known_hosts");
    assert_eq!(root.range.offset(), 0);
    assert_eq!(root.range.length(), data.len() as u64);

    // Three well-formed entries (the malformed one becomes a diagnostic).
    assert_eq!(
        root.children.len(),
        3,
        "expected 3 entries; got: {:?}",
        root.children.iter().map(|c| &c.label).collect::<Vec<_>>()
    );
    for entry in &root.children {
        assert_eq!(entry.kind, "ssh_known_host_entry");
        assert!(!entry.range.is_empty());
        assert!(entry.fields.iter().any(|f| f.name == "Hostnames"));
        assert!(entry.fields.iter().any(|f| f.name == "Key Type"));
        assert!(entry.fields.iter().any(|f| f.name == "Hashed"));
    }

    // Entry 0: github.com plain.
    let github = &root.children[0];
    assert!(github
        .fields
        .iter()
        .any(|f| f.name == "Hostnames" && f.value.contains("github.com")));
    assert!(github
        .fields
        .iter()
        .any(|f| f.name == "Hashed" && f.value == "No"));
    assert!(github
        .fields
        .iter()
        .any(|f| f.name == "Key Type" && f.value == "ssh-ed25519"));

    // Entry 1: hashed.
    let hashed = &root.children[1];
    assert!(hashed
        .fields
        .iter()
        .any(|f| f.name == "Hashed" && f.value == "Yes"));
    let host_field = hashed
        .fields
        .iter()
        .find(|f| f.name == "Hostnames")
        .unwrap();
    assert_eq!(host_field.value, "<hashed host>");
    assert!(hashed
        .fields
        .iter()
        .any(|f| f.name == "Key Type" && f.value == "ssh-rsa"));

    // Entry 2: marker @cert-authority.
    let ca = &root.children[2];
    assert!(ca
        .fields
        .iter()
        .any(|f| f.name == "Marker" && f.value == "@cert-authority"));
    assert!(ca
        .fields
        .iter()
        .any(|f| f.name == "Hostnames" && f.value.contains("*.example.com")));

    // Sibling entries must have distinct byte ranges.
    let mut offsets: Vec<u64> = root.children.iter().map(|c| c.range.offset()).collect();
    offsets.sort_unstable();
    offsets.dedup();
    assert_eq!(offsets.len(), root.children.len());

    // Malformed line should produce a diagnostic.
    assert!(
        root.diagnostics
            .iter()
            .any(|d| d.message.contains("bogus-algo") || d.message.contains("unrecognized")),
        "expected a diagnostic for the malformed entry; got: {:?}",
        root.diagnostics
    );
}

#[test]
fn authorized_keys_invalid_utf8_line_is_surfaced_as_diagnostic() {
    // One valid entry, one line with stray invalid UTF-8 bytes, one more
    // valid entry. The invalid line must NOT silently disappear — it must
    // produce a warning diagnostic with its byte range, and the surrounding
    // entries must still parse correctly.
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(
        b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl alice@example.com\n",
    );
    let invalid_start = data.len() as u64;
    // 0xFF / 0xFE / 0xFC are all invalid UTF-8 leading bytes.
    let invalid_line: &[u8] = &[0xFF, 0xFE, 0xFC, 0x80, 0x81, 0x82];
    data.extend_from_slice(invalid_line);
    data.push(b'\n');
    let invalid_len = invalid_line.len() as u64;
    data.extend_from_slice(
        b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfakeRSAblob== bob@example.com\n",
    );

    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::SshAuthorizedKeys, data.len() as u64);
    let analyzer = tinkerspark_format_ssh::SshAnalyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();
    let root = &report.root_nodes[0];
    assert_eq!(root.kind, "ssh_authorized_keys");

    // Both valid entries must still parse.
    assert_eq!(
        root.children.len(),
        2,
        "expected 2 valid entries; got: {:?}",
        root.children.iter().map(|c| &c.label).collect::<Vec<_>>()
    );
    assert!(root.children[0]
        .fields
        .iter()
        .any(|f| f.name == "Comment" && f.value == "alice@example.com"));
    assert!(root.children[1]
        .fields
        .iter()
        .any(|f| f.name == "Comment" && f.value == "bob@example.com"));

    // The invalid line must produce a Warning diagnostic with the exact
    // byte range of the bad bytes.
    let diag = root
        .diagnostics
        .iter()
        .find(|d| d.message.contains("not valid UTF-8"))
        .expect("expected a UTF-8 warning diagnostic");
    let range = diag
        .range
        .expect("UTF-8 diagnostic should carry its byte range");
    assert_eq!(range.offset(), invalid_start);
    assert_eq!(range.length(), invalid_len);
}

#[test]
fn known_hosts_invalid_utf8_line_is_surfaced_as_diagnostic() {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(
        b"github.com,140.82.114.4 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
    );
    let invalid_start = data.len() as u64;
    let invalid_line: &[u8] = &[0xFF, 0xFE, 0x80, 0x81];
    data.extend_from_slice(invalid_line);
    data.push(b'\n');
    let invalid_len = invalid_line.len() as u64;
    data.extend_from_slice(
        b"|1|F1E1f8gPzg5VrIWJzNCJjQjFKBQ=|N4i7zd0EIuTakvAlk5gIVtPP4lk= ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfakeRSAblob==\n",
    );

    let src = MemoryByteSource::new(data.clone());
    let handle = make_handle(DetectedKind::SshKnownHosts, data.len() as u64);
    let analyzer = tinkerspark_format_ssh::SshAnalyzer;
    let report = analyzer.analyze(&handle, &src).unwrap();
    let root = &report.root_nodes[0];
    assert_eq!(root.kind, "ssh_known_hosts");

    // Both valid entries (plain + hashed) must still parse.
    assert_eq!(root.children.len(), 2);
    assert!(root.children[0]
        .fields
        .iter()
        .any(|f| f.name == "Hostnames" && f.value.contains("github.com")));
    assert!(root.children[1]
        .fields
        .iter()
        .any(|f| f.name == "Hashed" && f.value == "Yes"));

    let diag = root
        .diagnostics
        .iter()
        .find(|d| d.message.contains("not valid UTF-8"))
        .expect("expected a UTF-8 warning diagnostic");
    let range = diag
        .range
        .expect("UTF-8 diagnostic should carry its byte range");
    assert_eq!(range.offset(), invalid_start);
    assert_eq!(range.length(), invalid_len);
}

#[test]
fn analyzer_claims_authorized_keys_and_known_hosts_kinds() {
    let analyzer = tinkerspark_format_ssh::SshAnalyzer;
    let src = MemoryByteSource::new(vec![0]);
    let auth_handle = make_handle(DetectedKind::SshAuthorizedKeys, 1);
    let known_handle = make_handle(DetectedKind::SshKnownHosts, 1);
    assert_eq!(
        analyzer.can_analyze(&auth_handle, &src),
        AnalyzerConfidence::High
    );
    assert_eq!(
        analyzer.can_analyze(&known_handle, &src),
        AnalyzerConfidence::High
    );
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
