// Integration tests for the OpenPGP analyzer using testdata fixtures.

use std::path::Path;
use tinkerspark_core_analyze::Analyzer;
use tinkerspark_core_bytes::open_file;
use tinkerspark_format_openpgp::OpenPgpAnalyzer;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/openpgp")
        .join(name)
}

fn analyze_fixture(name: &str) -> tinkerspark_core_analyze::AnalysisReport {
    let path = fixture_path(name);
    let (source, handle, _) =
        open_file(&path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    let analyzer = OpenPgpAnalyzer;
    analyzer
        .analyze(&handle, &*source)
        .unwrap_or_else(|e| panic!("analyze {name}: {e}"))
}

#[test]
fn multi_packet_binary() {
    let report = analyze_fixture("multi-packet.bin");
    assert_eq!(report.analyzer_id, "openpgp");
    assert_eq!(report.root_nodes.len(), 3);

    // First packet: Public Key.
    assert!(report.root_nodes[0].label.contains("Public"));

    // Second: UserID.
    let uid_node = &report.root_nodes[1];
    assert!(uid_node.label.contains("User ID"));
    let uid_field = uid_node
        .fields
        .iter()
        .find(|f| f.name == "User ID")
        .expect("should have User ID field");
    assert!(uid_field.value.contains("test@example.com"));

    // Third: Signature.
    assert!(report.root_nodes[2].label.contains("Signature"));

    // Each node should have a non-zero byte range.
    for node in &report.root_nodes {
        assert!(
            node.range.length() > 0,
            "node {} has empty range",
            node.label
        );
    }

    // Byte ranges should be non-overlapping and sequential.
    for i in 1..report.root_nodes.len() {
        let prev_end = report.root_nodes[i - 1].range.end();
        let curr_start = report.root_nodes[i].range.offset();
        assert!(
            curr_start >= prev_end,
            "overlapping ranges: packet {} ends at {}, packet {} starts at {}",
            i,
            prev_end,
            i + 1,
            curr_start,
        );
    }
}

#[test]
fn single_pubkey_new_format() {
    let report = analyze_fixture("single-pubkey.bin");
    assert_eq!(report.root_nodes.len(), 1);

    // Should have at least a Tag field and byte range fields.
    let node = &report.root_nodes[0];
    let has_tag = node.fields.iter().any(|f| f.name == "Tag");
    let has_header = node.fields.iter().any(|f| f.name == "Header");
    assert!(has_tag || has_header, "should have basic fields");
    assert!(node.range.length() > 0, "should have non-zero byte range");
}

#[test]
fn armored_file() {
    let report = analyze_fixture("multi-packet-armored.asc");
    // Should successfully dearmor and parse.
    assert_eq!(report.root_nodes.len(), 3);

    // Should have armor info diagnostic.
    let has_armor_note = report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("ASCII-armored"));
    assert!(has_armor_note, "should note that file is armored");
}

#[test]
fn unknown_tag() {
    let report = analyze_fixture("unknown-tag.bin");
    // Should have at least 1 node from boundary-only analysis.
    assert!(
        !report.root_nodes.is_empty(),
        "should find at least one packet boundary"
    );

    // Should have a diagnostic about the parser failing or unknown tag.
    let has_diag = !report.diagnostics.is_empty()
        || report.root_nodes.iter().any(|n| !n.diagnostics.is_empty());
    assert!(has_diag, "should have diagnostics for unusual packet");
}

#[test]
fn can_analyze_detection() {
    use tinkerspark_core_analyze::AnalyzerConfidence;

    let analyzer = OpenPgpAnalyzer;

    // Binary OpenPGP.
    let path = fixture_path("multi-packet.bin");
    let (source, handle, _) = open_file(&path).unwrap();
    assert!(analyzer.can_analyze(&handle, &*source) >= AnalyzerConfidence::Medium);

    // Armored OpenPGP.
    let path = fixture_path("multi-packet-armored.asc");
    let (source, handle, _) = open_file(&path).unwrap();
    assert!(analyzer.can_analyze(&handle, &*source) >= AnalyzerConfidence::Medium);
}
