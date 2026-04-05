// Integration tests using testdata/diff fixtures.

use std::path::Path;
use tinkerspark_core_bytes::open_file;
use tinkerspark_core_diff::{compute_diff, DiffConfig};

fn diff_fixtures(
    name: &str,
) -> (
    Box<dyn tinkerspark_core_bytes::ByteSource>,
    Box<dyn tinkerspark_core_bytes::ByteSource>,
) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/diff");
    let left_path = base.join(format!("{name}-left.bin"));
    let right_path = base.join(format!("{name}-right.bin"));
    let (left, _, _) =
        open_file(&left_path).unwrap_or_else(|e| panic!("open {}: {e}", left_path.display()));
    let (right, _, _) =
        open_file(&right_path).unwrap_or_else(|e| panic!("open {}: {e}", right_path.display()));
    (left, right)
}

#[test]
fn identical_files() {
    let (left, right) = diff_fixtures("identical");
    let result = compute_diff(&*left, &*right, &DiffConfig::default()).unwrap();
    assert!(result.is_identical());
    assert_eq!(result.left_len, 256);
    assert_eq!(result.right_len, 256);
}

#[test]
fn single_byte_change() {
    let (left, right) = diff_fixtures("single-change");
    let result = compute_diff(&*left, &*right, &DiffConfig::default()).unwrap();
    assert_eq!(result.change_count(), 1);
    assert_eq!(result.changes[0].left.offset(), 0x40);
    assert_eq!(result.changes[0].left.length(), 1);
}

#[test]
fn scattered_changes() {
    let (left, right) = diff_fixtures("scattered");
    let result = compute_diff(&*left, &*right, &DiffConfig::default()).unwrap();
    assert_eq!(result.change_count(), 3);
    assert_eq!(result.changes[0].left.offset(), 0x10);
    assert_eq!(result.changes[1].left.offset(), 0x50);
    assert_eq!(result.changes[2].left.offset(), 0xA0);
}

#[test]
fn block_change() {
    let (left, right) = diff_fixtures("block-change");
    let result = compute_diff(&*left, &*right, &DiffConfig::default()).unwrap();
    assert_eq!(result.change_count(), 1);
    assert_eq!(result.changes[0].left.offset(), 0x30);
    assert_eq!(result.changes[0].left.length(), 16);
}

#[test]
fn right_longer() {
    let (left, right) = diff_fixtures("right-longer");
    let result = compute_diff(&*left, &*right, &DiffConfig::default()).unwrap();
    assert_eq!(result.change_count(), 1);
    assert_eq!(result.left_len, 256);
    assert_eq!(result.right_len, 288);
    // Trailing range: left has 0 extra bytes, right has 32.
    assert_eq!(result.changes[0].left.length(), 0);
    assert_eq!(result.changes[0].right.length(), 32);
}

#[test]
fn left_longer() {
    let (left, right) = diff_fixtures("left-longer");
    let result = compute_diff(&*left, &*right, &DiffConfig::default()).unwrap();
    assert_eq!(result.change_count(), 1);
    assert_eq!(result.left_len, 256);
    assert_eq!(result.right_len, 200);
    assert_eq!(result.changes[0].left.length(), 56);
    assert_eq!(result.changes[0].right.length(), 0);
}

#[test]
fn all_different() {
    let (left, right) = diff_fixtures("all-different");
    let result = compute_diff(&*left, &*right, &DiffConfig::default()).unwrap();
    // Should be mostly or entirely changed. The exact count depends on
    // whether any random bytes happen to match, but changed bytes should
    // be the vast majority.
    assert!(result.left_changed_bytes() > 100);
}

#[test]
fn empty_vs_nonempty() {
    let (left, right) = diff_fixtures("empty");
    let result = compute_diff(&*left, &*right, &DiffConfig::default()).unwrap();
    assert_eq!(result.change_count(), 1);
    assert_eq!(result.left_len, 0);
    assert_eq!(result.right_len, 11);
    assert_eq!(result.changes[0].left.length(), 0);
    assert_eq!(result.changes[0].right.length(), 11);
}

#[test]
fn large_file_multi_chunk() {
    let (left, right) = diff_fixtures("large");
    let result = compute_diff(&*left, &*right, &DiffConfig::default()).unwrap();
    assert_eq!(result.left_len, 65536);
    assert_eq!(result.right_len, 65536);
    // 4 change regions of 8 bytes each.
    assert_eq!(result.change_count(), 4);
    assert_eq!(result.changes[0].left.offset(), 1024);
    assert_eq!(result.changes[0].left.length(), 8);
    assert_eq!(result.changes[1].left.offset(), 8192);
    assert_eq!(result.changes[2].left.offset(), 32768);
    assert_eq!(result.changes[3].left.offset(), 61440);
}

#[test]
fn large_file_small_chunks() {
    // Same test but force small chunk size to exercise cross-chunk logic.
    let (left, right) = diff_fixtures("large");
    let config = DiffConfig {
        chunk_size: 1024,
        ..Default::default()
    };
    let result = compute_diff(&*left, &*right, &config).unwrap();
    assert_eq!(result.change_count(), 4);
    assert_eq!(result.changes[0].left.offset(), 1024);
}
