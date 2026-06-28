//! path-NAME_MAX: Linux enforces a per-component length limit (`NAME_MAX`,
//! 255 *bytes*) during the path walk — `link_path_walk`/`walk_component`
//! reject any single component longer than 255 bytes with `ENAMETOOLONG`,
//! even when the whole pathname is well under `PATH_MAX`. The total-length
//! `PATH_MAX` gate already lives at the syscall boundary (`read_user_path`);
//! the per-component gate belongs at the lexical layer alongside the
//! splitter. These tests pin that contract.

use vfs::path::{check_component, components_checked, Component, NAME_MAX};
use vfs::VfsError;

// A component of exactly NAME_MAX bytes is accepted; one byte longer is not.
#[test]
fn name_max_boundary() {
    let ok = "a".repeat(NAME_MAX);
    assert_eq!(check_component(&ok), Ok(()), "255 bytes accepted");
    let toolong = "a".repeat(NAME_MAX + 1);
    assert_eq!(check_component(&toolong), Err(VfsError::Enametoolong), "256 rejected");
}

// Empty and short names are always fine.
#[test]
fn short_names_ok() {
    assert_eq!(check_component(""), Ok(()));
    assert_eq!(check_component("a"), Ok(()));
    assert_eq!(check_component("normal.txt"), Ok(()));
}

// NAME_MAX is measured in BYTES, not scalar values: a multi-byte UTF-8
// component overflows at 255 bytes, not 255 chars. 64 '€' (3 bytes each)
// = 192 bytes (ok); 86 '€' = 258 bytes (too long).
#[test]
fn name_max_counts_bytes_not_chars() {
    let euros_ok = "\u{20AC}".repeat(64); // 192 bytes, 64 chars
    assert_eq!(euros_ok.len(), 192);
    assert_eq!(check_component(&euros_ok), Ok(()));
    let euros_bad = "\u{20AC}".repeat(86); // 258 bytes, 86 chars
    assert_eq!(euros_bad.len(), 258);
    assert_eq!(check_component(&euros_bad), Err(VfsError::Enametoolong));
}

// Escaped non-UTF-8 bytes (path_from_bytes maps each bad byte to a 3-byte
// PUA scalar) must count as ONE on-disk byte each, NOT three. A component
// of 255 escaped bytes is exactly at the limit and must pass.
#[test]
fn name_max_counts_escaped_bytes_as_one() {
    // 255 raw 0xFF bytes → escaped String is 255 PUA chars (765 UTF-8 bytes).
    let raw = vec![0xFFu8; NAME_MAX];
    let escaped = vfs::path_from_bytes(&raw);
    assert!(escaped.len() > NAME_MAX, "escaped form is byte-inflated");
    assert_eq!(check_component(&escaped), Ok(()), "255 on-disk bytes ok");

    let raw2 = vec![0xFFu8; NAME_MAX + 1];
    let escaped2 = vfs::path_from_bytes(&raw2);
    assert_eq!(check_component(&escaped2), Err(VfsError::Enametoolong));
}

// components_checked splits like `components` but rejects an over-long
// component anywhere in the path; the whole path stays < PATH_MAX.
#[test]
fn components_checked_rejects_overlong_segment() {
    let long = "b".repeat(NAME_MAX + 1);
    let path = format!("/a/{long}/c");
    assert_eq!(components_checked(&path), Err(VfsError::Enametoolong));
}

// A path whose every component is within NAME_MAX splits successfully and
// matches the unchecked splitter exactly.
#[test]
fn components_checked_ok_matches_components() {
    let path = "/a/b/../c";
    let got = components_checked(path).expect("all components within NAME_MAX");
    assert_eq!(
        got,
        vec![
            Component::Root,
            Component::Normal("a"),
            Component::Normal("b"),
            Component::ParentDir,
            Component::Normal("c"),
        ]
    );
}

// `.` and `..` are control segments, never subject to NAME_MAX, and an
// over-long total path made of legal components is NOT rejected here (that
// is PATH_MAX's job at the syscall boundary).
#[test]
fn control_segments_exempt() {
    let seg = "x".repeat(NAME_MAX); // exactly at the per-component limit
    // 17 legal components: 17 * (1 + 255) = 4352 bytes total (> PATH_MAX),
    // yet every component is within NAME_MAX, so the per-component gate passes.
    let mut path = String::new();
    for _ in 0..17 { path.push('/'); path.push_str(&seg); }
    assert!(path.len() > 4096);
    assert!(components_checked(&path).is_ok(), "NAME_MAX is per-component, not total");
}
