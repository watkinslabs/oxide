//! path-D2: `lexical_normalize` must NOT collapse leading `..` on a
//! RELATIVE path. Linux resolves `..` per-component AFTER mount/symlink
//! crossing against the live tree (`path_resolution(7)`), never lexically,
//! so a relative path's leading `..` must survive normalization for the
//! namei walker to handle. Only interior `name/..` may collapse.
//!
//! Regression: the old `stack.pop().is_none()` logic double-popped — a
//! second `..` removed the `..` pushed by the first, so `../../a`
//! wrongly normalized to `a` (escaping one fewer directory level).

use vfs::path::lexical_normalize;

fn norm(p: &str) -> String { lexical_normalize(p).expect("normalize") }

#[test]
fn leading_dotdot_relative_preserved() {
    // Single leading `..` already worked; pin it.
    assert_eq!(norm(".."), "..");
    assert_eq!(norm("../a"), "../a");
    // The bug: stacked leading `..` collapsed to nothing.
    assert_eq!(norm("../.."), "../..");
    assert_eq!(norm("../../a"), "../../a");
    assert_eq!(norm("../../../x/y"), "../../../x/y");
}

#[test]
fn interior_dotdot_still_collapses() {
    // A `..` AFTER a real name cancels that name lexically.
    assert_eq!(norm("a/../b"), "b");
    assert_eq!(norm("../a/../b"), "../b");
    assert_eq!(norm("a/b/../../c"), "c");
    // name then escape past it leaves a residual leading `..`.
    assert_eq!(norm("a/../../b"), "../b");
    assert_eq!(norm("x/../.."), "..");
}

#[test]
fn dot_segments_and_slashes_normalized() {
    assert_eq!(norm("./../a"), "../a");
    assert_eq!(norm("..//.//../a"), "../../a");
    assert_eq!(norm("../a/."), "../a");
}

#[test]
fn absolute_dotdot_clamps_at_root_unchanged() {
    // Absolute-path semantics must NOT regress: `..` clamps at `/`.
    assert_eq!(norm("/.."), "/");
    assert_eq!(norm("/../../a"), "/a");
    assert_eq!(norm("/a/../../b"), "/b");
    assert_eq!(norm("/a/b/../c"), "/a/c");
}
