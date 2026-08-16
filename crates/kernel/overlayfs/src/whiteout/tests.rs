//! Recognising a whiteout, in both forms, over real layer objects.

extern crate alloc;

use alloc::vec;
use vfs::inode_ops::CreateCtx;
use vfs::types::{S_IFCHR, S_IFREG};

use crate::config::Config;
use crate::marker;
use crate::testfs::{layer, mkfile};
use crate::uapi::{Marker, MARKER_YES, WHITEOUT_RDEV};

use super::{is_device, is_impure, is_marked, is_opaque, is_whiteout, opacity, Opacity};

#[test]
fn a_zero_device_character_node_is_a_whiteout() {
    let root = layer(1);
    root.mknod_child("gone", S_IFCHR, WHITEOUT_RDEV, &CreateCtx::root()).unwrap();
    let w = root.lookup("gone").unwrap();
    assert!(is_device(&w));
    assert!(is_whiteout(&Config::default(), &w, false));
}

#[test]
fn a_real_character_device_is_not() {
    let root = layer(1);
    root.mknod_child("tty", S_IFCHR, 0x0501, &CreateCtx::root()).unwrap();
    let d = root.lookup("tty").unwrap();
    assert!(!is_device(&d));
    assert!(!is_whiteout(&Config::default(), &d, true));
}

#[test]
fn a_regular_file_is_not_a_whiteout_however_empty() {
    let root = layer(1);
    let f = mkfile(&root, "empty", b"");
    assert!(!is_whiteout(&Config::default(), &f, true));
}

#[test]
fn an_empty_file_carrying_the_marker_is_one() {
    let c = Config::default();
    let root = layer(1);
    let f = mkfile(&root, "gone", b"");
    marker::set_yes(&c, &f, Marker::Xwhiteout, syscall::errno::Errno::Eio).unwrap();
    assert!(is_marked(&c, &f));
    assert!(is_whiteout(&c, &f, true));
}

#[test]
fn a_file_with_contents_carrying_the_marker_is_not() {
    // Hiding it would lose a real file, and everything below it, to an
    // attribute its owner is allowed to set.
    let c = Config::default();
    let root = layer(1);
    let f = mkfile(&root, "real", b"contents");
    marker::set_yes(&c, &f, Marker::Xwhiteout, syscall::errno::Errno::Eio).unwrap();
    assert!(!is_marked(&c, &f));
    assert!(!is_whiteout(&c, &f, true));
}

#[test]
fn the_marker_form_is_only_looked_for_where_one_was_seen() {
    let c = Config::default();
    let root = layer(1);
    let f = mkfile(&root, "gone", b"");
    marker::set_yes(&c, &f, Marker::Xwhiteout, syscall::errno::Errno::Eio).unwrap();
    assert!(!is_whiteout(&c, &f, false));
    assert!(is_whiteout(&c, &f, true));
}

#[test]
fn an_opaque_directory_hides_everything_below_it() {
    let c = Config::default();
    let root = layer(1);
    let d = root.mkdir("d", 0o755, &CreateCtx::root()).unwrap();
    assert_eq!(opacity(&c, &d), Opacity::Merge);
    marker::set(&c, &d, Marker::Opaque, MARKER_YES, syscall::errno::Errno::Eio).unwrap();
    assert_eq!(opacity(&c, &d), Opacity::Opaque);
    assert!(is_opaque(&c, &d));
}

#[test]
fn the_x_value_means_marked_whiteouts_not_opacity() {
    let c = Config::default();
    let root = layer(1);
    let d = root.mkdir("d", 0o755, &CreateCtx::root()).unwrap();
    marker::set(&c, &d, Marker::Opaque, b"x", syscall::errno::Errno::Eio).unwrap();
    assert_eq!(opacity(&c, &d), Opacity::MarkedWhiteouts);
    assert!(!is_opaque(&c, &d));
}

#[test]
fn any_other_value_merges() {
    let c = Config::default();
    let root = layer(1);
    let d = root.mkdir("d", 0o755, &CreateCtx::root()).unwrap();
    marker::set(&c, &d, Marker::Opaque, b"n", syscall::errno::Errno::Eio).unwrap();
    assert_eq!(opacity(&c, &d), Opacity::Merge);
    marker::set(&c, &d, Marker::Opaque, b"yes", syscall::errno::Errno::Eio).unwrap();
    assert_eq!(opacity(&c, &d), Opacity::Merge);
}

#[test]
fn a_marker_on_a_file_is_not_read_as_a_directory_marker() {
    let c = Config::default();
    let root = layer(1);
    let f = mkfile(&root, "f", b"x");
    marker::set(&c, &f, Marker::Opaque, MARKER_YES, syscall::errno::Errno::Eio).unwrap();
    assert!(!is_opaque(&c, &f));
}

#[test]
fn the_impure_marker_is_read_the_same_way() {
    let c = Config::default();
    let root = layer(1);
    let d = root.mkdir("d", 0o755, &CreateCtx::root()).unwrap();
    assert!(!is_impure(&c, &d));
    marker::set_yes(&c, &d, Marker::Impure, syscall::errno::Errno::Eio).unwrap();
    assert!(is_impure(&c, &d));
}

#[test]
fn the_unprivileged_namespace_reads_its_own_markers_only() {
    let trusted = Config::default();
    let user = Config { userxattr: true, ..Config::default() };
    let root = layer(1);
    let d = root.mkdir("d", 0o755, &CreateCtx::root()).unwrap();
    marker::set(&trusted, &d, Marker::Opaque, MARKER_YES, syscall::errno::Errno::Eio).unwrap();
    assert!(is_opaque(&trusted, &d));
    assert!(!is_opaque(&user, &d));
}

#[test]
fn a_removed_marker_stops_being_read() {
    let c = Config::default();
    let root = layer(1);
    let d = root.mkdir("d", 0o755, &CreateCtx::root()).unwrap();
    marker::set_yes(&c, &d, Marker::Opaque, syscall::errno::Errno::Eio).unwrap();
    marker::remove(&c, &d, Marker::Opaque).unwrap();
    assert!(!is_opaque(&c, &d));
    // Removing one that is not there is the same end state, not a failure.
    marker::remove(&c, &d, Marker::Opaque).unwrap();
}

#[test]
fn a_marker_value_survives_a_round_trip() {
    let c = Config::default();
    let root = layer(1);
    let f = mkfile(&root, "f", b"");
    marker::set(&c, &f, Marker::Redirect, b"/some/where", syscall::errno::Errno::Eio).unwrap();
    assert_eq!(marker::get(&c, &f, Marker::Redirect), Some(vec![b'/', b's', b'o', b'm', b'e',
                                                                b'/', b'w', b'h', b'e', b'r', b'e']));
    let _ = S_IFREG;
}
