//! The merged stream: what appears once, what is hidden, and in what order.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::dirent::DType;
use vfs::inode_ops::CreateCtx;

use crate::config::Config;
use crate::layers::{LayerStack, OvlEntry};
use crate::lookup::lookup;
use crate::marker;
use crate::testfs::{layer, mkfile, mkpath, mkwhiteout, stack};
use crate::uapi::{Marker, MARKER_YES};

use super::{is_empty, merged, visible};

/// The visible names of the merged directory `name`.
fn names(s: &Arc<LayerStack>, root: &OvlEntry, name: &str) -> Vec<String> {
    let e = lookup(s, root, root, name).unwrap().unwrap();
    visible(&merged(s, &e).unwrap()).map(|x| x.name.clone()).collect()
}

/// A sorted copy, for the cases where only membership matters.
fn sorted(mut v: Vec<String>) -> Vec<String> { v.sort(); v }

#[test]
fn a_name_in_two_layers_appears_once() {
    let up = layer(0);
    let lo = layer(1);
    mkfile(&lo, "d/both", b"below");
    mkfile(&up, "d/both", b"above");
    let (s, root) = stack(Config::default(), Some(up), &[lo], &[]);
    assert_eq!(names(&s, &root, "d"), alloc::vec!["both"]);
}

#[test]
fn every_layers_names_appear() {
    let up = layer(0);
    let l1 = layer(1);
    let l2 = layer(2);
    mkfile(&up, "d/u", b"");
    mkfile(&l1, "d/a", b"");
    mkfile(&l2, "d/b", b"");
    let (s, root) = stack(Config::default(), Some(up), &[l1, l2], &[]);
    assert_eq!(sorted(names(&s, &root, "d")), alloc::vec!["a", "b", "u"]);
}

#[test]
fn a_whiteout_hides_the_name_and_does_not_appear_itself() {
    let up = layer(0);
    let lo = layer(1);
    mkfile(&lo, "d/gone", b"");
    mkfile(&lo, "d/keep", b"");
    let ud = mkpath(&up, "d");
    mkwhiteout(&ud, "gone");
    let (s, root) = stack(Config::default(), Some(up), &[lo], &[]);
    assert_eq!(names(&s, &root, "d"), alloc::vec!["keep"]);
}

#[test]
fn a_whiteout_hides_the_name_in_every_layer_below() {
    let up = layer(0);
    let l1 = layer(1);
    let l2 = layer(2);
    mkfile(&l1, "d/gone", b"one");
    mkfile(&l2, "d/gone", b"two");
    mkfile(&l2, "d/keep", b"");
    let ud = mkpath(&up, "d");
    mkwhiteout(&ud, "gone");
    let (s, root) = stack(Config::default(), Some(up), &[l1, l2], &[]);
    assert_eq!(names(&s, &root, "d"), alloc::vec!["keep"]);
}

#[test]
fn a_real_character_device_is_still_listed() {
    let up = layer(0);
    let lo = layer(1);
    let d = mkpath(&lo, "d");
    d.mknod_child("tty", vfs::types::S_IFCHR | 0o600, 0x0501, &CreateCtx::root()).unwrap();
    let (s, root) = stack(Config::default(), Some(up), &[lo], &[]);
    assert_eq!(names(&s, &root, "d"), alloc::vec!["tty"]);
}

#[test]
fn an_opaque_directory_shows_only_its_own_names() {
    let c = Config::default();
    let up = layer(0);
    let lo = layer(1);
    mkfile(&lo, "d/below", b"");
    mkfile(&up, "d/above", b"");
    let d = crate::testfs::lookup(&up, "d").unwrap();
    marker::set(&c, &d, Marker::Opaque, MARKER_YES, syscall::errno::Errno::Eio).unwrap();
    let (s, root) = stack(c, Some(up), &[lo], &[]);
    assert_eq!(names(&s, &root, "d"), alloc::vec!["above"]);
}

#[test]
fn the_bottom_layers_names_come_first_and_keep_their_order() {
    // A copy-up adds a name to the writable layer; nothing already in the
    // bottom layer may move, or a caller resuming from an offset sees an entry
    // twice or misses one.
    let up = layer(0);
    let lo = layer(1);
    mkfile(&lo, "d/a", b"");
    mkfile(&lo, "d/b", b"");
    mkfile(&lo, "d/c", b"");
    let (s, root) = stack(Config::default(), Some(up.clone()), &[lo], &[]);
    let before = names(&s, &root, "d");
    assert_eq!(before, alloc::vec!["a", "b", "c"]);

    // Copy `b` up and add a name that only the writable layer has.
    mkfile(&up, "d/b", b"copied");
    mkfile(&up, "d/zz", b"new");
    let after = names(&s, &root, "d");
    assert_eq!(&after[..3], &before[..], "the bottom layer's order is unchanged");
    assert_eq!(after.last().unwrap(), "zz");
}

#[test]
fn a_directory_holding_only_whiteouts_counts_as_empty() {
    // Otherwise `rm -r` of a directory whose contents were all deleted fails
    // on a directory that looks empty to everything else.
    let up = layer(0);
    let lo = layer(1);
    mkfile(&lo, "d/gone", b"");
    let ud = mkpath(&up, "d");
    mkwhiteout(&ud, "gone");
    let (s, root) = stack(Config::default(), Some(up), &[lo], &[]);
    let e = lookup(&s, &root, &root, "d").unwrap().unwrap();
    assert!(is_empty(&s, &e).unwrap());
    assert_eq!(merged(&s, &e).unwrap().len(), 1, "the whiteout is still there to clean up");
}

#[test]
fn a_directory_with_a_lower_entry_is_not_empty() {
    let up = layer(0);
    let lo = layer(1);
    mkfile(&lo, "d/keep", b"");
    mkpath(&up, "d");
    let (s, root) = stack(Config::default(), Some(up), &[lo], &[]);
    let e = lookup(&s, &root, &root, "d").unwrap().unwrap();
    assert!(!is_empty(&s, &e).unwrap());
}

#[test]
fn the_type_of_each_entry_survives_the_merge() {
    let up = layer(0);
    let lo = layer(1);
    mkfile(&lo, "d/file", b"");
    mkpath(&lo, "d/dir");
    let d = crate::testfs::lookup(&lo, "d").unwrap();
    d.symlink_child("link", b"/t", &CreateCtx::root()).unwrap();
    let (s, root) = stack(Config::default(), Some(up), &[lo], &[]);
    let e = lookup(&s, &root, &root, "d").unwrap().unwrap();
    let list = merged(&s, &e).unwrap();
    let ty = |n: &str| list.iter().find(|x| x.name == n).unwrap().dtype;
    assert_eq!(ty("file"), DType::from_file_type(vfs::types::FileType::Regular));
    assert_eq!(ty("dir"), DType::from_file_type(vfs::types::FileType::Directory));
    assert_eq!(ty("link"), DType::from_file_type(vfs::types::FileType::Symlink));
}

#[test]
fn the_marked_whiteout_form_is_filtered_too() {
    let c = Config::default();
    let up = layer(0);
    let l1 = layer(1);
    let l2 = layer(2);
    let d = mkpath(&l1, "d");
    marker::set(&c, &d, Marker::Opaque, b"x", syscall::errno::Errno::Eio).unwrap();
    let gone = mkfile(&l1, "d/gone", b"");
    marker::set(&c, &gone, Marker::Xwhiteout, MARKER_YES, syscall::errno::Errno::Eio).unwrap();
    mkfile(&l2, "d/gone", b"still here");
    mkfile(&l2, "d/keep", b"");
    let (s, root) = stack(c, Some(up), &[l1, l2], &[]);
    assert_eq!(names(&s, &root, "d"), alloc::vec!["keep"]);
}

#[test]
fn a_lower_only_directory_still_reads() {
    let l1 = layer(1);
    mkfile(&l1, "d/a", b"");
    let (s, root) = stack(Config::default(), None, &[l1], &[]);
    assert_eq!(names(&s, &root, "d"), alloc::vec!["a"]);
}

#[test]
fn a_data_only_layer_contributes_no_names() {
    // Nothing resolves a name into one, so listing its contents would show
    // files that cannot be opened.
    let up = layer(0);
    let l1 = layer(1);
    let d1 = layer(2);
    mkfile(&l1, "d/named", b"");
    mkfile(&d1, "d/hidden", b"");
    let (s, root) = stack(Config::default(), Some(up), &[l1, d1], &[1]);
    assert_eq!(names(&s, &root, "d"), alloc::vec!["named"]);
    let _ = String::new();
}
