//! Walking real layers: what a name resolves to, and what stops the walk.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use syscall::errno::Errno;
use vfs::inode_ops::CreateCtx;
use vfs::InodeRef;

use crate::config::{Config, RedirectMode};
use crate::layers::{LayerStack, OvlEntry};
use crate::marker;
use crate::metacopy::Metacopy;
use crate::testfs::{layer, mkfile, mkpath, mkwhiteout, slurp, stack};
use crate::uapi::{Marker, MARKER_YES};

use super::merge::lookup;

/// A two-layer mount with the given configuration.
fn mount(config: Config) -> (Arc<LayerStack>, OvlEntry, InodeRef, InodeRef) {
    let up = layer(0);
    let lo = layer(1);
    let (s, root) = stack(config, Some(up.clone()), &[lo.clone()], &[]);
    (s, root, up, lo)
}

/// Resolve one name directly under the mount root.
fn find(s: &Arc<LayerStack>, root: &OvlEntry, name: &str) -> Result<Option<OvlEntry>, Errno> {
    lookup(s, root, root, name)
}

#[test]
fn a_name_only_in_the_lower_layer_resolves_there() {
    let (s, root, _up, lo) = mount(Config::default());
    mkfile(&lo, "only-lower", b"below");
    let e = find(&s, &root, "only-lower").unwrap().unwrap();
    assert!(e.upper.is_none());
    assert_eq!(e.lower.len(), 1);
    assert_eq!(slurp(&e.lower[0].inode), b"below".to_vec());
}

#[test]
fn a_name_in_both_layers_takes_the_upper_one() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"below");
    mkfile(&up, "f", b"above");
    let e = find(&s, &root, "f").unwrap().unwrap();
    assert_eq!(slurp(&e.real().unwrap()), b"above".to_vec());
    // A plain file in the upper layer stops the walk: nothing below it is
    // part of this object.
    assert!(e.lower.is_empty());
}

#[test]
fn a_name_in_neither_layer_resolves_to_nothing() {
    let (s, root, _up, _lo) = mount(Config::default());
    assert!(find(&s, &root, "absent").unwrap().is_none());
}

#[test]
fn a_whiteout_hides_the_lower_file() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "gone", b"below");
    mkwhiteout(&up, "gone");
    let e = find(&s, &root, "gone").unwrap();
    assert!(e.is_none(), "a whited-out name must resolve to nothing");
}

#[test]
fn a_directory_present_in_both_layers_merges() {
    let (s, root, up, lo) = mount(Config::default());
    mkpath(&lo, "d");
    mkpath(&up, "d");
    let e = find(&s, &root, "d").unwrap().unwrap();
    assert!(e.upper.is_some());
    assert_eq!(e.lower.len(), 1);
    assert!(e.path_type(true).merge);
}

#[test]
fn an_opaque_upper_directory_hides_the_lower_one() {
    let c = Config::default();
    let (s, root, up, lo) = mount(c.clone());
    mkfile(&lo, "d/below", b"x");
    let d = mkpath(&up, "d");
    marker::set(&c, &d, Marker::Opaque, MARKER_YES, Errno::Eio).unwrap();
    let e = find(&s, &root, "d").unwrap().unwrap();
    assert!(e.opaque);
    assert!(e.lower.is_empty(), "an opaque directory has no lower half");
}

#[test]
fn a_whiteout_inside_a_merged_directory_hides_only_that_name() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "d/keep", b"k");
    mkfile(&lo, "d/gone", b"g");
    let ud = mkpath(&up, "d");
    mkwhiteout(&ud, "gone");
    let d = find(&s, &root, "d").unwrap().unwrap();
    assert!(lookup(&s, &d, &root, "gone").unwrap().is_none());
    assert!(lookup(&s, &d, &root, "keep").unwrap().is_some());
}

#[test]
fn three_layers_resolve_topmost_first() {
    let up = layer(0);
    let l1 = layer(1);
    let l2 = layer(2);
    mkfile(&l2, "f", b"bottom");
    mkfile(&l1, "f", b"middle");
    let (s, root) = stack(Config::default(), Some(up), &[l1, l2], &[]);
    let e = find(&s, &root, "f").unwrap().unwrap();
    assert_eq!(slurp(&e.lower[0].inode), b"middle".to_vec());
}

#[test]
fn a_directory_merges_across_every_layer_that_has_it() {
    let up = layer(0);
    let l1 = layer(1);
    let l2 = layer(2);
    mkpath(&l1, "d");
    mkpath(&l2, "d");
    mkpath(&up, "d");
    let (s, root) = stack(Config::default(), Some(up), &[l1, l2], &[]);
    let e = find(&s, &root, "d").unwrap().unwrap();
    assert_eq!(e.lower.len(), 2);
}

#[test]
fn a_whiteout_in_a_middle_layer_stops_the_walk_there() {
    let up = layer(0);
    let l1 = layer(1);
    let l2 = layer(2);
    mkfile(&l2, "f", b"bottom");
    mkwhiteout(&l1, "f");
    let (s, root) = stack(Config::default(), Some(up), &[l1, l2], &[]);
    assert!(find(&s, &root, "f").unwrap().is_none());
}

#[test]
fn a_relative_redirect_finds_the_lower_object_under_its_old_name() {
    let c = Config { redirect_mode: RedirectMode::On, ..Config::default() };
    let (s, root, up, lo) = mount(c.clone());
    mkpath(&lo, "was");
    let now = mkpath(&up, "now");
    marker::set(&c, &now, Marker::Redirect, b"was", Errno::Eio).unwrap();
    let e = find(&s, &root, "now").unwrap().unwrap();
    assert_eq!(e.lower.len(), 1, "the renamed directory keeps its lower half");
}

#[test]
fn an_absolute_redirect_restarts_at_the_layer_root() {
    let c = Config { redirect_mode: RedirectMode::On, ..Config::default() };
    let (s, root, up, lo) = mount(c.clone());
    mkpath(&lo, "a/b/deep");
    let d = mkpath(&up, "moved");
    marker::set(&c, &d, Marker::Redirect, b"/a/b/deep", Errno::Eio).unwrap();
    let e = find(&s, &root, "moved").unwrap().unwrap();
    assert_eq!(e.lower.len(), 1);
}

#[test]
fn a_redirect_is_not_followed_when_the_mount_refuses_to() {
    // Following one reaches a lower object without walking, and therefore
    // without being permission-checked, through the directories above it.
    let c = Config { redirect_mode: RedirectMode::NoFollow, ..Config::default() };
    let (s, root, up, lo) = mount(c.clone());
    mkpath(&lo, "was");
    let now = mkpath(&up, "now");
    marker::set(&c, &now, Marker::Redirect, b"was", Errno::Eio).unwrap();
    assert_eq!(find(&s, &root, "now").err(), Some(Errno::Eperm));
}

#[test]
fn a_malformed_redirect_is_refused() {
    let c = Config { redirect_mode: RedirectMode::On, ..Config::default() };
    let (s, root, up, _lo) = mount(c.clone());
    let d = mkpath(&up, "now");
    marker::set(&c, &d, Marker::Redirect, b"a/b", Errno::Eio).unwrap();
    assert_eq!(find(&s, &root, "now").err(), Some(Errno::Einval));
}

#[test]
fn a_metadata_only_upper_file_keeps_looking_for_its_data() {
    let c = Config { metacopy: true, redirect_mode: RedirectMode::On, ..Config::default() };
    let (s, root, up, lo) = mount(c.clone());
    mkfile(&lo, "f", b"the real contents");
    let f = mkfile(&up, "f", b"");
    marker::set(&c, &f, Marker::Metacopy, &Metacopy::empty().encode(), Errno::Eio).unwrap();
    let e = find(&s, &root, "f").unwrap().unwrap();
    assert!(e.metacopy);
    assert_eq!(e.lower.len(), 1);
    assert_eq!(slurp(&e.realdata().unwrap()), b"the real contents".to_vec());
}

#[test]
fn a_metadata_only_file_with_nothing_below_it_is_an_error() {
    // Presenting it as empty would silently lose whatever it stands for.
    let c = Config { metacopy: true, redirect_mode: RedirectMode::On, ..Config::default() };
    let (s, root, up, _lo) = mount(c.clone());
    let f = mkfile(&up, "f", b"");
    marker::set(&c, &f, Marker::Metacopy, &Metacopy::empty().encode(), Errno::Eio).unwrap();
    assert_eq!(find(&s, &root, "f").err(), Some(Errno::Eio));
}

#[test]
fn a_metadata_only_record_is_not_followed_when_the_mount_refuses_to() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"below");
    let f = mkfile(&up, "f", b"");
    marker::set(&Config::default(), &f, Marker::Metacopy, &Metacopy::empty().encode(), Errno::Eio)
        .unwrap();
    assert_eq!(find(&s, &root, "f").err(), Some(Errno::Eperm));
}

#[test]
fn a_directory_below_a_file_is_not_merged_with_it() {
    let (s, root, up, lo) = mount(Config::default());
    mkpath(&lo, "n");
    mkfile(&up, "n", b"file");
    let e = find(&s, &root, "n").unwrap().unwrap();
    assert!(e.lower.is_empty());
}

#[test]
fn a_file_below_a_directory_is_not_merged_with_it() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "n", b"file");
    mkpath(&up, "n");
    let e = find(&s, &root, "n").unwrap().unwrap();
    assert!(e.lower.is_empty());
}

#[test]
fn a_name_longer_than_any_layer_accepts_is_refused() {
    let (s, root, _up, _lo) = mount(Config::default());
    let long: alloc::string::String = "x".repeat(crate::limits::NAME_MAX as usize + 1);
    assert_eq!(find(&s, &root, &long).err(), Some(Errno::Enametoolong));
}

#[test]
fn a_read_only_mount_with_no_upper_layer_still_merges() {
    let l1 = layer(1);
    let l2 = layer(2);
    mkpath(&l1, "d");
    mkpath(&l2, "d");
    let (s, root) = stack(Config::default(), None, &[l1, l2], &[]);
    let e = find(&s, &root, "d").unwrap().unwrap();
    assert!(e.upper.is_none());
    assert_eq!(e.lower.len(), 2);
    assert!(e.path_type(true).merge);
}

#[test]
fn the_marked_whiteout_form_is_recognised_once_a_directory_declares_it() {
    let c = Config::default();
    let up = layer(0);
    let l1 = layer(1);
    let l2 = layer(2);
    // A layer written without device nodes: the directory says so with the
    // opaque marker's `x` value, and the whiteout is an empty marked file
    // hiding the same name in the layer below.
    let d = mkpath(&l1, "d");
    marker::set(&c, &d, Marker::Opaque, b"x", Errno::Eio).unwrap();
    let gone = mkfile(&l1, "d/gone", b"");
    marker::set(&c, &gone, Marker::Xwhiteout, MARKER_YES, Errno::Eio).unwrap();
    mkfile(&l2, "d/gone", b"still here");
    mkfile(&l2, "d/keep", b"k");
    let (s, root) = stack(c.clone(), Some(up), &[l1, l2], &[]);

    let e = find(&s, &root, "d").unwrap().unwrap();
    assert!(e.xwhiteouts, "the directory must be flagged so the slower check runs");
    assert!(lookup(&s, &e, &root, "gone").unwrap().is_none());
    assert!(lookup(&s, &e, &root, "keep").unwrap().is_some());
    let _ = vec![0u8; 0];
    let _ = CreateCtx::root();
}

#[test]
fn a_single_last_lower_does_not_activate_the_marked_whiteout_extension() {
    let c = Config::default();
    let lo = layer(1);
    let d = mkpath(&lo, "d");
    marker::set(&c, &d, Marker::Opaque, b"x", Errno::Eio).unwrap();
    let marked = mkfile(&lo, "d/marked", b"");
    marker::set(&c, &marked, Marker::Xwhiteout, MARKER_YES, Errno::Eio).unwrap();
    let (s, root) = stack(c, None, &[lo], &[]);

    let e = find(&s, &root, "d").unwrap().unwrap();
    assert!(!e.xwhiteouts, "the final lower layer does not activate xwhiteouts");
    assert!(lookup(&s, &e, &root, "marked").unwrap().is_some());
}
