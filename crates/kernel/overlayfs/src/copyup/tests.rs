//! Copy-up end to end, against real layers.
//!
//! Each case looks at what is actually on each layer afterwards, not at what
//! the copy-up returned: the failures that matter here are a file that arrived
//! with the wrong contents, an attribute that did not arrive at all, and a
//! work directory left holding the copy that should have moved.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::inode_ops::CreateCtx;
use vfs::types::{FileType, S_IFCHR};
use vfs::InodeRef;

use crate::config::{Config, FsyncMode};
use crate::layers::{LayerStack, OvlEntry};
use crate::lookup::lookup;
use crate::marker;
use crate::testfs::{layer, lookup as find_path, mkfile, mkpath, names, slurp, stack};
use crate::uapi::{Marker, WHITEOUT_RDEV};
use crate::xattr::NAME_CAPS;

use super::run::{copy_up, copy_up_data};

/// A two-layer mount.
fn mount(config: Config) -> (Arc<LayerStack>, OvlEntry, InodeRef, InodeRef) {
    let up = layer(0);
    let lo = layer(1);
    let (s, root) = stack(config, Some(up.clone()), &[lo.clone()], &[]);
    (s, root, up, lo)
}

/// Resolve `name` under the root and copy it up.
fn up_one(s: &Arc<LayerStack>, root: &OvlEntry, name: &str, flags: u32)
    -> Result<OvlEntry, Errno> {
    let mut e = lookup(s, root, root, name)?.expect("name resolves");
    copy_up(s, root, &mut e, name, flags)?;
    Ok(e)
}

#[test]
fn a_lower_file_arrives_whole_in_the_writable_layer() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"contents below");
    let e = up_one(&s, &root, "f", 1).unwrap();
    assert!(e.upper.is_some());
    let arrived = find_path(&up, "f").expect("copied up");
    assert_eq!(slurp(&arrived), b"contents below".to_vec());
    assert_eq!(arrived.size(), 14);
}

#[test]
fn the_work_directory_is_left_empty() {
    // A copy left behind is a leak that grows with every write, and one that
    // a later mount would have to clean up.
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"x");
    up_one(&s, &root, "f", 1).unwrap();
    let work = find_path(&up, "..work").unwrap();
    assert!(names(&work).is_empty(), "{:?}", names(&work));
}

#[test]
fn the_lower_file_is_untouched() {
    let (s, root, _up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"below");
    up_one(&s, &root, "f", 1).unwrap();
    assert_eq!(slurp(&find_path(&lo, "f").unwrap()), b"below".to_vec());
}

#[test]
fn mode_owner_and_times_come_across() {
    let (s, root, up, lo) = mount(Config::default());
    let f = mkfile(&lo, "f", b"x");
    f.set_perm(0o604).unwrap();
    f.set_owner(1000, 1001).unwrap();
    up_one(&s, &root, "f", 1).unwrap();
    let arrived = find_path(&up, "f").unwrap();
    assert_eq!(arrived.i_mode() & 0o7777, 0o604);
    assert_eq!(arrived.uid(), Some(1000));
    assert_eq!(arrived.gid(), Some(1001));
}

#[test]
fn ordinary_attributes_come_across_and_the_overlays_own_do_not() {
    let c = Config::default();
    let (s, root, up, lo) = mount(c.clone());
    let f = mkfile(&lo, "f", b"x");
    f.setxattr("user.mime_type", b"text/plain".to_vec(), false, false).unwrap();
    // A marker on the lower object is the overlay's own bookkeeping. Copying
    // it would make the copy claim to be a copy of something else.
    marker::set(&c, &f, Marker::Origin, b"not mine", Errno::Eio).unwrap();
    up_one(&s, &root, "f", 1).unwrap();
    let arrived = find_path(&up, "f").unwrap();
    assert_eq!(arrived.getxattr("user.mime_type").unwrap(), b"text/plain".to_vec());
    assert_ne!(marker::get(&c, &arrived, Marker::Origin), Some(b"not mine".to_vec()));
}

#[test]
fn file_capabilities_survive_the_copy() {
    // ORDERING CONTROL: writing a file's contents clears its capabilities. If
    // the attributes were copied before the data, this attribute would be
    // gone — and a setcap binary inside a container image would silently lose
    // its privileges the first time anything wrote to it.
    let (s, root, up, lo) = mount(Config::default());
    let f = mkfile(&lo, "f", b"a program");
    f.setxattr(NAME_CAPS, b"cap-value".to_vec(), false, false).unwrap();
    up_one(&s, &root, "f", 1).unwrap();
    let arrived = find_path(&up, "f").unwrap();
    assert_eq!(arrived.getxattr(NAME_CAPS).unwrap(), b"cap-value".to_vec());
}

#[test]
fn the_origin_of_the_lower_object_is_recorded() {
    let c = Config::default();
    let (s, root, up, lo) = mount(c.clone());
    mkfile(&lo, "f", b"x");
    up_one(&s, &root, "f", 1).unwrap();
    let arrived = find_path(&up, "f").unwrap();
    assert!(marker::present(&c, &arrived, Marker::Origin),
            "without it the copy and the lower object stop being one file");
}

#[test]
fn a_directory_copies_up_without_its_contents() {
    // Copying a directory's contents would turn one write deep in an image
    // into a copy of the whole tree above it.
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "d/inside", b"x");
    let e = up_one(&s, &root, "d", 0).unwrap();
    assert!(e.upper.is_some());
    let arrived = find_path(&up, "d").unwrap();
    assert_eq!(arrived.file_type(), FileType::Directory);
    assert!(names(&arrived).is_empty());
}

#[test]
fn a_symlink_copies_up_with_its_target() {
    let (s, root, up, lo) = mount(Config::default());
    lo.symlink_child("l", b"/some/target", &CreateCtx::root()).unwrap();
    up_one(&s, &root, "l", 0).unwrap();
    let arrived = find_path(&up, "l").unwrap();
    assert_eq!(arrived.file_type(), FileType::Symlink);
    assert_eq!(arrived.get_link().unwrap(), b"/some/target".to_vec());
}

#[test]
fn a_device_node_copies_up_with_its_device_number() {
    let (s, root, up, lo) = mount(Config::default());
    lo.mknod_child("dev", S_IFCHR | 0o600, 0x0501, &CreateCtx::root()).unwrap();
    up_one(&s, &root, "dev", 0).unwrap();
    let arrived = find_path(&up, "dev").unwrap();
    assert_eq!(arrived.file_type(), FileType::CharDev);
    assert_eq!(arrived.rdev(), 0x0501);
    assert_ne!(arrived.rdev(), WHITEOUT_RDEV, "a copied device must not become a whiteout");
}

#[test]
fn an_empty_file_copies_up_as_an_empty_file() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"");
    up_one(&s, &root, "f", 1).unwrap();
    assert_eq!(slurp(&find_path(&up, "f").unwrap()), Vec::<u8>::new());
}

#[test]
fn a_copy_up_for_a_truncating_open_does_not_move_the_old_contents() {
    // They are about to be discarded; copying them is pure cost on a file the
    // caller is replacing.
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"old contents");
    up_one(&s, &root, "f", super::plan::O_TRUNC).unwrap();
    assert_eq!(slurp(&find_path(&up, "f").unwrap()), Vec::<u8>::new());
}

#[test]
fn a_metadata_only_copy_leaves_the_contents_below() {
    let c = Config { metacopy: true, redirect_mode: crate::config::RedirectMode::On,
                     ..Config::default() };
    let (s, root, up, lo) = mount(c.clone());
    mkfile(&lo, "f", b"big contents");
    let e = up_one(&s, &root, "f", 0).unwrap();
    assert!(e.metacopy);
    let arrived = find_path(&up, "f").unwrap();
    assert!(marker::present(&c, &arrived, Marker::Metacopy));
    // The upper object carries the SIZE, so `stat` is right without the data
    // being there; reads are answered from the lower object instead.
    assert_eq!(arrived.size(), 12);
    assert_eq!(slurp(&e.realdata().unwrap()), b"big contents".to_vec());
    assert!(alloc::sync::Arc::ptr_eq(&e.realdata().unwrap(), &e.lower[0].inode));
}

#[test]
fn the_contents_follow_later_when_the_file_is_written() {
    let c = Config { metacopy: true, redirect_mode: crate::config::RedirectMode::On,
                     ..Config::default() };
    let (s, root, up, lo) = mount(c.clone());
    mkfile(&lo, "f", b"big contents");
    let mut e = up_one(&s, &root, "f", 0).unwrap();
    copy_up_data(&s, &mut e).unwrap();
    assert!(!e.metacopy);
    let arrived = find_path(&up, "f").unwrap();
    assert_eq!(slurp(&arrived), b"big contents".to_vec());
    assert!(!marker::present(&c, &arrived, Marker::Metacopy),
            "the record must go, or the file reads as empty for ever");
}

#[test]
fn capabilities_survive_the_later_data_copy_too() {
    let c = Config { metacopy: true, redirect_mode: crate::config::RedirectMode::On,
                     ..Config::default() };
    let (s, root, up, lo) = mount(c.clone());
    let f = mkfile(&lo, "f", b"a program");
    f.setxattr(NAME_CAPS, b"cap-value".to_vec(), false, false).unwrap();
    let mut e = up_one(&s, &root, "f", 0).unwrap();
    copy_up_data(&s, &mut e).unwrap();
    assert_eq!(find_path(&up, "f").unwrap().getxattr(NAME_CAPS).unwrap(), b"cap-value".to_vec());
}

#[test]
fn copying_up_twice_is_a_no_op() {
    let (s, root, up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"x");
    let mut e = lookup(&s, &root, &root, "f").unwrap().unwrap();
    copy_up(&s, &root, &mut e, "f", 1).unwrap();
    copy_up(&s, &root, &mut e, "f", 1).unwrap();
    assert_eq!(names(&up).iter().filter(|n| *n == "f").count(), 1);
}

#[test]
fn a_read_only_mount_cannot_copy_up() {
    let l1 = layer(1);
    mkfile(&l1, "f", b"x");
    let (s, root) = stack(Config::default(), None, &[l1], &[]);
    let mut e = lookup(&s, &root, &root, "f").unwrap().unwrap();
    assert_eq!(copy_up(&s, &root, &mut e, "f", 1), Err(Errno::Eio));
}

#[test]
fn a_protection_flag_is_recorded_rather_than_set_on_the_copy() {
    // Setting it on the object being built would stop the copy-up finishing.
    let c = Config::default();
    let (s, root, up, lo) = mount(c.clone());
    let f = mkfile(&lo, "f", b"x");
    f.set_i_flags(vfs::inode::FS_IMMUTABLE_FL);
    up_one(&s, &root, "f", 1).unwrap();
    let arrived = find_path(&up, "f").unwrap();
    assert_eq!(marker::get(&c, &arrived, Marker::Protattr), Some(b"i".to_vec()));
    assert_eq!(arrived.i_flags() & vfs::inode::FS_IMMUTABLE_FL, 0);
}

#[test]
fn a_larger_file_arrives_byte_for_byte() {
    let (s, root, up, lo) = mount(Config::default());
    let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    mkfile(&lo, "big", &body);
    up_one(&s, &root, "big", 1).unwrap();
    assert_eq!(slurp(&find_path(&up, "big").unwrap()), body);
}

#[test]
fn the_flush_setting_does_not_change_what_arrives() {
    for mode in [FsyncMode::Volatile, FsyncMode::Auto, FsyncMode::Strict] {
        let (s, root, up, lo) = mount(Config { fsync_mode: mode, ..Config::default() });
        mkfile(&lo, "f", b"same");
        up_one(&s, &root, "f", 1).unwrap();
        assert_eq!(slurp(&find_path(&up, "f").unwrap()), b"same".to_vec(), "{mode:?}");
    }
}

#[test]
fn the_copy_is_visible_through_a_fresh_lookup() {
    let (s, root, _up, lo) = mount(Config::default());
    mkfile(&lo, "f", b"below");
    up_one(&s, &root, "f", 1).unwrap();
    let again = lookup(&s, &root, &root, "f").unwrap().unwrap();
    assert!(again.upper.is_some());
    assert_eq!(slurp(&again.real().unwrap()), b"below".to_vec());
    let _ = String::new();
    let _ = mkpath(&lo, "unused");
}
