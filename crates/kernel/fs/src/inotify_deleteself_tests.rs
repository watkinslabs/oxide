// IN_DELETE_SELF ownership and the `fsnotify_link_count` leg.
//
// DELETE_SELF used to be fired by `unlink(2)` directly, which was wrong twice
// over: a file with remaining hardlinks reported it on the FIRST name removed,
// and `rmdir` — which never touched that code — reported it not at all, so a
// watch on a removed directory never learned its watch was dead. Linux fires it
// from the dcache: `dentry_unlink_inode` runs
// `if (!inode->i_nlink) fsnotify_inoderemove(inode)` (`fs/dcache.c`).
//
// Included as a child module of `inotify` via `#[path]`.

use super::*;
use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::{FileType, InodeRef, InodeBuilder, default_file_ops, default_inode_ops, mk_mode};

use crate::inotify::dispatch::{fire_delete_self, fire_link_count};
use crate::inotify::syscalls::add_or_update_watch;
use crate::inotify::types::{inode_key, FAN_ATTRIB, FAN_DELETE_SELF, IN_ATTRIB, IN_ISDIR};

fn mk(ft: FileType, fsid: u64, nlink: u32) -> InodeRef {
    InodeBuilder::new(0x6B00_0000 + fsid, mk_mode(ft, 0o644),
        default_inode_ops(), default_file_ops())
        .fsid(fsid).nlink(nlink).build()
}

fn masks(g: &InotifyData) -> Vec<u32> { g.events.lock().iter().map(|e| e.mask).collect() }

/// A hardlink bumps the link count, so a watch on the FILE gets FS_ATTRIB —
/// Linux `fsnotify_link` is `fsnotify_link_count(inode)` PLUS the named
/// FS_CREATE on the parent. Only the parent leg used to exist.
#[test]
fn a_new_hardlink_reports_attrib_on_the_file() {
    let g = InotifyData::new(0);
    let f = mk(FileType::Regular, 0x6B01, 1);
    add_or_update_watch(&g, inode_key(&f), f.fsid(), IN_ATTRIB).unwrap();

    fire_link_count(&f);
    assert_eq!(masks(&g), alloc::vec![IN_ATTRIB], "the link()ed file sees its count move");
}

/// The same leg on a rename that overwrote an existing entry
/// (`fsnotify_move`: `if (target) fsnotify_link_count(target)`).
#[test]
fn an_overwritten_rename_target_reports_attrib() {
    let g = InotifyData::new(0);
    let victim = mk(FileType::Regular, 0x6B02, 2);
    add_or_update_watch(&g, inode_key(&victim), victim.fsid(), IN_ATTRIB).unwrap();

    fire_link_count(&victim);
    assert_eq!(masks(&g), alloc::vec![IN_ATTRIB]);
}

/// DELETE_SELF on a directory carries no IN_ISDIR — it is in
/// `IN_SELF_NO_ISDIR` (Linux never sets FS_ISDIR on the *_SELF events).
/// Pins that an rmdir'd directory reports the bare bit.
#[test]
fn delete_self_on_a_directory_carries_no_isdir() {
    let g = InotifyData::new(0);
    let d = mk(FileType::Directory, 0x6B03, 2);
    add_or_update_watch(&g, inode_key(&d), d.fsid(), FAN_DELETE_SELF).unwrap();

    fire_delete_self(&d);
    assert_eq!(masks(&g), alloc::vec![FAN_DELETE_SELF], "no IN_ISDIR on a *_SELF event");
    assert_eq!(masks(&g)[0] & IN_ISDIR, 0);
}

/// A watch asking only for ATTRIB does not receive DELETE_SELF, and vice
/// versa — guards against the two legs being conflated.
#[test]
fn the_two_legs_are_separately_maskable() {
    let g = InotifyData::new(0);
    let f = mk(FileType::Regular, 0x6B04, 1);
    add_or_update_watch(&g, inode_key(&f), f.fsid(), FAN_DELETE_SELF).unwrap();

    fire_link_count(&f);
    assert_eq!(masks(&g), Vec::<u32>::new(), "an ATTRIB leg is not a DELETE_SELF");
    fire_delete_self(&f);
    assert_eq!(masks(&g), alloc::vec![FAN_DELETE_SELF]);
    assert_ne!(FAN_ATTRIB, FAN_DELETE_SELF, "distinct bits");
}
