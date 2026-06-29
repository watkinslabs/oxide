//! `generic_fillattr` (Linux `fs/stat.c`) overlay + idmap merge — regression
//! cover for the pseudo-fs metadata path: an inode's perm/owner/time, with the
//! resolved owner ids mapped THROUGH the mount idmap before they land in the
//! `Kstat` (`stx_uid`/`stx_gid` are vfsuid/vfsgid).
//!
//! Concrete-inode-model note (B280b): the `struct Inode` always stores its own
//! mode/owner/times, so the `InodeTimes` overlay fallback no longer fires —
//! the inode field always wins. These tests stamp the values onto the inode;
//! the overlay argument is retained but no longer consulted. The assertions
//! (the observable `Kstat`, including the idmap mapping) are unchanged.

use vfs::getattr::generic_fillattr;
use vfs::idmap::Idmap;
use vfs::inode_times::InodeTimes;
use vfs::{FileType, InodeBuilder, InodeRef, IDENTITY,
          default_file_ops, default_inode_ops, mk_mode};

/// Inode carrying explicit mode/owner/times in its own fields.
fn inode_with(ino: u64, perm: u16, uid: u32, gid: u32, times: (u64, u64, u64)) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(uid, gid).times(times.0, times.1, times.2).build()
}

fn overlay() -> InodeTimes {
    InodeTimes {
        atime_ns: 111, mtime_ns: 222, ctime_ns: 333,
        mode_bits: 0o600, uid: 1000, gid: 2000, owner_set: true,
    }
}

#[test]
fn overlay_supplies_perm_owner_times_when_native_absent() {
    let i = inode_with(11, 0o600, 1000, 2000, (111, 222, 333));
    let st = generic_fillattr(&i, &IDENTITY, Some(overlay()));
    // perm (S_IFREG | 0o600).
    assert_eq!(st.mode & 0o7777, 0o600);
    assert_eq!(st.uid, 1000);
    assert_eq!(st.gid, 2000);
    assert_eq!(st.atime_ns, 111);
    assert_eq!(st.mtime_ns, 222);
    assert_eq!(st.ctime_ns, 333);
}

#[test]
fn idmap_maps_overlay_owner_out() {
    // fs[0..5000) <-> vfs[10000..15000): uid 1000 -> vfsuid 11000,
    // gid 2000 -> vfsgid 12000.
    let m = Idmap::uniform(0, 10_000, 5_000);
    let i = inode_with(11, 0o600, 1000, 2000, (111, 222, 333));
    let st = generic_fillattr(&i, &m, Some(overlay()));
    assert_eq!(st.uid, 11_000, "uid mapped out through the mount idmap");
    assert_eq!(st.gid, 12_000, "gid mapped out through the mount idmap");
}

#[test]
fn native_fields_override_overlay() {
    // Native perm/uid/gid present → the overlay's owner_set values are ignored.
    let i = inode_with(12, 0o640, 7, 9, (0, 0, 0));
    let st = generic_fillattr(&i, &IDENTITY, Some(overlay()));
    assert_eq!(st.mode & 0o7777, 0o640, "native perm wins");
    assert_eq!(st.uid, 7, "native uid wins");
    assert_eq!(st.gid, 9, "native gid wins");
}

#[test]
fn no_overlay_uses_default_perm_and_zero_owner() {
    // No overlay → Linux-shaped default perm + uid/gid 0.
    let i = inode_with(11, 0o644, 0, 0, (0, 0, 0));
    let st = generic_fillattr(&i, &IDENTITY, None);
    assert_eq!(st.mode & 0o7777, 0o644, "default regular-file perm");
    assert_eq!(st.uid, 0);
    assert_eq!(st.gid, 0);
}
