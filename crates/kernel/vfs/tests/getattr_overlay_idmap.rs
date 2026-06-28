//! `generic_fillattr` (Linux `fs/stat.c`) overlay + idmap merge — regression
//! cover for the pseudo-fs metadata path: an inode whose native perm/owner/time
//! accessors return `None` (devfs/procfs/tmpfs entry) inherits perm, uid, gid
//! and timestamps from the kernel `inode_times` overlay, and the resolved owner
//! ids are mapped THROUGH the mount idmap before they land in the `Kstat`
//! (`stx_uid`/`stx_gid` are vfsuid/vfsgid). Native inode fields win over the
//! overlay when present. Pure `Inode` impls, no QEMU.

use vfs::getattr::generic_fillattr;
use vfs::idmap::Idmap;
use vfs::inode::Inode;
use vfs::inode_times::InodeTimes;
use vfs::{FileType, InodeRef, KResult, VfsError, IDENTITY};

/// Inode with no native metadata (everything defaults to `None`) — the overlay
/// is the sole source of perm/owner/time.
struct Bare;
impl Inode for Bare {
    fn ino(&self) -> vfs::Ino { 11 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// Inode carrying NATIVE perm/owner that must override any overlay.
struct Native;
impl Inode for Native {
    fn ino(&self) -> vfs::Ino { 12 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn perm(&self) -> Option<u16> { Some(0o640) }
    fn uid(&self) -> Option<u32> { Some(7) }
    fn gid(&self) -> Option<u32> { Some(9) }
}

fn overlay() -> InodeTimes {
    InodeTimes {
        atime_ns: 111, mtime_ns: 222, ctime_ns: 333,
        mode_bits: 0o600, uid: 1000, gid: 2000, owner_set: true,
    }
}

#[test]
fn overlay_supplies_perm_owner_times_when_native_absent() {
    let st = generic_fillattr(&Bare, &IDENTITY, Some(overlay()));
    // perm from overlay (S_IFREG | 0o600).
    assert_eq!(st.mode & 0o7777, 0o600);
    assert_eq!(st.uid, 1000);
    assert_eq!(st.gid, 2000);
    assert_eq!(st.atime_ns, 111);
    assert_eq!(st.mtime_ns, 222);
    assert_eq!(st.ctime_ns, 333);
}

#[test]
fn idmap_maps_overlay_owner_out() {
    // fs[0..5000) <-> vfs[10000..15000): overlay uid 1000 -> vfsuid 11000,
    // gid 2000 -> vfsgid 12000.
    let m = Idmap::uniform(0, 10_000, 5_000);
    let st = generic_fillattr(&Bare, &m, Some(overlay()));
    assert_eq!(st.uid, 11_000, "overlay uid mapped out through the mount idmap");
    assert_eq!(st.gid, 12_000, "overlay gid mapped out through the mount idmap");
}

#[test]
fn native_fields_override_overlay() {
    // Native perm/uid/gid present → the overlay's owner_set values are ignored.
    let st = generic_fillattr(&Native, &IDENTITY, Some(overlay()));
    assert_eq!(st.mode & 0o7777, 0o640, "native perm wins");
    assert_eq!(st.uid, 7, "native uid wins");
    assert_eq!(st.gid, 9, "native gid wins");
}

#[test]
fn no_overlay_uses_default_perm_and_zero_owner() {
    // No native metadata, no overlay → Linux-shaped default perm + uid/gid 0.
    let st = generic_fillattr(&Bare, &IDENTITY, None);
    assert_eq!(st.mode & 0o7777, 0o644, "default regular-file perm");
    assert_eq!(st.uid, 0);
    assert_eq!(st.gid, 0);
}
