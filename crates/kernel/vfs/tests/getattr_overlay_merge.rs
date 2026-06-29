//! inode-D17 (overlay-merge half): `generic_fillattr` (Linux `fs/stat.c`) merges
//! the kernel `inode_times` metadata overlay for pseudo-fs inodes that carry no
//! native timestamps/owner/mode — the out-of-line store `utimensat`/`chmod`/
//! `chown` write to when the backing inode trait returns `None`. The overlay is
//! a FALLBACK only: a backend that stores its own value (`Inode::perm`/`uid`/
//! `gid`/`atime`/`mtime`/`ctime` -> `Some`) overrides the overlay, exactly
//! Linux preferring the real inode field over any generic default.
//!
//! Fails-before: dropping the overlay merge would make `stat` on a chmod'd /
//! utime'd pseudo-fs entry report defaults (mode 0644/0755, time 0) instead of
//! the values just written — the bug the out-of-line store exists to avoid.
//!
//! `InodeTimes` is passed by value to `generic_fillattr`, NOT through the
//! `cfg(oxide-kernel)`-gated global map, so this is pure value math — no global
//! state, no serial guard.

use vfs::getattr::S_IFREG;
use vfs::inode::Inode;
use vfs::inode_times::InodeTimes;
use vfs::{FileType, InodeRef, KResult, VfsError, IDENTITY};

/// A pseudo-fs inode with NO native metadata: perm/uid/gid/times all default to
/// `None`, so the overlay is the only source.
struct PseudoInode;
impl Inode for PseudoInode {
    fn ino(&self) -> vfs::Ino { 11 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// An inode that stores its OWN metadata, overriding any overlay.
struct NativeInode;
impl Inode for NativeInode {
    fn ino(&self) -> vfs::Ino { 12 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn perm(&self) -> Option<u16> { Some(0o600) }
    fn uid(&self) -> Option<u32> { Some(7) }
    fn gid(&self) -> Option<u32> { Some(8) }
    fn atime(&self) -> Option<u64> { Some(111) }
    fn mtime(&self) -> Option<u64> { Some(222) }
    fn ctime(&self) -> Option<u64> { Some(333) }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

fn overlay() -> InodeTimes {
    InodeTimes {
        atime_ns: 1_000, mtime_ns: 2_000, ctime_ns: 3_000,
        mode_bits: 0o640, uid: 1234, gid: 5678, owner_set: true,
    }
}

// A None-everything pseudo inode reports the overlay's perm/owner/times.
#[test]
fn overlay_supplies_metadata_for_pseudo_inode() {
    let st = vfs::generic_fillattr(&PseudoInode, &IDENTITY, Some(overlay()));
    assert_eq!(st.mode, S_IFREG | 0o640, "mode = S_IFREG | overlay perm bits");
    assert_eq!(st.uid, 1234);
    assert_eq!(st.gid, 5678);
    assert_eq!(st.atime_ns, 1_000);
    assert_eq!(st.mtime_ns, 2_000);
    assert_eq!(st.ctime_ns, 3_000);
}

// No overlay -> Linux generic defaults (0644 for a regular file, owner 0, t=0).
#[test]
fn no_overlay_uses_generic_defaults() {
    let st = vfs::generic_fillattr(&PseudoInode, &IDENTITY, None);
    assert_eq!(st.mode, S_IFREG | 0o644);
    assert_eq!(st.uid, 0);
    assert_eq!(st.gid, 0);
    assert_eq!((st.atime_ns, st.mtime_ns, st.ctime_ns), (0, 0, 0));
}

// A backend that stores its own metadata WINS over the overlay (overlay is a
// fallback for `None`-returning accessors only).
#[test]
fn native_metadata_overrides_overlay() {
    let st = vfs::generic_fillattr(&NativeInode, &IDENTITY, Some(overlay()));
    assert_eq!(st.mode, S_IFREG | 0o600, "native perm, not overlay 0640");
    assert_eq!((st.uid, st.gid), (7, 8), "native owner, not overlay 1234/5678");
    assert_eq!((st.atime_ns, st.mtime_ns, st.ctime_ns), (111, 222, 333),
        "native times, not overlay 1000/2000/3000");
}
