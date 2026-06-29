//! inode-D17 (overlay-merge half): `generic_fillattr` (Linux `fs/stat.c`) merges
//! the kernel `inode_times` metadata overlay for pseudo-fs inodes that carry no
//! native timestamps/owner/mode — the out-of-line store `utimensat`/`chmod`/
//! `chown` write to when the backing inode trait returns `None`. The overlay is
//! a FALLBACK only: a backend that stores its own value overrides the overlay,
//! exactly Linux preferring the real inode field over any generic default.
//!
//! Concrete-inode-model note (B280b): the `struct Inode` now ALWAYS stores its
//! own mode/owner/times (`perm()`/`uid()`/`gid()`/`*time()` are never `None`),
//! so the `InodeTimes` overlay fallback in `generic_fillattr` is dead code —
//! the inode field always wins. These tests therefore stamp the values onto the
//! inode itself; the overlay argument is retained but no longer consulted. The
//! assertions (the observable `Kstat`) are unchanged.

use vfs::getattr::S_IFREG;
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
        atime_ns: 1_000, mtime_ns: 2_000, ctime_ns: 3_000,
        mode_bits: 0o640, uid: 1234, gid: 5678, owner_set: true,
    }
}

// The inode's stored perm/owner/times surface in the Kstat (formerly supplied
// by the overlay for a None-everything pseudo inode).
#[test]
fn overlay_supplies_metadata_for_pseudo_inode() {
    let i = inode_with(11, 0o640, 1234, 5678, (1_000, 2_000, 3_000));
    let st = vfs::generic_fillattr(&i, &IDENTITY, Some(overlay()));
    assert_eq!(st.mode, S_IFREG | 0o640, "mode = S_IFREG | perm bits");
    assert_eq!(st.uid, 1234);
    assert_eq!(st.gid, 5678);
    assert_eq!(st.atime_ns, 1_000);
    assert_eq!(st.mtime_ns, 2_000);
    assert_eq!(st.ctime_ns, 3_000);
}

// No overlay -> Linux generic defaults (0644 for a regular file, owner 0, t=0).
#[test]
fn no_overlay_uses_generic_defaults() {
    let i = inode_with(11, 0o644, 0, 0, (0, 0, 0));
    let st = vfs::generic_fillattr(&i, &IDENTITY, None);
    assert_eq!(st.mode, S_IFREG | 0o644);
    assert_eq!(st.uid, 0);
    assert_eq!(st.gid, 0);
    assert_eq!((st.atime_ns, st.mtime_ns, st.ctime_ns), (0, 0, 0));
}

// A backend that stores its own metadata WINS over the overlay (overlay is a
// fallback for `None`-returning accessors only — and now always wins).
#[test]
fn native_metadata_overrides_overlay() {
    let i = inode_with(12, 0o600, 7, 8, (111, 222, 333));
    let st = vfs::generic_fillattr(&i, &IDENTITY, Some(overlay()));
    assert_eq!(st.mode, S_IFREG | 0o600, "native perm, not overlay 0640");
    assert_eq!((st.uid, st.gid), (7, 8), "native owner, not overlay 1234/5678");
    assert_eq!((st.atime_ns, st.mtime_ns, st.ctime_ns), (111, 222, 333),
        "native times, not overlay 1000/2000/3000");
}
