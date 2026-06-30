//! inode-D17: the legacy pointer-keyed `inode_times` overlay store is gone. The
//! concrete `struct Inode` owns its `i_atime`/`i_mtime`/`i_ctime`/`i_mode`/owner
//! fields, so `generic_fillattr` reads them DIRECTLY and the overlay argument is
//! never consulted. `inode_times::get` is now always `None`; the `set*` shims
//! are inert (retained only for cross-lane callers).

use vfs::getattr::{generic_fillattr, S_IFREG};
use vfs::inode_times::{self, InodeTimes};
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeBuilder, InodeRef, IDENTITY};

fn inode(ino: u64, perm: u16, uid: u32, gid: u32, t: (u64, u64, u64)) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(uid, gid).times(t.0, t.1, t.2).build()
}

/// The overlay store no longer exists: `get` returns `None`, and the `set*`
/// shims do not resurrect it.
#[test]
fn overlay_store_is_gone() {
    let i = inode(11, 0o644, 0, 0, (1, 2, 3));
    assert!(inode_times::get(&i).is_none(), "no overlay store: get == None");
    inode_times::set(&i, Some(50), Some(60), 70);
    inode_times::set_mode(&i, 0o777, 70);
    inode_times::set_owner(&i, 4242, 4343, 70);
    assert!(inode_times::get(&i).is_none(), "set* shims are inert");
}

/// `generic_fillattr` reads the inode's OWN fields and ignores a (bogus)
/// overlay argument entirely.
#[test]
fn generic_fillattr_ignores_overlay_uses_inode_fields() {
    let i = inode(12, 0o640, 100, 200, (111, 222, 333));
    let bogus = InodeTimes {
        atime_ns: 9, mtime_ns: 9, ctime_ns: 9,
        mode_bits: 0o111, uid: 7, gid: 7, owner_set: true,
    };
    let st = generic_fillattr(&i, &IDENTITY, Some(bogus));
    assert_eq!(st.mode, S_IFREG | 0o640, "inode mode, not overlay 0o111");
    assert_eq!((st.uid, st.gid), (100, 200), "inode owner, not overlay 7/7");
    assert_eq!((st.atime_ns, st.mtime_ns, st.ctime_ns), (111, 222, 333),
        "inode times, not overlay 9/9/9");
}
