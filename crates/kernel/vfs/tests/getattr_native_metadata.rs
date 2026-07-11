//! `generic_fillattr` reads concrete inode metadata directly.

use vfs::getattr::{generic_fillattr, S_IFREG};
use vfs::idmap::Idmap;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeBuilder, InodeRef, IDENTITY};

fn inode(ino: u64, perm: u16, uid: u32, gid: u32, times: (u64, u64, u64)) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(uid, gid)
        .times(times.0, times.1, times.2)
        .build()
}

#[test]
fn fillattr_reports_native_mode_owner_and_times() {
    let i = inode(11, 0o640, 1234, 5678, (111, 222, 333));
    let st = generic_fillattr(&i, &IDENTITY);
    assert_eq!(st.mode, S_IFREG | 0o640);
    assert_eq!((st.uid, st.gid), (1234, 5678));
    assert_eq!((st.atime_ns, st.mtime_ns, st.ctime_ns), (111, 222, 333));
}

#[test]
fn fillattr_maps_native_owner_ids_through_mount_idmap() {
    let i = inode(12, 0o600, 1000, 2000, (0, 0, 0));
    let map = Idmap::uniform(0, 10_000, 5_000);
    let st = generic_fillattr(&i, &map);
    assert_eq!(st.uid, 11_000);
    assert_eq!(st.gid, 12_000);
}
