//! `generic_fillattr` reads concrete inode metadata directly.

use vfs::getattr::{generic_fillattr, S_IFREG};
use vfs::idmap::Idmap;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeBuilder, InodeRef, Timespec64, IDENTITY};

fn inode(ino: u64, perm: u16, uid: u32, gid: u32, times: (Timespec64, Timespec64, Timespec64)) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(uid, gid)
        .times(times.0, times.1, times.2)
        .build()
}

#[test]
fn fillattr_reports_native_mode_owner_and_times() {
    let i = inode(11, 0o640, 1234, 5678,
        (Timespec64::new(111, 1), Timespec64::new(222, 2), Timespec64::new(333, 3)));
    let st = generic_fillattr(&i, &IDENTITY);
    assert_eq!(st.mode, S_IFREG | 0o640);
    assert_eq!((st.uid, st.gid), (1234, 5678));
    assert_eq!((st.atime, st.mtime, st.ctime),
        (Timespec64::new(111, 1), Timespec64::new(222, 2), Timespec64::new(333, 3)));
}

#[test]
fn fillattr_maps_native_owner_ids_through_mount_idmap() {
    let i = inode(12, 0o600, 1000, 2000, (Timespec64::ZERO, Timespec64::ZERO, Timespec64::ZERO));
    let map = Idmap::uniform(0, 10_000, 5_000);
    let st = generic_fillattr(&i, &map);
    assert_eq!(st.uid, 11_000);
    assert_eq!(st.gid, 12_000);
}

/// F767: a PRE-1970 inode timestamp reaches `Kstat` with its signed seconds
/// intact. Under the old unsigned model this value could not be stored at all.
#[test]
fn fillattr_reports_pre_epoch_times_as_negative_seconds() {
    let t = Timespec64::new(-2_000_000_000, 123_456_789); // 1906-08-16
    let i = inode(13, 0o644, 0, 0, (t, t, t));
    let st = vfs::generic_fillattr(&i, &IDENTITY);
    assert_eq!(st.atime.sec, -2_000_000_000, "seconds stay negative, not reinterpreted huge");
    assert_eq!(st.atime.nsec, 123_456_789, "sub-second field non-negative and preserved");
    assert_eq!((st.atime, st.mtime, st.ctime), (t, t, t));
}
