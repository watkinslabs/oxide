// `file_getattr(2)` / `file_setattr(2)` (468/469) and `FS_IOC_FSGETXATTR`
// (ioctl slot 16) over the REAL `/dev` tree.
//
// Reference contract these tests encode (verified against the reference kernel,
// not from memory): the device filesystem is a shmem-backed mount, so its
// DIRECTORIES carry the shmem fileattr vector and report a chattr word. Its
// DEVICE NODES do not — a special inode (char/block/fifo/socket) gets the
// special-inode op vector, which has no fileattr entry, so the ABI edge reports
// `EOPNOTSUPP` there. Symlink leaves likewise carry no fileattr entry.
//
// The device-node and symlink cases are the reason the fix is scoped to the
// directory tree: promoting every `/dev` inode would DIVERGE from the
// reference, not converge on it.

use vfs::{FileAttr, VfsError};
use vfs::inode::{FS_IMMUTABLE_FL, FS_SYNC_FL};

use crate::tests::TEST_SERIAL;

/// Directory unique to this file so a concurrent test never observes it.
const DIR_PATH: &str = "/dev/b1976attr/inner";

#[test]
fn dev_directories_report_a_chattr_word() {
    let _g = TEST_SERIAL.lock().unwrap();
    crate::register_dir(DIR_PATH);
    for p in ["/dev", "/dev/b1976attr", DIR_PATH] {
        let i = crate::lookup(p).expect("dev dir");
        let fa = i.fileattr_get().unwrap_or_else(|e| panic!("get {p}: {e:?}"));
        assert_eq!(fa.flags, 0, "fresh dir has no chattr flags: {p}");
        assert_eq!(fa.fsx_xflags, 0, "fresh dir has no xflags: {p}");
    }
}

#[test]
fn dev_directory_accepts_immutable_and_rejects_the_rest() {
    let _g = TEST_SERIAL.lock().unwrap();
    crate::register_dir(DIR_PATH);
    let i = crate::lookup(DIR_PATH).expect("dev dir");
    i.fileattr_set(&FileAttr { flags: FS_IMMUTABLE_FL, ..Default::default() }).expect("set +i");
    assert_eq!(i.fileattr_get().expect("get").flags & FS_IMMUTABLE_FL, FS_IMMUTABLE_FL);
    assert_eq!(i.fileattr_set(&FileAttr { flags: FS_SYNC_FL, ..Default::default() }).err(),
               Some(VfsError::Eopnotsupp));
    i.fileattr_set(&FileAttr::default()).expect("clear");
    assert_eq!(i.fileattr_get().expect("get").flags, 0);
}

/// A special inode carries no fileattr vector in the reference; the ABI edge
/// turns the no-vector errno into `EOPNOTSUPP`.
#[test]
fn dev_device_nodes_have_no_fileattr_vector() {
    let _g = TEST_SERIAL.lock().unwrap();
    let _ = crate::boot::try_populate_defaults();
    for p in ["/dev/null", "/dev/zero", "/dev/full"] {
        let i = crate::lookup(p).expect("dev node");
        assert_eq!(i.fileattr_get().err(), Some(VfsError::Enotty), "get {p}");
        assert_eq!(i.fileattr_set(&FileAttr::default()).err(), Some(VfsError::Enotty),
                   "set {p}");
    }
}
