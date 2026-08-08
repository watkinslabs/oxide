// Which `i_op->fileattr_{get,set}` surface a pseudo-directory publishes, and
// the guarantee that adding a shmem-backed variant did not change the pseudo
// default.
//
// Reference contract these tests encode (verified against the reference kernel,
// not from memory):
//   * A pseudo-filesystem directory (sysfs/procfs/tracefs/devpts/cgroup/…)
//     installs NO fileattr vector, so `file_getattr(2)`/`file_setattr(2)` and
//     `FS_IOC_FSGETXATTR` report `EOPNOTSUPP` (the ABI edge maps the
//     no-vector errno onto it).
//   * A shmem-backed mount's directory DOES install one: `get` reports the
//     inode's chattr word (0 on a fresh directory) and `set` accepts exactly
//     immutable/append/nodump/noatime/casefold, answering `EOPNOTSUPP` to any
//     other flag bit and to any `fsxattr`-only field.

use alloc::sync::Arc;

use vfs::{FileAttr, VfsError};
use vfs::inode::{FS_APPEND_FL, FS_IMMUTABLE_FL, FS_NOATIME_FL, FS_NODUMP_FL, FS_SYNC_FL,
                 S_APPEND, S_IMMUTABLE};

use crate::{DirFileattr, PseudoDir, PseudoSymlink};

const TEST_FSID: u64 = 0xDEAD;
const ROOT_INO: vfs::Ino = 0x5000_0001;

fn pseudo_root() -> Arc<PseudoDir> { PseudoDir::new_root(ROOT_INO, TEST_FSID) }

fn shmem_root() -> Arc<PseudoDir> {
    PseudoDir::new_root_with_fileattr(ROOT_INO, TEST_FSID, DirFileattr::Shmem)
}

/// The six-plus pseudo filesystems sharing this tree keep answering the
/// no-vector errno — at the root AND at every nested directory, which is where
/// an ops default that failed to inherit would show up.
#[test]
fn pseudo_dir_publishes_no_fileattr_vector() {
    let r = pseudo_root();
    r.ensure_dir_path("/kernel/debug/tracing");
    for p in ["", "/kernel", "/kernel/debug", "/kernel/debug/tracing"] {
        let i = r.lookup_path(p).expect("dir");
        assert_eq!(i.fileattr_get().err(), Some(VfsError::Enotty), "get {p}");
        assert_eq!(i.fileattr_set(&FileAttr::default()).err(), Some(VfsError::Enotty),
                   "set {p}");
    }
}

/// A namespace clone of a pseudo tree must not acquire a vector either.
#[test]
fn pseudo_dir_deep_clone_keeps_no_vector() {
    let r = pseudo_root();
    r.ensure_dir_path("/fs/cgroup");
    let c = r.deep_clone();
    let i = c.lookup_path("/fs/cgroup").expect("cloned dir");
    assert_eq!(i.fileattr_get().err(), Some(VfsError::Enotty));
}

/// A shmem-backed tree's directories report a zero chattr word rather than an
/// error, at the root and at every inherited child.
#[test]
fn shmem_dir_reports_zero_flags() {
    let r = shmem_root();
    r.ensure_dir_path("/pts/inner");
    for p in ["", "/pts", "/pts/inner"] {
        let fa = r.lookup_path(p).expect("dir").fileattr_get().expect("get");
        assert_eq!(fa.flags, 0, "flags {p}");
        assert_eq!(fa.fsx_xflags, 0, "xflags {p}");
    }
}

/// A namespace clone inherits the shmem vector.
#[test]
fn shmem_dir_deep_clone_keeps_vector() {
    let r = shmem_root();
    r.ensure_dir_path("/input");
    let c = r.deep_clone();
    assert!(c.lookup_path("/input").expect("cloned dir").fileattr_get().is_ok());
}

/// The modifiable set round-trips through `i_flags` and back out of `get`.
#[test]
fn shmem_dir_set_modifiable_roundtrip() {
    let r = shmem_root();
    let i = r.as_inode();
    let want = FileAttr { flags: FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL | FS_NOATIME_FL,
                          ..Default::default() };
    i.fileattr_set(&want).expect("set");
    assert_ne!(i.i_flags() & S_IMMUTABLE, 0);
    assert_ne!(i.i_flags() & S_APPEND, 0);
    let got = i.fileattr_get().expect("get");
    assert_eq!(got.flags & (FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL | FS_NOATIME_FL),
               FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL | FS_NOATIME_FL);
    // Clearing back to nothing is the same path in reverse.
    i.fileattr_set(&FileAttr::default()).expect("clear");
    assert_eq!(i.fileattr_get().expect("get").flags, 0);
}

/// A flag outside the modifiable set is `EOPNOTSUPP`, NOT silently accepted —
/// "answers 0 to get" does not mean "accepts anything on set".
#[test]
fn shmem_dir_set_rejects_unmodifiable_flag() {
    let r = shmem_root();
    let fa = FileAttr { flags: FS_SYNC_FL, ..Default::default() };
    assert_eq!(r.as_inode().fileattr_set(&fa).err(), Some(VfsError::Eopnotsupp));
}

/// `fsxattr`-only state has nowhere to live on a shmem inode.
#[test]
fn shmem_dir_set_rejects_fsx_state() {
    let r = shmem_root();
    for fa in [FileAttr { fsx_projid: 7, ..Default::default() },
               FileAttr { fsx_extsize: 4096, ..Default::default() },
               FileAttr { fsx_cowextsize: 4096, ..Default::default() }] {
        assert_eq!(r.as_inode().fileattr_set(&fa).err(), Some(VfsError::Eopnotsupp));
    }
}

/// Symlink leaves carry the generic inode ops in BOTH tree flavours: the
/// reference's shmem symlink vector has no fileattr entry either, so the
/// shmem-backed tree must not have promoted them.
#[test]
fn symlink_leaf_has_no_fileattr_vector_in_either_tree() {
    for r in [pseudo_root(), shmem_root()] {
        r.insert_path("/link", PseudoSymlink::new(2, TEST_FSID, b"/target"));
        let i = r.lookup_path("/link").expect("link");
        assert_eq!(i.fileattr_get().err(), Some(VfsError::Enotty));
    }
}
