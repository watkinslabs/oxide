//! The type-confusion case and the three errno contracts.
//!
//! The errnos are held here rather than restated in a comment: `admit_ring_fd`
//! reports EOPNOTSUPP for a live non-ring fd (io_uring's own resolve step, not
//! the caller's EBADF/EINVAL), and `admit_fixed_file` reports EBADF for a ring
//! offered as a fixed file. If either ever drifts, these fail.

use alloc::sync::Arc;

use vfs::{default_inode_ops, mk_mode, Dentry, FileOps, FileType, Ino, InodeBuilder, InodeRef, OpenFlags};

use super::{admit_fixed_file, admit_ring_fd, is_io_uring_file};

/// Stand-in for the vtable `make_io_uring_inode` installs — the one vtable
/// that answers yes, exactly as `io_uring_fops` is the one Linux compares to.
struct RingFileOps;
impl FileOps for RingFileOps {
    fn is_io_uring(&self) -> bool { true }
}

/// Any other vtable. The default answer is no, so a family that never heard of
/// io_uring cannot be mistaken for one.
struct OtherFileOps;
impl FileOps for OtherFileOps {}

fn inode(ino: Ino, ops: Arc<dyn FileOps>) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), ops).build()
}

fn file(inode: InodeRef) -> Arc<vfs::File> {
    let dentry = Dentry::new_root(Arc::clone(&inode));
    vfs::File::new(inode, dentry, OpenFlags::O_RDWR)
}

/// A number io_uring itself would mint.
fn a_ring_number() -> Ino { vfs::pseudo_ino::IO_URING.at(7) }

#[test]
fn a_real_ring_resolves() {
    let f = file(inode(a_ring_number(), Arc::new(RingFileOps)));
    assert!(is_io_uring_file(&f));
    assert_eq!(admit_ring_fd(&f), Ok(()));
}

/// The type-confusion case: a foreign description carrying io_uring's exact
/// inode number. The number test admitted it; `io_uring_enter` then read its
/// unrelated `i_private` as an `IoUringInode`.
#[test]
fn a_foreign_inode_carrying_a_ring_number_is_refused() {
    let f = file(inode(a_ring_number(), Arc::new(OtherFileOps)));
    assert!(!is_io_uring_file(&f));
    assert_eq!(admit_ring_fd(&f), Err(syscall::errno::Errno::Eopnotsupp));
    assert_eq!(admit_fixed_file(&f), Ok(()));
}

/// The tag's own base, the number the old high-half test keyed on.
#[test]
fn a_foreign_inode_carrying_the_ring_tag_base_is_refused() {
    let f = file(inode(vfs::pseudo_ino::IO_URING.start(), Arc::new(OtherFileOps)));
    assert!(!is_io_uring_file(&f));
    assert_eq!(admit_ring_fd(&f), Err(syscall::errno::Errno::Eopnotsupp));
}

/// The caller gets io_uring's own "not a ring" errno, not a stolen operation:
/// EOPNOTSUPP, which is what `io_uring_ctx_get_file()` reports for a live fd
/// that is something else.
#[test]
fn a_non_ring_fd_reports_eopnotsupp_not_einval_or_ebadf() {
    let f = file(inode(0x1234, Arc::new(OtherFileOps)));
    let e = admit_ring_fd(&f).unwrap_err();
    assert_eq!(e, syscall::errno::Errno::Eopnotsupp);
    assert_ne!(e, syscall::errno::Errno::Einval);
    assert_ne!(e, syscall::errno::Errno::Ebadf);
}

/// A ring may not be registered as a fixed file — that is what stops a ring
/// from pinning itself — and the verdict is EBADF.
#[test]
fn a_ring_offered_as_a_fixed_file_reports_ebadf() {
    let f = file(inode(a_ring_number(), Arc::new(RingFileOps)));
    assert_eq!(admit_fixed_file(&f), Err(syscall::errno::Errno::Ebadf));
}

/// A ring identifies as one wherever its number lands, so the answer does not
/// depend on the number space staying partitioned.
#[test]
fn identity_does_not_depend_on_the_number() {
    for ino in [0u64, 1, 0x7400_0001, vfs::pseudo_ino::PIPE.start(), u64::MAX] {
        assert!(is_io_uring_file(&file(inode(ino, Arc::new(RingFileOps)))));
        assert!(!is_io_uring_file(&file(inode(ino, Arc::new(OtherFileOps)))));
    }
}

/// Ring numbers stay inside io_uring's declared range however many rings are
/// created — the low half comes from the shared anon-inode counter, which now
/// has a bound of its own.
#[test]
fn ring_numbers_stay_inside_the_io_uring_region() {
    let r = &vfs::pseudo_ino::IO_URING;
    for n in [0u64, 1, u32::MAX as u64, r.len(), r.len() * 3 + 1, u64::MAX] {
        assert!(r.contains(r.at(n)), "index {n} left the io_uring region");
    }
    for _ in 0..1024 { assert!(r.contains(r.at(vfs::get_next_ino() as u64))); }
}
