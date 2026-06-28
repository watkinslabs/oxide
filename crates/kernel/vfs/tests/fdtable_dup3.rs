//! fdtable-D17: `dup3(2)` semantics over the real `FdTable`. `dup3`
//! was named in the module header's op set but had no method — only
//! `dup2` existed. It differs from `dup2` on the points Linux
//! `ksys_dup3` enforces, asserted here:
//!   - `O_CLOEXEC` in `flags` sets FD_CLOEXEC on the new fd atomically
//!     with the install; absent, it clears (even over a cloexec target).
//!   - `old_fd == new_fd` → EINVAL (dup2 returns new_fd as a no-op).
//!   - equal-AND-invalid fds → EINVAL (the equal check precedes the
//!     validity check), NOT EBADF.
//!   - flag bits other than `O_CLOEXEC` → EINVAL.
//!   - `new_fd` out of range → EBADF; bad `old_fd` → EBADF.
//!   - a live target fd is closed/replaced (and its slot taken over).

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, FdTable, File, FileType, InodeRef, KResult, OpenFlags, VfsError, FD_TABLE_MAX};

struct Dummy;
impl Inode for Dummy {
    fn ino(&self) -> vfs::Ino { 0x1 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

fn mk_file() -> Arc<File> {
    let ino: InodeRef = Arc::new(Dummy);
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDWR)
}

/// `dup3(old, new, O_CLOEXEC)` sets FD_CLOEXEC on the new fd while the
/// source fd keeps its own (clear) flag — fd flags are per-slot.
#[test]
fn dup3_o_cloexec_sets_target_flag() {
    let t = FdTable::new();
    let old = t.alloc(mk_file()).unwrap();
    let new = old + 10;
    assert_eq!(t.dup3(old, new, OpenFlags::O_CLOEXEC), Ok(new));
    assert_eq!(t.cloexec(new), Ok(true), "O_CLOEXEC flag must mark the new fd");
    assert_eq!(t.cloexec(old), Ok(false), "source fd flag is independent");
    // Both fds resolve to the same shared open file description.
    assert!(Arc::ptr_eq(&t.get(old).unwrap(), &t.get(new).unwrap()));
}

/// `dup3` without `O_CLOEXEC` clears the flag even when the target slot
/// previously held a cloexec fd (the install overwrites the bit).
#[test]
fn dup3_no_flag_clears_existing_cloexec_target() {
    let t = FdTable::new();
    let old = t.alloc(mk_file()).unwrap();
    let new = t.alloc(mk_file()).unwrap();
    t.set_cloexec(new, true).unwrap();
    assert_eq!(t.cloexec(new), Ok(true));
    assert_eq!(t.dup3(old, new, OpenFlags::empty()), Ok(new));
    assert_eq!(t.cloexec(new), Ok(false), "dup3 w/o O_CLOEXEC clears the target flag");
}

/// `old_fd == new_fd` is EINVAL (dup2's no-op semantics do NOT apply).
#[test]
fn dup3_equal_fds_is_einval_not_noop() {
    let t = FdTable::new();
    let fd = t.alloc(mk_file()).unwrap();
    assert_eq!(t.dup3(fd, fd, OpenFlags::empty()), Err(VfsError::Einval),
        "dup3 with old==new must be EINVAL, never a no-op");
}

/// Equal fds are rejected BEFORE validity is checked, so an equal pair
/// pointing at a closed/never-opened fd is still EINVAL, not EBADF.
#[test]
fn dup3_equal_invalid_fds_is_einval() {
    let t = FdTable::new();
    assert_eq!(t.dup3(7, 7, OpenFlags::empty()), Err(VfsError::Einval),
        "equal-fd check precedes fd validity → EINVAL, not EBADF");
}

/// A flag bit other than `O_CLOEXEC` → EINVAL (checked first of all).
#[test]
fn dup3_bad_flags_is_einval() {
    let t = FdTable::new();
    let old = t.alloc(mk_file()).unwrap();
    assert_eq!(t.dup3(old, old + 1, OpenFlags::O_NONBLOCK), Err(VfsError::Einval),
        "non-O_CLOEXEC flag bit must be EINVAL");
}

/// `new_fd` at/above the RLIMIT_NOFILE ceiling → EBADF (not EMFILE).
#[test]
fn dup3_newfd_out_of_range_is_ebadf() {
    let t = FdTable::new();
    let old = t.alloc(mk_file()).unwrap();
    assert_eq!(t.dup3(old, FD_TABLE_MAX as i32, OpenFlags::empty()), Err(VfsError::Ebadf));
    assert_eq!(t.dup3(old, -2, OpenFlags::empty()), Err(VfsError::Ebadf));
}

/// Bad (non-equal) `old_fd` → EBADF, surfaced after the range checks.
#[test]
fn dup3_bad_oldfd_is_ebadf() {
    let t = FdTable::new();
    assert_eq!(t.dup3(42, 3, OpenFlags::empty()), Err(VfsError::Ebadf));
    assert_eq!(t.dup3(-1, 3, OpenFlags::empty()), Err(VfsError::Ebadf));
}

/// `dup3` over a live target replaces it: the old occupant is dropped
/// and the slot now resolves to the source's open file description.
#[test]
fn dup3_replaces_live_target() {
    let t = FdTable::new();
    let old = t.alloc(mk_file()).unwrap();
    let victim = t.alloc(mk_file()).unwrap();
    let victim_file = t.get(victim).unwrap();
    assert!(!Arc::ptr_eq(&t.get(old).unwrap(), &victim_file));
    assert_eq!(t.dup3(old, victim, OpenFlags::empty()), Ok(victim));
    assert!(Arc::ptr_eq(&t.get(old).unwrap(), &t.get(victim).unwrap()),
        "target slot now shares the source open file description");
}
