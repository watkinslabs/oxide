//! F761: Linux `getname_maybe_null` target selection for the `*xattrat` (463-466)
//! and `file_{get,set}attr` (468/469) families, driven through the real
//! `pathresolve::at` module.
//!
//! Two Linux facts are pinned here, both of which the pre-F761 shims got wrong
//! because they routed every `*xattrat` call through `resolve_at_lookup`:
//!
//!   1. `AT_EMPTY_PATH` + a **NULL** pathname is legal and means "operate on
//!      `dfd`" (`fs/xattr.c:726`, `include/linux/fs.h:2541`). The old code sent
//!      a NULL pointer straight to `at_path_empty`, which is unconditionally
//!      `EFAULT` — so `fsetxattr`-shaped calls could never work.
//!   2. `list`/`removexattrat` omit the `dfd >= 0` guard that `set`/`getxattrat`
//!      carry (`fs/xattr.c:992`, `:1089` vs `:726`, `:866`), so a NULL filename
//!      with `AT_FDCWD` is `EBADF` for those two and the **cwd** for the others.
//!
//! Stubs mirror `openat_absolute_dirfd_hosted.rs`: `at.rs` reaches
//! `pathresolve::{cred,root}` and `namei_common` via `super::`/`crate::`, and
//! its `#![cfg(any(target_os = "oxide-kernel", test))]` gate makes the real
//! module reachable through `#[path]` under `cfg(test)`.

// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
extern crate alloc;

use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::at::{AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW};
use syscall::errno::Errno;
use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, InodeRef, OpenFlags, VfsPath,
    default_file_ops, default_inode_ops, mk_mode};

#[path = "../src/pathresolve/at.rs"]
mod at;

mod cred {
    pub(crate) fn current_cred() -> vfs::Cred { vfs::Cred::root() }
}

mod root {
    use std::sync::Mutex;
    static ROOT: Mutex<Option<(vfs::VfsPath, bool)>> = Mutex::new(None);
    pub(crate) fn set(root: vfs::VfsPath) { *ROOT.lock().unwrap() = Some((root, false)); }
    pub(crate) fn clear() { *ROOT.lock().unwrap() = None; }
    pub(crate) fn resolution_root_vfs() -> Option<(vfs::VfsPath, bool)> { ROOT.lock().unwrap().clone() }
}

// `at.rs` only reaches these two on paths this file never drives (a non-NULL,
// non-empty pathname). Present so the module type-checks whole.
mod namei_common {
    pub(crate) fn errno_from_vfs(_e: vfs::VfsError) -> i64 {
        -(syscall::errno::Errno::Enoent.as_i32() as i64)
    }
    pub(crate) fn read_user_path(_ptr: u64) -> Result<alloc::string::String, i64> {
        Err(-(syscall::errno::Errno::Efault.as_i32() as i64))
    }
}

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_TID: AtomicU64 = AtomicU64::new(0x7610);

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    // SAFETY: tests store leaked Task pointers and clear the hook before returning.
    if p.is_null() { None } else { Some(unsafe { &*p }) }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    root::clear();
}

fn install_current_with_fdt(fdt: std::sync::Arc<FdTable>) {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    let task = Box::leak(Box::new(Task::new(tid as u32, "f761-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
}

fn regular_file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

const ROOT_INO: u64 = 2;
const TARGET_INO: u64 = 77;

/// Installs a root `/` and a task whose fd 0 is a regular file (`TARGET_INO`).
fn setup() -> i32 {
    let root_inode = InodeBuilder::new(ROOT_INO, mk_mode(FileType::Directory, 0o755),
                                       default_inode_ops(), default_file_ops()).build();
    let root_dentry = Dentry::new_root(root_inode.clone());
    root::set(VfsPath { mnt_id: 1, dentry: root_dentry, inode: root_inode, last_component: None });

    let inode = regular_file(TARGET_INO);
    let dentry = Dentry::new_root(inode.clone());
    let fdt = std::sync::Arc::new(FdTable::new());
    let fd = fdt.alloc(File::new(inode, dentry, OpenFlags::O_RDWR)).unwrap();
    install_current_with_fdt(fdt);
    fd
}

fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }
fn ebadf() -> i64 { -(Errno::Ebadf.as_i32() as i64) }

// --- set/getxattrat + file_{get,set}attr: `!filename && dfd >= 0` ---------

#[test]
fn null_path_with_at_empty_path_targets_the_open_fd() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fd = setup();
    let p = at::resolve_at_or_dirfd(fd, 0, AT_EMPTY_PATH).expect("NULL + AT_EMPTY_PATH is legal");
    assert_eq!(p.inode.ino(), TARGET_INO);
    reset();
}

#[test]
fn null_path_with_at_fdcwd_falls_through_to_filename_lookup_on_the_cwd() {
    // `if (!filename && dfd >= 0)` is FALSE for AT_FDCWD (-100), so Linux calls
    // `filename_lookup(AT_FDCWD, NULL, …)`, which `__set_nameidata` turns into
    // an empty pathname relative to the cwd (`fs/namei.c`).
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    setup();
    let p = at::resolve_at_or_dirfd(at::AT_FDCWD, 0, AT_EMPTY_PATH).expect("cwd, not EBADF");
    assert_eq!(p.inode.ino(), ROOT_INO);
    reset();
}

#[test]
fn null_path_without_at_empty_path_is_efault() {
    // `getname(NULL)` — no `AT_EMPTY_PATH`, no shortcut.
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fd = setup();
    assert_eq!(at::resolve_at_or_dirfd(fd, 0, 0).err(), Some(efault()));
    assert_eq!(at::resolve_at_or_dirfd(fd, 0, AT_SYMLINK_NOFOLLOW).err(), Some(efault()));
    assert_eq!(at::resolve_at_or_dirfd(at::AT_FDCWD, 0, 0).err(), Some(efault()));
    reset();
}

#[test]
fn null_path_with_a_closed_dirfd_is_ebadf() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    setup();
    assert_eq!(at::resolve_at_or_dirfd(99, 0, AT_EMPTY_PATH).err(), Some(ebadf()));
    reset();
}

// --- list/removexattrat: `!filename` with NO `dfd >= 0` guard -------------

#[test]
fn list_and_remove_send_a_null_path_to_the_fd_table_even_for_at_fdcwd() {
    // `path_listxattrat`/`path_removexattrat` call `CLASS(fd, f)(dfd)`
    // unconditionally, and `fd_empty(AT_FDCWD)` is true → EBADF. This is the
    // one place the two halves of the family genuinely disagree.
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fd = setup();
    assert_eq!(at::resolve_at_or_fd(at::AT_FDCWD, 0, AT_EMPTY_PATH).err(), Some(ebadf()));
    let p = at::resolve_at_or_fd(fd, 0, AT_EMPTY_PATH).expect("a real fd still works");
    assert_eq!(p.inode.ino(), TARGET_INO);
    assert_eq!(at::resolve_at_or_fd(fd, 0, 0).err(), Some(efault()), "no AT_EMPTY_PATH, NULL is EFAULT");
    assert_eq!(at::resolve_at_or_fd(-7, 0, AT_EMPTY_PATH).err(), Some(ebadf()));
    reset();
}
