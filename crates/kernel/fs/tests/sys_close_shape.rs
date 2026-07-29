// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use std::sync::Mutex;
use core::sync::atomic::{AtomicPtr, Ordering};

use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, OpenFlags, default_file_ops, default_inode_ops, mk_mode};

#[path = "../../syscalls/src/003_close.rs"]
mod close_syscall;

/// Every test here mutates the process-global `CURRENT`; cargo runs them on
/// concurrent threads, so one test's `install_current` was being observed by
/// another's syscall. Serialize them (same guard as `sys_dup2_shape`).
static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: tests store only leaked Task pointers and clear the hook pointer before returning.
        Some(unsafe { &*p })
    }
}

fn args(fd: u64) -> SyscallArgs {
    SyscallArgs { a0: fd, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn mk_file(ino: u64) -> Arc<File> {
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops()).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

fn install_current_with_fdt(fdt: Option<Arc<FdTable>>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0xC103, "close-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

#[test]
fn sys_close_uses_current_fdtable_and_removes_before_return() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(0xC103)).unwrap();
    assert_eq!(fd, 0);
    install_current_with_fdt(Some(Arc::clone(&fdt)));

    assert_eq!(close_syscall::sys_close(&args(fd as u64)), 0);
    assert_eq!(fdt.get(fd).unwrap_err(), vfs::VfsError::Ebadf);
    assert_eq!(close_syscall::sys_close(&args(fd as u64)), -(Errno::Ebadf.as_i32() as i64));

    CURRENT.store(ptr::null_mut(), Ordering::Release);
}

#[test]
fn sys_close_matches_linux_unsigned_int_fd_truncation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(0xC104)).unwrap();
    assert_eq!(fd, 0);
    install_current_with_fdt(Some(Arc::clone(&fdt)));

    assert_eq!(close_syscall::sys_close(&args(0x1_0000_0000)), 0);
    assert_eq!(fdt.get(fd).unwrap_err(), vfs::VfsError::Ebadf);
    assert_eq!(close_syscall::sys_close(&args(u64::MAX)), -(Errno::Ebadf.as_i32() as i64));

    CURRENT.store(ptr::null_mut(), Ordering::Release);
}

#[test]
fn sys_close_without_current_or_fdtable_is_ebadf() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    sched::set_current_hook(hooked_current);
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    assert_eq!(close_syscall::sys_close(&args(0)), -(Errno::Ebadf.as_i32() as i64));

    install_current_with_fdt(None);
    assert_eq!(close_syscall::sys_close(&args(0)), -(Errno::Ebadf.as_i32() as i64));

    CURRENT.store(ptr::null_mut(), Ordering::Release);
}
