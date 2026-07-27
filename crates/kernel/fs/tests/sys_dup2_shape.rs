extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, InodeRef, OpenFlags, VfsError, default_file_ops, default_inode_ops, mk_mode};

#[path = "../../syscalls/src/033_dup2.rs"]
mod dup2_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_TID: AtomicU64 = AtomicU64::new(0x3300);
static CLONE_CALLS: AtomicUsize = AtomicUsize::new(0);

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: tests store leaked Task pointers and clear the hook before returning.
        Some(unsafe { &*p })
    }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    CLONE_CALLS.store(0, Ordering::Release);
    sched::set_current_hook(hooked_current);
    vfs::set_clone_hook(record_clone);
}

fn args(oldfd: u64, newfd: u64) -> SyscallArgs {
    SyscallArgs { a0: oldfd, a1: newfd, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn record_clone(_ino: &InodeRef, _writable: bool) {
    CLONE_CALLS.fetch_add(1, Ordering::AcqRel);
}

fn mk_file(ino: u64) -> Arc<File> {
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops()).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

fn install_current_with_fdt(fdt: Option<Arc<FdTable>>) -> &'static Task {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    let task = Box::leak(Box::new(Task::new(tid as u32, "dup2-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

#[test]
fn sys_dup2_equal_fd_is_noop_and_validates_oldfd_only() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(0x3301)).unwrap();
    fdt.set_cloexec(fd, true).unwrap();
    let high = fdt.dup_min(fd, 10).unwrap();
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));
    // SAFETY: test task is private to this harness and not concurrently scheduled.
    task.set_rlimit(sched::rlimit::rlim::NOFILE, (4, 4));

    assert_eq!(dup2_syscall::sys_dup2(&args(high as u64, high as u64)), high as i64);
    assert_eq!(fdt.cloexec(high), Ok(false), "oldfd==newfd does not rewrite fd flags");
    assert_eq!(dup2_syscall::sys_dup2(&args(99, 99)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 1, "only setup dup_min cloned a reference");
    reset();
}

#[test]
fn sys_dup2_replaces_target_clears_cloexec_and_fires_one_clone() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let old = fdt.alloc(mk_file(0x3302)).unwrap();
    let new = fdt.alloc(mk_file(0x3303)).unwrap();
    fdt.set_cloexec(new, true).unwrap();
    CLONE_CALLS.store(0, Ordering::Release);
    install_current_with_fdt(Some(Arc::clone(&fdt)));

    assert_eq!(dup2_syscall::sys_dup2(&args(old as u64, new as u64)), new as i64);
    assert!(Arc::ptr_eq(&fdt.get(old).unwrap(), &fdt.get(new).unwrap()));
    assert_eq!(fdt.cloexec(new), Ok(false), "dup2 clears the target FD_CLOEXEC bit");
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 1);
    reset();
}

#[test]
fn sys_dup2_newfd_at_soft_limit_is_ebadf_before_oldfd_lookup() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let old = fdt.alloc(mk_file(0x3304)).unwrap();
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));
    // SAFETY: test task is private to this harness and not concurrently scheduled.
    task.set_rlimit(sched::rlimit::rlim::NOFILE, (4, 4));

    assert_eq!(dup2_syscall::sys_dup2(&args(old as u64, 4)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(dup2_syscall::sys_dup2(&args(99, 4)), -(Errno::Ebadf.as_i32() as i64),
        "ksys_dup3 checks newfd against rlimit before oldfd lookup");
    reset();
}

#[test]
fn sys_dup2_reserved_target_is_ebusy_and_preserves_reservation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let old = fdt.alloc(mk_file(0x3305)).unwrap();
    let reserved = fdt.get_unused_fd_flags(OpenFlags::O_CLOEXEC, vfs::FD_TABLE_MAX).unwrap();
    CLONE_CALLS.store(0, Ordering::Release);
    install_current_with_fdt(Some(Arc::clone(&fdt)));

    assert_eq!(dup2_syscall::sys_dup2(&args(old as u64, reserved as u64)), -(VfsError::Ebusy as i64));
    assert_eq!(fdt.get(reserved).unwrap_err(), VfsError::Ebadf, "reserved slot has no file installed");
    assert_eq!(fdt.cloexec(reserved), Ok(true), "reservation flags remain intact");
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 0);
    fdt.fd_install(reserved, mk_file(0x3306));
    assert!(fdt.get(reserved).is_ok());
    reset();
}

#[test]
fn sys_dup2_matches_linux_unsigned_int_fd_truncation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let old = fdt.alloc(mk_file(0x3307)).unwrap();
    let filler = fdt.alloc(mk_file(0x3308)).unwrap();
    assert_eq!((old, filler), (0, 1));
    install_current_with_fdt(Some(Arc::clone(&fdt)));

    assert_eq!(dup2_syscall::sys_dup2(&args(0x1_0000_0000, 0x1_0000_0001)), 1);
    assert_eq!(dup2_syscall::sys_dup2(&args(u64::MAX, 1)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(dup2_syscall::sys_dup2(&args(0, u64::MAX)), -(Errno::Ebadf.as_i32() as i64));
    reset();
}

#[test]
fn sys_dup2_without_current_or_fdtable_is_ebadf() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    assert_eq!(dup2_syscall::sys_dup2(&args(0, 1)), -(Errno::Ebadf.as_i32() as i64));

    install_current_with_fdt(None);
    assert_eq!(dup2_syscall::sys_dup2(&args(0, 1)), -(Errno::Ebadf.as_i32() as i64));
    reset();
}
