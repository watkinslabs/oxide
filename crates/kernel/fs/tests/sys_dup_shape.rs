extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, InodeRef, OpenFlags, VfsError, default_file_ops, default_inode_ops, mk_mode};

#[path = "../../syscalls/src/032_dup.rs"]
mod dup_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_TID: AtomicU64 = AtomicU64::new(0x3200);
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

fn args(fd: u64) -> SyscallArgs {
    SyscallArgs { a0: fd, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }
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
    let task = Box::leak(Box::new(Task::new(tid as u32, "dup-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

#[test]
fn sys_dup_uses_current_fdtable_lowest_free_and_clears_cloexec() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let old = fdt.alloc(mk_file(0x3201)).unwrap();
    let filler = fdt.alloc(mk_file(0x3202)).unwrap();
    assert_eq!((old, filler), (0, 1));
    assert_eq!(fdt.close(filler), Ok(()));
    fdt.set_cloexec(old, true).unwrap();
    install_current_with_fdt(Some(Arc::clone(&fdt)));

    let new = dup_syscall::sys_dup(&args(old as u64));
    assert_eq!(new, 1, "dup allocates the lowest free fd below RLIMIT_NOFILE");
    assert!(Arc::ptr_eq(&fdt.get(old).unwrap(), &fdt.get(new as i32).unwrap()));
    assert_eq!(fdt.cloexec(old), Ok(true), "source fd flags are per descriptor");
    assert_eq!(fdt.cloexec(new as i32), Ok(false), "dup installs with FD_CLOEXEC clear");
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 1, "dup announces one extra fd-table reference");
    reset();
}

#[test]
fn sys_dup_invalid_oldfd_wins_before_emfile() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));
    // SAFETY: test task is private to this harness and not concurrently scheduled.
    task.set_rlimit(sched::rlimit::rlim::NOFILE, (0, 0));

    assert_eq!(dup_syscall::sys_dup(&args(7)), -(Errno::Ebadf.as_i32() as i64),
        "Linux sys_dup fget_raw(oldfd) precedes get_unused_fd_flags");
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 0);
    reset();
}

#[test]
fn sys_dup_reports_emfile_when_no_slot_below_soft_limit() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let old = fdt.alloc(mk_file(0x3203)).unwrap();
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));
    // SAFETY: test task is private to this harness and not concurrently scheduled.
    task.set_rlimit(sched::rlimit::rlim::NOFILE, (1, 1));

    assert_eq!(dup_syscall::sys_dup(&args(old as u64)), -(VfsError::Emfile as i64));
    assert_eq!(fdt.count(), 1, "failed dup leaves fd table unchanged");
    assert_eq!(fdt.live_fds(), vec![old]);
    assert_eq!(CLONE_CALLS.load(Ordering::Acquire), 0,
        "temporary fget_raw-style references are not fd-table clone events");
    reset();
}

#[test]
fn sys_dup_without_current_or_fdtable_is_ebadf() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    assert_eq!(dup_syscall::sys_dup(&args(0)), -(Errno::Ebadf.as_i32() as i64));

    install_current_with_fdt(None);
    assert_eq!(dup_syscall::sys_dup(&args(0)), -(Errno::Ebadf.as_i32() as i64));
    reset();
}
