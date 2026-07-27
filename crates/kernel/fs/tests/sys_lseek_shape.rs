extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::inode::Inode;
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, InodeRef, KResult, OpenFlags, VfsError,
          default_file_ops, default_inode_ops, mk_mode};

#[path = "../../syscalls/src/008_lseek.rs"]
mod lseek_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x1508);

struct OkOps;

impl FileOps for OkOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(buf.len()) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: tests store only leaked Task pointers and clear the hook pointer before returning.
        Some(unsafe { &*p })
    }
}

fn args(fd: u64, off: i64, whence: i32) -> SyscallArgs {
    SyscallArgs { a0: fd, a1: off as u64, a2: whence as u32 as u64, a3: 0, a4: 0, a5: 0 }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
}

fn install_current_with_fdt(fdt: Option<Arc<FdTable>>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x1508, "lseek-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn mk_file(ft: FileType, flags: OpenFlags, size: u64) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(ft, 0o644), default_inode_ops(), Arc::new(OkOps)).size(size).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, flags)
}

fn mk_default_regular(size: u64) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).size(size).build();
    let dentry = Dentry::new_root(Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDWR)
}

#[test]
fn sys_lseek_ebadf_paths_precede_whence_validation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    assert_eq!(lseek_syscall::sys_lseek(&args(0, 0, 99)), -(Errno::Ebadf.as_i32() as i64));

    install_current_with_fdt(None);
    assert_eq!(lseek_syscall::sys_lseek(&args(0, 0, 99)), -(Errno::Ebadf.as_i32() as i64));

    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(fdt));
    assert_eq!(lseek_syscall::sys_lseek(&args(9, 0, 99)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(lseek_syscall::sys_lseek(&args(u64::MAX, 0, 99)), -(Errno::Ebadf.as_i32() as i64));
    reset();
}

#[test]
fn sys_lseek_matches_linux_unsigned_int_fd_truncation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_default_regular(16);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    assert_eq!(fd, 0);
    install_current_with_fdt(Some(fdt));

    assert_eq!(lseek_syscall::sys_lseek(&args(0x1_0000_0000, 3, 0)), 3);
    assert_eq!(file.pos(), 3);
    reset();
}

#[test]
fn sys_lseek_bad_whence_beats_seekability_after_fd_lookup() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(FileType::Fifo, OpenFlags::O_RDWR, 0)).unwrap();
    install_current_with_fdt(Some(fdt));

    assert_eq!(lseek_syscall::sys_lseek(&args(fd as u64, 0, 99)), -(Errno::Einval.as_i32() as i64));
    assert_eq!(lseek_syscall::sys_lseek(&args(fd as u64, 0, 0)), -(VfsError::Espipe as i64));
    reset();
}

#[test]
fn sys_lseek_regular_file_generic_cases_and_rejected_seek_preserves_pos() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_default_regular(8);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    install_current_with_fdt(Some(fdt));

    assert_eq!(lseek_syscall::sys_lseek(&args(fd as u64, 2, 0)), 2);
    assert_eq!(lseek_syscall::sys_lseek(&args(fd as u64, 3, 1)), 5);
    assert_eq!(lseek_syscall::sys_lseek(&args(fd as u64, -1, 2)), 7);
    assert_eq!(lseek_syscall::sys_lseek(&args(fd as u64, -9, 2)), -(Errno::Einval.as_i32() as i64));
    assert_eq!(file.pos(), 7);
    reset();
}

#[test]
fn sys_lseek_seek_data_and_hole_follow_generic_non_sparse_rules() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_default_regular(8)).unwrap();
    install_current_with_fdt(Some(fdt));

    assert_eq!(lseek_syscall::sys_lseek(&args(fd as u64, 0, 3)), 0);
    assert_eq!(lseek_syscall::sys_lseek(&args(fd as u64, 0, 4)), 8);
    assert_eq!(lseek_syscall::sys_lseek(&args(fd as u64, 8, 3)), -(VfsError::Enxio as i64));
    assert_eq!(lseek_syscall::sys_lseek(&args(fd as u64, -1, 3)), -(Errno::Einval.as_i32() as i64));
    reset();
}
