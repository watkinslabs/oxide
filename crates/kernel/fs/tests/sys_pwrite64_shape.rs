extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::{Dentry, FdTable, File, FileOps, FileType, Inode, InodeBuilder, KResult,
          OpenFlags, VfsError, default_inode_ops, mk_mode};

mod namei_common {
    pub(crate) fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
}

mod userbuf {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use syscall::errno::Errno;

    pub static VALIDATE_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static VALIDATE_LEN: AtomicU64 = AtomicU64::new(0);
    pub static CLAMP_INPUT: AtomicUsize = AtomicUsize::new(0);
    pub const TEST_MAX_RW_COUNT: usize = 8;

    pub fn reset() {
        VALIDATE_CALLS.store(0, Ordering::SeqCst);
        VALIDATE_LEN.store(0, Ordering::SeqCst);
        CLAMP_INPUT.store(0, Ordering::SeqCst);
    }

    pub fn validate_user_buf_readable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        VALIDATE_CALLS.fetch_add(1, Ordering::SeqCst);
        VALIDATE_LEN.store(len, Ordering::SeqCst);
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }

    pub fn clamp_rw_count(n: usize) -> usize {
        CLAMP_INPUT.store(n, Ordering::SeqCst);
        core::cmp::min(n, TEST_MAX_RW_COUNT)
    }
}

mod write_common {
    pub fn positional_write_pos(file: &vfs::File, off: u64) -> u64 {
        if file.flags().contains(vfs::OpenFlags::O_APPEND) { file.inode().size() } else { off }
    }

    pub fn rlimit_fsize_cap(_cur: &sched::Task, _file: &vfs::File, _pos: u64, len: usize,
                            _signal_on_efbig: bool) -> Result<usize, i64> {
        Ok(len)
    }
}

#[path = "../../syscalls/src/018_pwrite64.rs"]
mod pwrite64_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static WRITE_OFF: AtomicU64 = AtomicU64::new(u64::MAX);
static WRITE_LEN: AtomicUsize = AtomicUsize::new(usize::MAX);
static WRITE_CALLS: AtomicUsize = AtomicUsize::new(0);
static NEXT_INO: AtomicU64 = AtomicU64::new(0x1800);

struct WriteOps;

impl FileOps for WriteOps {
    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        WRITE_CALLS.fetch_add(1, Ordering::SeqCst);
        WRITE_OFF.store(off, Ordering::SeqCst);
        WRITE_LEN.store(buf.len(), Ordering::SeqCst);
        inode.set_size(off.saturating_add(buf.len() as u64));
        Ok(buf.len())
    }
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

fn args(fd: u64, buf: u64, cnt: u64, off: i64) -> SyscallArgs {
    SyscallArgs { a0: fd, a1: buf, a2: cnt, a3: off as u64, a4: 0, a5: 0 }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    userbuf::reset();
    WRITE_CALLS.store(0, Ordering::SeqCst);
    WRITE_LEN.store(usize::MAX, Ordering::SeqCst);
    WRITE_OFF.store(u64::MAX, Ordering::SeqCst);
}

fn mk_file(ft: FileType, flags: OpenFlags) -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(ft, 0o644),
        default_inode_ops(), Arc::new(WriteOps)).size(64).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, flags)
}

fn install_current_with_fdt(fdt: Option<Arc<FdTable>>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x1800, "pwrite64-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

#[test]
fn negative_offset_precedes_fd_and_user_buffer_validation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    assert_eq!(pwrite64_syscall::sys_pwrite64(&args(0, 0, 0, -1)), -(Errno::Einval.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn ebadf_paths_precede_user_buffer_validation_even_zero_length() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    assert_eq!(pwrite64_syscall::sys_pwrite64(&args(0, 0, 0, 0)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);

    install_current_with_fdt(None);
    assert_eq!(pwrite64_syscall::sys_pwrite64(&args(0, 0, 0, 0)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);

    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    assert_eq!(pwrite64_syscall::sys_pwrite64(&args(7, 0, 0, 0)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn fmode_gates_precede_user_buffer_validation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(FileType::Fifo, OpenFlags::O_WRONLY)).unwrap();
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    assert_eq!(pwrite64_syscall::sys_pwrite64(&args(fd as u64, 0, 1, 0)), -(VfsError::Espipe as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);

    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(FileType::Regular, OpenFlags::O_RDONLY)).unwrap();
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    assert_eq!(pwrite64_syscall::sys_pwrite64(&args(fd as u64, 0, 1, 0)), -(VfsError::Ebadf as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn zero_length_still_enters_vfs_write_and_accounts_syscall() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(FileType::Regular, OpenFlags::O_WRONLY)).unwrap();
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));

    assert_eq!(pwrite64_syscall::sys_pwrite64(&args(fd as u64, 0, 0, 5)), 0);
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(WRITE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(WRITE_LEN.load(Ordering::SeqCst), 0);
    assert_eq!(WRITE_OFF.load(Ordering::SeqCst), 5);
    assert_eq!(task.io_wchar.load(Ordering::SeqCst), 0);
    assert_eq!(task.io_syscw.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn validates_original_count_then_clamps_backend_count_and_keeps_f_pos() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file(FileType::Regular, OpenFlags::O_WRONLY);
    file.set_pos(77);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));
    let buf = [0u8; 64];

    assert_eq!(pwrite64_syscall::sys_pwrite64(&args(fd as u64, buf.as_ptr() as u64, 32, 9)),
        userbuf::TEST_MAX_RW_COUNT as i64);
    assert_eq!(file.pos(), 77);
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::VALIDATE_LEN.load(Ordering::SeqCst), 32);
    assert_eq!(userbuf::CLAMP_INPUT.load(Ordering::SeqCst), 32);
    assert_eq!(WRITE_LEN.load(Ordering::SeqCst), userbuf::TEST_MAX_RW_COUNT);
    assert_eq!(WRITE_OFF.load(Ordering::SeqCst), 9);
    assert_eq!(task.io_wchar.load(Ordering::SeqCst), userbuf::TEST_MAX_RW_COUNT as u64);
    assert_eq!(task.io_syscw.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn append_mode_pwrite_uses_inode_size_not_explicit_offset() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file(FileType::Regular, OpenFlags::O_WRONLY | OpenFlags::O_APPEND);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    let buf = [1u8, 2, 3];

    assert_eq!(pwrite64_syscall::sys_pwrite64(&args(fd as u64, buf.as_ptr() as u64, buf.len() as u64, 0)), 3);
    assert_eq!(WRITE_OFF.load(Ordering::SeqCst), 64);
    reset();
}
