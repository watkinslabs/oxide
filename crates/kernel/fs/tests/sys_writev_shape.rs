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

mod userbuf {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use syscall::errno::Errno;

    pub static VALIDATE_IOV_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static VALIDATE_IOV_LEN: AtomicU64 = AtomicU64::new(0);
    pub static VALIDATE_BUF_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static VALIDATE_BUF_LEN_SUM: AtomicU64 = AtomicU64::new(0);
    pub const MAX_RW_COUNT: usize = 8;

    pub fn reset() {
        VALIDATE_IOV_CALLS.store(0, Ordering::SeqCst);
        VALIDATE_IOV_LEN.store(0, Ordering::SeqCst);
        VALIDATE_BUF_CALLS.store(0, Ordering::SeqCst);
        VALIDATE_BUF_LEN_SUM.store(0, Ordering::SeqCst);
    }

    pub fn validate_user_buf(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        VALIDATE_IOV_CALLS.fetch_add(1, Ordering::SeqCst);
        VALIDATE_IOV_LEN.store(len, Ordering::SeqCst);
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }

    pub fn validate_user_buf_readable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        VALIDATE_BUF_CALLS.fetch_add(1, Ordering::SeqCst);
        VALIDATE_BUF_LEN_SUM.fetch_add(len, Ordering::SeqCst);
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }
}

mod socket {
    use alloc::sync::Arc;

    #[derive(Clone, Copy)]
    #[repr(i64)]
    pub enum Error { Eio = vfs::VfsError::Eio as i64 }

    pub struct SendContext<'a> { _task: &'a sched::Task }
    impl<'a> SendContext<'a> { pub fn new(task: &'a sched::Task) -> Self { Self { _task: task } } }

    pub fn writev(_context: &SendContext<'_>, file: Arc<vfs::File>, bufs: &[&[u8]])
        -> Result<usize, Error>
    {
        file.write_iter(bufs).map_err(|_| Error::Eio)
    }
}

#[path = "../../syscalls/src/020_writev.rs"]
mod writev_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static WRITE_CALLS: AtomicUsize = AtomicUsize::new(0);
static WRITE_LEN_SUM: AtomicUsize = AtomicUsize::new(0);
static WRITE_OFF_FIRST: AtomicU64 = AtomicU64::new(u64::MAX);
static ERROR_ON_CALL: AtomicUsize = AtomicUsize::new(0);
static NEXT_INO: AtomicU64 = AtomicU64::new(0x2000);

struct WriteOps;

impl FileOps for WriteOps {
    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let call = WRITE_CALLS.fetch_add(1, Ordering::SeqCst) + 1;
        if call == 1 { WRITE_OFF_FIRST.store(off, Ordering::SeqCst); }
        if ERROR_ON_CALL.load(Ordering::SeqCst) == call {
            return Err(VfsError::Eio);
        }
        WRITE_LEN_SUM.fetch_add(buf.len(), Ordering::SeqCst);
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

fn args(fd: u64, iov: u64, iovcnt: u64) -> SyscallArgs {
    SyscallArgs { a0: fd, a1: iov, a2: iovcnt, a3: 0, a4: 0, a5: 0 }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    userbuf::reset();
    WRITE_CALLS.store(0, Ordering::SeqCst);
    WRITE_LEN_SUM.store(0, Ordering::SeqCst);
    WRITE_OFF_FIRST.store(u64::MAX, Ordering::SeqCst);
    ERROR_ON_CALL.store(0, Ordering::SeqCst);
}

fn mk_file(flags: OpenFlags) -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(WriteOps)).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, flags)
}

fn install_current_with_fdt(fdt: Option<Arc<FdTable>>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x2000, "writev-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

#[repr(C)]
struct Iov { base: u64, len: u64 }

#[test]
fn ebadf_and_fmode_precede_iovec_import() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    assert_eq!(writev_syscall::sys_writev(&args(0, 0, 1)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_IOV_CALLS.load(Ordering::SeqCst), 0);

    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    assert_eq!(writev_syscall::sys_writev(&args(7, 0, 1)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_IOV_CALLS.load(Ordering::SeqCst), 0);

    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(OpenFlags::O_RDONLY)).unwrap();
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));
    assert_eq!(writev_syscall::sys_writev(&args(fd as u64, 0, 1)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_IOV_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(task.io_syscw.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn zero_iov_still_checks_file_and_accounts() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(OpenFlags::O_WRONLY)).unwrap();
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));

    assert_eq!(writev_syscall::sys_writev(&args(fd as u64, 0, 0)), 0);
    assert_eq!(userbuf::VALIDATE_IOV_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(WRITE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(task.io_wchar.load(Ordering::SeqCst), 0);
    assert_eq!(task.io_syscw.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn iovcnt_over_limit_after_fd_and_mode() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(OpenFlags::O_WRONLY)).unwrap();
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));

    assert_eq!(writev_syscall::sys_writev(&args(fd as u64, 0, 1025)), -(Errno::Einval.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_IOV_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(task.io_syscw.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn validates_iovec_array_then_each_source_buffer() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(OpenFlags::O_WRONLY)).unwrap();
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));
    let iov = [Iov { base: 0, len: 4 }];

    assert_eq!(writev_syscall::sys_writev(&args(fd as u64, iov.as_ptr() as u64, 1)), -(Errno::Efault.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_IOV_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::VALIDATE_IOV_LEN.load(Ordering::SeqCst), 16);
    assert_eq!(userbuf::VALIDATE_BUF_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(WRITE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(task.io_syscw.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn max_rw_count_caps_aggregate_iovec_import_and_accounts() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file(OpenFlags::O_WRONLY);
    file.set_pos(20);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));
    let a = [1u8; 6];
    let b = [2u8; 6];
    let iov = [
        Iov { base: a.as_ptr() as u64, len: a.len() as u64 },
        Iov { base: b.as_ptr() as u64, len: b.len() as u64 },
    ];

    assert_eq!(writev_syscall::sys_writev(&args(fd as u64, iov.as_ptr() as u64, iov.len() as u64)), 8);
    assert_eq!(userbuf::VALIDATE_IOV_LEN.load(Ordering::SeqCst), 32);
    assert_eq!(userbuf::VALIDATE_BUF_CALLS.load(Ordering::SeqCst), 2);
    assert_eq!(userbuf::VALIDATE_BUF_LEN_SUM.load(Ordering::SeqCst), 12);
    assert_eq!(WRITE_CALLS.load(Ordering::SeqCst), 2);
    assert_eq!(WRITE_LEN_SUM.load(Ordering::SeqCst), userbuf::MAX_RW_COUNT);
    assert_eq!(WRITE_OFF_FIRST.load(Ordering::SeqCst), 20);
    assert_eq!(file.pos(), 28);
    assert_eq!(task.io_wchar.load(Ordering::SeqCst), userbuf::MAX_RW_COUNT as u64);
    assert_eq!(task.io_syscw.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn backend_error_after_partial_write_returns_partial_count() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(OpenFlags::O_WRONLY)).unwrap();
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));
    let a = [1u8; 4];
    let b = [2u8; 4];
    let iov = [
        Iov { base: a.as_ptr() as u64, len: a.len() as u64 },
        Iov { base: b.as_ptr() as u64, len: b.len() as u64 },
    ];
    ERROR_ON_CALL.store(2, Ordering::SeqCst);

    assert_eq!(writev_syscall::sys_writev(&args(fd as u64, iov.as_ptr() as u64, iov.len() as u64)), 4);
    assert_eq!(WRITE_CALLS.load(Ordering::SeqCst), 2);
    assert_eq!(task.io_wchar.load(Ordering::SeqCst), 4);
    assert_eq!(task.io_syscw.load(Ordering::SeqCst), 1);
    reset();
}
