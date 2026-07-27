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

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static WRITTEN: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static READ_OFF_FIRST: AtomicU64 = AtomicU64::new(u64::MAX);
static READ_CALLS: AtomicUsize = AtomicUsize::new(0);
static WRITE_CALLS: AtomicUsize = AtomicUsize::new(0);
static WRITE_PARTIAL_FIRST: AtomicUsize = AtomicUsize::new(0);
static WRITE_ERROR_ON_CALL: AtomicUsize = AtomicUsize::new(0);
static NEXT_INO: AtomicU64 = AtomicU64::new(0x4000);

const DATA: &[u8] = b"abcdef";

struct ReadOps;
struct WriteOps;

impl FileOps for ReadOps {
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let call = READ_CALLS.fetch_add(1, Ordering::SeqCst) + 1;
        if call == 1 { READ_OFF_FIRST.store(off, Ordering::SeqCst); }
        let off = off as usize;
        if off >= DATA.len() { return Ok(0); }
        let n = core::cmp::min(buf.len(), DATA.len() - off);
        buf[..n].copy_from_slice(&DATA[off..off + n]);
        Ok(n)
    }
}

impl FileOps for WriteOps {
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let call = WRITE_CALLS.fetch_add(1, Ordering::SeqCst) + 1;
        if WRITE_ERROR_ON_CALL.load(Ordering::SeqCst) == call {
            return Err(VfsError::Eio);
        }
        let partial = WRITE_PARTIAL_FIRST.load(Ordering::SeqCst);
        let n = if call == 1 && partial != 0 { partial.min(buf.len()) } else { buf.len() };
        WRITTEN.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

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
    sched::set_current_hook(hooked_current);
    WRITTEN.lock().unwrap().clear();
    READ_OFF_FIRST.store(u64::MAX, Ordering::SeqCst);
    READ_CALLS.store(0, Ordering::SeqCst);
    WRITE_CALLS.store(0, Ordering::SeqCst);
    WRITE_PARTIAL_FIRST.store(0, Ordering::SeqCst);
    WRITE_ERROR_ON_CALL.store(0, Ordering::SeqCst);
}

fn args(out_fd: i32, in_fd: i32, offp: u64, count: u64) -> SyscallArgs {
    SyscallArgs { a0: out_fd as u64, a1: in_fd as u64, a2: offp, a3: count, a4: u64::MAX, a5: u64::MAX }
}

fn install_current(fdt: Arc<FdTable>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x4000, "sendfile-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn mk_file(ft: FileType, flags: OpenFlags, fop: Arc<dyn FileOps>) -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(ft, 0o644), default_inode_ops(), fop)
        .size(DATA.len() as u64)
        .build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, flags)
}

fn mk_pair(src_ft: FileType) -> (Arc<FdTable>, Arc<File>, Arc<File>, i32, i32) {
    let fdt = Arc::new(FdTable::new());
    let src = mk_file(src_ft, OpenFlags::O_RDONLY, Arc::new(ReadOps));
    let dst = mk_file(FileType::Regular, OpenFlags::O_WRONLY, Arc::new(WriteOps));
    let in_fd = fdt.alloc(Arc::clone(&src)).unwrap();
    let out_fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    (fdt, src, dst, in_fd, out_fd)
}

#[test]
fn explicit_offset_uses_pread_and_updates_user_offset_not_input_pos() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (fdt, src, dst, in_fd, out_fd) = mk_pair(FileType::Regular);
    src.set_pos(4);
    let task = install_current(Arc::clone(&fdt));
    let mut off = 1i64;

    assert_eq!(sched::xfer::sys_sendfile(&args(out_fd, in_fd, &mut off as *mut i64 as u64, 3)), 3);
    assert_eq!(off, 4);
    assert_eq!(src.pos(), 4);
    assert_eq!(dst.pos(), 3);
    assert_eq!(READ_OFF_FIRST.load(Ordering::SeqCst), 1);
    assert_eq!(&*WRITTEN.lock().unwrap(), b"bcd");
    assert_eq!(task.io_rchar.load(Ordering::SeqCst), 3);
    assert_eq!(task.io_wchar.load(Ordering::SeqCst), 3);
    assert_eq!(task.io_syscr.load(Ordering::SeqCst), 1);
    assert_eq!(task.io_syscw.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn null_offset_advances_input_file_position() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (fdt, src, _dst, in_fd, out_fd) = mk_pair(FileType::Regular);
    src.set_pos(2);
    install_current(Arc::clone(&fdt));

    assert_eq!(sched::xfer::sys_sendfile(&args(out_fd, in_fd, 0, 2)), 2);
    assert_eq!(src.pos(), 4);
    assert_eq!(READ_OFF_FIRST.load(Ordering::SeqCst), 2);
    assert_eq!(&*WRITTEN.lock().unwrap(), b"cd");
    reset();
}

#[test]
fn explicit_offset_on_non_pread_input_is_espipe_before_copy_accounting() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (fdt, _src, _dst, in_fd, out_fd) = mk_pair(FileType::Fifo);
    let task = install_current(Arc::clone(&fdt));
    let mut off = 2i64;

    assert_eq!(sched::xfer::sys_sendfile(&args(out_fd, in_fd, &mut off as *mut i64 as u64, 3)),
        -(Errno::Espipe.as_i32() as i64));
    assert_eq!(off, 2);
    assert_eq!(READ_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(WRITE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(task.io_syscr.load(Ordering::SeqCst), 0);
    assert_eq!(task.io_syscw.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn output_error_after_partial_write_returns_partial_count_and_offset() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (fdt, _src, _dst, in_fd, out_fd) = mk_pair(FileType::Regular);
    install_current(Arc::clone(&fdt));
    WRITE_PARTIAL_FIRST.store(2, Ordering::SeqCst);
    WRITE_ERROR_ON_CALL.store(2, Ordering::SeqCst);
    let mut off = 0i64;

    assert_eq!(sched::xfer::sys_sendfile(&args(out_fd, in_fd, &mut off as *mut i64 as u64, 4)), 2);
    assert_eq!(off, 2);
    assert_eq!(&*WRITTEN.lock().unwrap(), b"ab");
    reset();
}

#[test]
fn null_offset_partial_output_advances_input_by_copied_bytes_only() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (fdt, src, _dst, in_fd, out_fd) = mk_pair(FileType::Regular);
    install_current(Arc::clone(&fdt));
    WRITE_PARTIAL_FIRST.store(2, Ordering::SeqCst);
    WRITE_ERROR_ON_CALL.store(2, Ordering::SeqCst);

    assert_eq!(sched::xfer::sys_sendfile(&args(out_fd, in_fd, 0, 4)), 2);
    assert_eq!(src.pos(), 2);
    assert_eq!(READ_OFF_FIRST.load(Ordering::SeqCst), 0);
    assert_eq!(&*WRITTEN.lock().unwrap(), b"ab");
    reset();
}
