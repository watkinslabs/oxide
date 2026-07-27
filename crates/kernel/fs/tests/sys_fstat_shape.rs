extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, OpenFlags, default_file_ops, default_inode_ops, mk_mode};

mod namei_common {
    pub fn fsid_to_dev(fsid: u64) -> u64 { vfs::fsid_to_dev(fsid) }
}

mod userbuf {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use syscall::errno::Errno;

    pub static VALIDATE_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static VALIDATE_LEN: AtomicU64 = AtomicU64::new(0);

    pub fn reset() {
        VALIDATE_CALLS.store(0, Ordering::SeqCst);
        VALIDATE_LEN.store(0, Ordering::SeqCst);
    }

    pub fn validate_user_buf_writable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        VALIDATE_CALLS.fetch_add(1, Ordering::SeqCst);
        VALIDATE_LEN.store(len, Ordering::SeqCst);
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }
}

#[path = "../../syscalls/src/stat_common.rs"]
mod stat_common;

#[path = "../../syscalls/src/005_fstat.rs"]
mod fstat_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0xF500);

const TEST_UID: u32 = 1000;
const TEST_GID: u32 = 1001;
const TEST_FSID: u64 = 0x0505;
const TEST_SIZE: u64 = 0x1234;
const TEST_BLOCKS: u64 = 7;

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: tests store only leaked Task pointers and clear the hook pointer before returning.
        Some(unsafe { &*p })
    }
}

fn args(fd: u64, buf: u64) -> SyscallArgs {
    SyscallArgs { a0: fd, a1: buf, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    userbuf::reset();
}

fn install_current_with_fdt(fdt: Option<Arc<FdTable>>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0xF500, "fstat-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn mk_file(flags: OpenFlags, size: u64) -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o640),
        default_inode_ops(), default_file_ops())
        .owner(TEST_UID, TEST_GID)
        .fsid(TEST_FSID)
        .size(size)
        .blocks(TEST_BLOCKS)
        .build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, flags)
}

fn le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap())
}

fn le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(buf[off..off + 8].try_into().unwrap())
}

fn le_i64(buf: &[u8], off: usize) -> i64 {
    i64::from_ne_bytes(buf[off..off + 8].try_into().unwrap())
}

#[test]
fn sys_fstat_ebadf_paths_precede_user_buffer_validation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    assert_eq!(fstat_syscall::sys_fstat(&args(0, 0)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);

    install_current_with_fdt(None);
    assert_eq!(fstat_syscall::sys_fstat(&args(0, 0)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);

    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    assert_eq!(fstat_syscall::sys_fstat(&args(7, 0)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(fstat_syscall::sys_fstat(&args(u64::MAX, 0)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn sys_fstat_conversion_precedes_user_buffer_validation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(OpenFlags::O_RDONLY, i64::MAX as u64 + 1)).unwrap();
    install_current_with_fdt(Some(Arc::clone(&fdt)));

    assert_eq!(fstat_syscall::sys_fstat(&args(fd as u64, 0)), -(Errno::Eoverflow.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn sys_fstat_valid_fd_faults_only_at_copyout_validation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(OpenFlags::O_RDONLY, TEST_SIZE)).unwrap();
    install_current_with_fdt(Some(Arc::clone(&fdt)));

    assert_eq!(fstat_syscall::sys_fstat(&args(fd as u64, 0)), -(Errno::Efault.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::VALIDATE_LEN.load(Ordering::SeqCst), stat_common::STAT_BYTES);
    reset();
}

#[test]
fn sys_fstat_writes_struct_stat_for_opath_fd() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let ino = NEXT_INO.load(Ordering::Relaxed);
    let fd = fdt.alloc(mk_file(OpenFlags::O_PATH, TEST_SIZE)).unwrap();
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    let mut buf = [0u8; stat_common::STAT_BYTES_X86_64 as usize];

    assert_eq!(fstat_syscall::sys_fstat(&args(fd as u64, buf.as_mut_ptr() as u64)), 0);
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::VALIDATE_LEN.load(Ordering::SeqCst), stat_common::STAT_BYTES);
    assert_eq!(le_u64(&buf, 0), vfs::fsid_to_dev(TEST_FSID));
    assert_eq!(le_u64(&buf, 8), ino);
    assert_eq!(le_u32(&buf, 24), mk_mode(FileType::Regular, 0o640));
    assert_eq!(le_u32(&buf, 28), TEST_UID);
    assert_eq!(le_u32(&buf, 32), TEST_GID);
    assert_eq!(le_i64(&buf, 48), TEST_SIZE as i64);
    assert_eq!(le_i64(&buf, 64), TEST_BLOCKS as i64);
    reset();
}
