extern crate alloc;
extern crate self as uaccess;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::{Dentry, FdTable, File, FileOps, FileType, Inode, InodeBuilder, KResult, OpenFlags, VfsError, default_inode_ops, mk_mode};

mod netlink_fd {
    pub fn is_netlink(_fd: u64) -> bool { false }
    pub fn read(_fd: u64, _buf: u64, _len: usize) -> i64 { unreachable!("netlink disabled in read shape tests") }
}

pub fn access_ok(ptr: u64, len: usize) -> bool { len == 0 || ptr != 0 }

mod recv_user {
    pub struct IoVec {
        pub base: u64,
        pub len: usize,
    }

    pub struct RecvUser {
        pub msgp: u64,
        pub name: u64,
        pub namelen: u32,
        pub name_len_ptr: u64,
        pub control: u64,
        pub controllen: usize,
        pub iov: alloc::vec::Vec<IoVec>,
        pub capacity: usize,
    }
}

mod recvmsg {
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;
    use vfs::File;

    pub struct Target;

    pub fn from_file(_file: Arc<File>) -> Result<Target, ()> {
        if crate::SOCKET_TARGET.load(Ordering::Acquire) { Ok(Target) } else { Err(()) }
    }
    pub fn recv(_target: &Target, _user: &crate::recv_user::RecvUser, _flags: u64) -> i64 {
        let user = _user;
        let abi = user.msgp == 0 && user.name == 0 && user.namelen == 0 && user.name_len_ptr == 0
            && user.control == 0 && user.controllen == 0 && user.iov.len() == 1
            && user.capacity == user.iov[0].len;
        crate::RECV_USER_ABI_VALID.store(abi, Ordering::SeqCst);
        crate::RECV_CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }
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

    pub fn validate_user_buf_writable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        VALIDATE_CALLS.fetch_add(1, Ordering::SeqCst);
        VALIDATE_LEN.store(len, Ordering::SeqCst);
        if ptr == 0 { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }

    pub fn clamp_rw_count(n: usize) -> usize {
        CLAMP_INPUT.store(n, Ordering::SeqCst);
        core::cmp::min(n, TEST_MAX_RW_COUNT)
    }
}

#[path = "../../syscalls/src/000_read.rs"]
mod read_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static READ_LEN: AtomicUsize = AtomicUsize::new(usize::MAX);
static READ_CALLS: AtomicUsize = AtomicUsize::new(0);
static RECV_CALLS: AtomicUsize = AtomicUsize::new(0);
static RECV_USER_ABI_VALID: AtomicBool = AtomicBool::new(false);
static SOCKET_TARGET: AtomicBool = AtomicBool::new(false);
static NEXT_INO: AtomicU64 = AtomicU64::new(0xD000);

struct ReadOps;

impl FileOps for ReadOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        READ_CALLS.fetch_add(1, Ordering::SeqCst);
        READ_LEN.store(buf.len(), Ordering::SeqCst);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
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

fn args(fd: u64, buf: u64, cnt: u64) -> SyscallArgs {
    SyscallArgs { a0: fd, a1: buf, a2: cnt, a3: 0, a4: 0, a5: 0 }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    userbuf::reset();
    READ_CALLS.store(0, Ordering::SeqCst);
    RECV_CALLS.store(0, Ordering::SeqCst);
    RECV_USER_ABI_VALID.store(false, Ordering::SeqCst);
    SOCKET_TARGET.store(false, Ordering::Release);
    READ_LEN.store(usize::MAX, Ordering::SeqCst);
}

fn mk_file(flags: OpenFlags) -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(ReadOps)).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, flags)
}

fn install_current_with_fdt(fdt: Option<Arc<FdTable>>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0xD000, "read-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

#[test]
fn sys_read_ebadf_paths_precede_user_buffer_validation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    assert_eq!(read_syscall::sys_read(&args(0, 0, 1)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);

    install_current_with_fdt(None);
    assert_eq!(read_syscall::sys_read(&args(0, 0, 1)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);

    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    assert_eq!(read_syscall::sys_read(&args(7, 0, 1)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn sys_read_file_mode_precedes_user_buffer_validation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(OpenFlags::O_WRONLY)).unwrap();
    install_current_with_fdt(Some(Arc::clone(&fdt)));

    assert_eq!(read_syscall::sys_read(&args(fd as u64, 0, 1)), -(VfsError::Ebadf as i64));
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(READ_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn sys_read_zero_length_still_checks_fd_and_file() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(OpenFlags::O_RDONLY)).unwrap();
    install_current_with_fdt(Some(Arc::clone(&fdt)));

    assert_eq!(read_syscall::sys_read(&args(fd as u64, 0, 0)), 0);
    let cur = sched::current().unwrap();
    assert_eq!(cur.io_rchar.load(Ordering::SeqCst), 0);
    assert_eq!(cur.io_syscr.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(READ_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(READ_LEN.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn sys_read_zero_length_socket_does_not_enter_receive() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(OpenFlags::O_RDONLY)).unwrap();
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    SOCKET_TARGET.store(true, Ordering::Release);

    assert_eq!(read_syscall::sys_read(&args(fd as u64, 0, 0)), 0);
    assert_eq!(RECV_CALLS.load(Ordering::SeqCst), 0);
    assert!(!RECV_USER_ABI_VALID.load(Ordering::SeqCst));
    assert_eq!(READ_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(sched::current().unwrap().io_syscr.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn sys_read_socket_constructs_the_canonical_receive_destination() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(OpenFlags::O_RDONLY)).unwrap();
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    SOCKET_TARGET.store(true, Ordering::Release);
    let mut buf = [0u8; 4];

    assert_eq!(read_syscall::sys_read(&args(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)), 0);
    assert_eq!(RECV_CALLS.load(Ordering::SeqCst), 1);
    assert!(RECV_USER_ABI_VALID.load(Ordering::SeqCst));
    assert_eq!(READ_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn sys_read_validates_original_count_then_clamps_backend_count() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(OpenFlags::O_RDONLY)).unwrap();
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    let mut buf = [0u8; 64];

    assert_eq!(read_syscall::sys_read(&args(fd as u64, buf.as_mut_ptr() as u64, 32)), userbuf::TEST_MAX_RW_COUNT as i64);
    let cur = sched::current().unwrap();
    assert_eq!(cur.io_rchar.load(Ordering::SeqCst), userbuf::TEST_MAX_RW_COUNT as u64);
    assert_eq!(cur.io_syscr.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::VALIDATE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::VALIDATE_LEN.load(Ordering::SeqCst), 32);
    assert_eq!(userbuf::CLAMP_INPUT.load(Ordering::SeqCst), 32);
    assert_eq!(READ_LEN.load(Ordering::SeqCst), userbuf::TEST_MAX_RW_COUNT);
    assert_eq!(&buf[..userbuf::TEST_MAX_RW_COUNT], &[0, 1, 2, 3, 4, 5, 6, 7]);
    reset();
}
