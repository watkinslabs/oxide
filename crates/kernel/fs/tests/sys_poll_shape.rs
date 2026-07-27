extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::inode::Inode;
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, KResult, OpenFlags, default_inode_ops, mk_mode};

mod poll {
    pub mod poll_common {
        extern crate alloc;
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

        pub fn monotonic_ns() -> u64 { 0 }

        pub static PARK_CALLS: AtomicUsize = AtomicUsize::new(0);
        pub static SIGNAL_ON_PARK: AtomicBool = AtomicBool::new(false);

        pub struct PollWaiter { generation: AtomicU64 }

        impl PollWaiter {
            pub fn new() -> Arc<Self> { Arc::new(Self { generation: AtomicU64::new(0) }) }
            pub fn subscribe(self: &Arc<Self>, _subs: &vfs::PollSubscribers) {}
            pub fn unsubscribe(&self, _subs: &vfs::PollSubscribers) {}
            pub fn generation(&self) -> u64 { self.generation.load(Ordering::Acquire) }
            pub unsafe fn park_until(&self, _observed: u64, _deadline_ns: u64) {
                PARK_CALLS.fetch_add(1, Ordering::SeqCst);
                if SIGNAL_ON_PARK.load(Ordering::SeqCst) {
                    if let Some(cur) = sched::current() {
                        cur.sigpending.fetch_or(1, Ordering::Release);
                    }
                }
            }
        }
    }
}

mod userbuf {
    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use syscall::errno::Errno;

    pub static READ_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static READ_LEN: AtomicU64 = AtomicU64::new(0);
    pub static WRITE_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static WRITE_LEN: AtomicU64 = AtomicU64::new(0);
    pub static FAIL_READ: AtomicBool = AtomicBool::new(false);
    pub static FAIL_WRITE: AtomicBool = AtomicBool::new(false);

    pub fn reset() {
        READ_CALLS.store(0, Ordering::SeqCst);
        READ_LEN.store(0, Ordering::SeqCst);
        WRITE_CALLS.store(0, Ordering::SeqCst);
        WRITE_LEN.store(0, Ordering::SeqCst);
        FAIL_READ.store(false, Ordering::SeqCst);
        FAIL_WRITE.store(false, Ordering::SeqCst);
    }

    pub fn validate_user_buf_readable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        READ_CALLS.fetch_add(1, Ordering::SeqCst);
        READ_LEN.store(len, Ordering::SeqCst);
        if ptr == 0 || FAIL_READ.load(Ordering::SeqCst) { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }

    pub fn validate_user_buf_writable(ptr: u64, len: u64, _align: u64) -> Result<(), i64> {
        WRITE_CALLS.fetch_add(1, Ordering::SeqCst);
        WRITE_LEN.store(len, Ordering::SeqCst);
        if ptr == 0 || FAIL_WRITE.load(Ordering::SeqCst) { Err(-(Errno::Efault.as_i32() as i64)) } else { Ok(()) }
    }
}

#[path = "../../syscalls/src/pselect_ppoll.rs"]
mod pselect_ppoll;

#[path = "../../syscalls/src/007_poll.rs"]
mod poll_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7000);
static POLL_CALLS: AtomicUsize = AtomicUsize::new(0);

const POLLIN:  i16 = 0x0001;
const POLLOUT: i16 = 0x0004;
const POLLHUP: i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;

struct PollOps(u32);

impl FileOps for PollOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(buf.len()) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
    fn poll(&self, _inode: &Inode) -> u32 {
        POLL_CALLS.fetch_add(1, Ordering::SeqCst);
        self.0
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

fn args(fds: u64, nfds: u64, timeout: i32) -> SyscallArgs {
    SyscallArgs { a0: fds, a1: nfds, a2: timeout as u32 as u64, a3: 0, a4: 0, a5: 0 }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    userbuf::reset();
    POLL_CALLS.store(0, Ordering::SeqCst);
    poll::poll_common::PARK_CALLS.store(0, Ordering::SeqCst);
    poll::poll_common::SIGNAL_ON_PARK.store(false, Ordering::SeqCst);
}

fn install_current_with_fdt(fdt: Option<Arc<FdTable>>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x7000, "poll-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn mk_file(mask: u32) -> Arc<File> {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), Arc::new(PollOps(mask))).build();
    let dentry = Dentry::new(None, "poll-file".into(), Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

fn put_pollfd(buf: &mut [u8], idx: usize, fd: i32, events: i16, revents: i16) {
    let off = idx * 8;
    buf[off..off + 4].copy_from_slice(&fd.to_ne_bytes());
    buf[off + 4..off + 6].copy_from_slice(&events.to_ne_bytes());
    buf[off + 6..off + 8].copy_from_slice(&revents.to_ne_bytes());
}

fn get_i32(buf: &[u8], off: usize) -> i32 {
    i32::from_ne_bytes(buf[off..off + 4].try_into().unwrap())
}

fn get_i16(buf: &[u8], off: usize) -> i16 {
    i16::from_ne_bytes(buf[off..off + 2].try_into().unwrap())
}

#[test]
fn sys_poll_no_current_and_rlimit_errors_precede_user_copy() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    assert_eq!(poll_syscall::sys_poll(&args(0, 1, 0)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::READ_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 0);

    let fdt = Arc::new(FdTable::new());
    let cur = install_current_with_fdt(Some(fdt));
    let too_many = cur.nofile_soft() as u64 + 1;
    assert_eq!(poll_syscall::sys_poll(&args(0, too_many, 0)), -(Errno::Einval.as_i32() as i64));
    assert_eq!(userbuf::READ_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn sys_poll_copyin_error_precedes_fd_table_lookup() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    install_current_with_fdt(None);

    assert_eq!(poll_syscall::sys_poll(&args(0, 1, 0)), -(Errno::Efault.as_i32() as i64));
    assert_eq!(userbuf::READ_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn sys_poll_valid_copyin_then_missing_fd_table_is_ebadf() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    install_current_with_fdt(None);
    let mut buf = [0u8; 8];
    put_pollfd(&mut buf, 0, 0, POLLIN, -1);

    assert_eq!(poll_syscall::sys_poll(&args(buf.as_mut_ptr() as u64, 1, 0)), -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(userbuf::READ_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn sys_poll_writes_revents_only_after_polling() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file((POLLIN | POLLOUT | POLLHUP) as u32)).unwrap();
    install_current_with_fdt(Some(fdt));
    let mut buf = [0u8; 8];
    put_pollfd(&mut buf, 0, fd, POLLIN, -1);

    assert_eq!(poll_syscall::sys_poll(&args(buf.as_mut_ptr() as u64, 1, 0)), 1);
    assert_eq!(userbuf::READ_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::READ_LEN.load(Ordering::SeqCst), 8);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::WRITE_LEN.load(Ordering::SeqCst), 8);
    assert_eq!(POLL_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(get_i32(&buf, 0), fd);
    assert_eq!(get_i16(&buf, 4), POLLIN);
    assert_eq!(get_i16(&buf, 6), POLLIN | POLLHUP);
    reset();
}

#[test]
fn sys_poll_copyout_error_happens_after_polling() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(POLLIN as u32)).unwrap();
    install_current_with_fdt(Some(fdt));
    userbuf::FAIL_WRITE.store(true, Ordering::SeqCst);
    let mut buf = [0u8; 8];
    put_pollfd(&mut buf, 0, fd, POLLIN, -1);

    assert_eq!(poll_syscall::sys_poll(&args(buf.as_mut_ptr() as u64, 1, 0)), -(Errno::Efault.as_i32() as i64));
    assert_eq!(userbuf::READ_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(POLL_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(get_i16(&buf, 6), -1);
    reset();
}

#[test]
fn sys_poll_negative_fd_ignored_bad_fd_pollnval_and_timeout_zero_returns_zero() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(0)).unwrap();
    install_current_with_fdt(Some(fdt));
    let mut buf = [0u8; 24];
    put_pollfd(&mut buf, 0, -1, POLLIN, -1);
    put_pollfd(&mut buf, 1, 42, 0, -1);
    put_pollfd(&mut buf, 2, fd, POLLIN, -1);

    assert_eq!(poll_syscall::sys_poll(&args(buf.as_mut_ptr() as u64, 3, 0)), 1);
    assert_eq!(get_i16(&buf, 6), 0);
    assert_eq!(get_i16(&buf, 14), POLLNVAL);
    assert_eq!(get_i16(&buf, 22), 0);

    put_pollfd(&mut buf, 0, fd, POLLIN, -1);
    assert_eq!(poll_syscall::sys_poll(&args(buf.as_mut_ptr() as u64, 1, 0)), 0);
    assert_eq!(get_i16(&buf, 6), 0);
    reset();
}

#[test]
fn sys_poll_zero_fds_blocks_until_signal_for_negative_timeout() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(fdt));
    poll::poll_common::SIGNAL_ON_PARK.store(true, Ordering::SeqCst);

    assert_eq!(poll_syscall::sys_poll(&args(0, 0, -1)), -(Errno::Eintr.as_i32() as i64));
    assert_eq!(userbuf::READ_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(poll::poll_common::PARK_CALLS.load(Ordering::SeqCst), 1);
    reset();
}
