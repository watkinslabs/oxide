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

macro_rules! debug_ssh {
    ($($tt:tt)*) => {};
}

mod poll {
    pub mod poll_common {
        extern crate alloc;
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

        pub static NOW_NS: AtomicU64 = AtomicU64::new(0);
        pub static PARK_CALLS: AtomicUsize = AtomicUsize::new(0);
        pub static SIGNAL_ON_PARK: AtomicBool = AtomicBool::new(false);

        pub fn monotonic_ns() -> u64 { NOW_NS.load(Ordering::SeqCst) }

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

#[path = "../../syscalls/src/023_select.rs"]
mod select_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7300);
static POLL_CALLS: AtomicUsize = AtomicUsize::new(0);

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

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    userbuf::reset();
    POLL_CALLS.store(0, Ordering::SeqCst);
    poll::poll_common::NOW_NS.store(0, Ordering::SeqCst);
    poll::poll_common::PARK_CALLS.store(0, Ordering::SeqCst);
    poll::poll_common::SIGNAL_ON_PARK.store(false, Ordering::SeqCst);
}

fn install_current_with_fdt(fdt: Option<Arc<FdTable>>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x7300, "select-test", SchedClass::Normal { weight: 1024 })));
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
    let dentry = Dentry::new(None, "select-file".into(), Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

fn args(nfds: u64, r: u64, w: u64, e: u64, tv: u64) -> SyscallArgs {
    SyscallArgs { a0: nfds, a1: r, a2: w, a3: e, a4: tv, a5: 0 }
}

fn set_fd(buf: &mut [u8], fd: usize) {
    buf[fd / 8] |= 1u8 << (fd & 7);
}

fn has_fd(buf: &[u8], fd: usize) -> bool {
    (buf[fd / 8] & (1u8 << (fd & 7))) != 0
}

fn timeval(sec: i64, usec: i64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&sec.to_ne_bytes());
    out[8..].copy_from_slice(&usec.to_ne_bytes());
    out
}

fn read_i64(buf: &[u8], off: usize) -> i64 {
    i64::from_ne_bytes(buf[off..off + 8].try_into().unwrap())
}

#[test]
fn copyin_uses_linux_long_rounded_fdset_size() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(fdt));
    let mut r = [0u8; 8];
    let mut tv = timeval(0, 0);

    assert_eq!(select_syscall::sys_select(&args(1, r.as_mut_ptr() as u64, 0, 0, tv.as_mut_ptr() as u64)), 0);
    assert_eq!(userbuf::READ_CALLS.load(Ordering::SeqCst), 2);
    assert_eq!(userbuf::READ_LEN.load(Ordering::SeqCst), 8);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::WRITE_LEN.load(Ordering::SeqCst), 8);
    reset();
}

#[test]
fn selected_closed_fd_is_ebadf_before_poll_or_copyout() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(fdt));
    let mut r = [0u8; 8];
    set_fd(&mut r, 3);

    assert_eq!(select_syscall::sys_select(&args(4, r.as_mut_ptr() as u64, 0, 0, 0)),
        -(Errno::Ebadf.as_i32() as i64));
    assert_eq!(POLL_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 0);
    reset();
}

#[test]
fn ready_bits_are_reported_per_set_and_counted_separately() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_PRI)).unwrap() as usize;
    install_current_with_fdt(Some(fdt));
    let mut r = [0u8; 8];
    let mut w = [0u8; 8];
    let mut e = [0u8; 8];
    set_fd(&mut r, fd);
    set_fd(&mut w, fd);
    set_fd(&mut e, fd);

    assert_eq!(select_syscall::sys_select(&args((fd + 1) as u64,
        r.as_mut_ptr() as u64, w.as_mut_ptr() as u64, e.as_mut_ptr() as u64, 0)), 3);
    assert!(has_fd(&r, fd));
    assert!(has_fd(&w, fd));
    assert!(has_fd(&e, fd));
    assert_eq!(POLL_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn hup_is_readable_not_writable_for_select() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(vfs::POLL_HUP)).unwrap() as usize;
    install_current_with_fdt(Some(fdt));
    let mut r = [0u8; 8];
    let mut w = [0u8; 8];
    set_fd(&mut r, fd);
    set_fd(&mut w, fd);

    assert_eq!(select_syscall::sys_select(&args((fd + 1) as u64,
        r.as_mut_ptr() as u64, w.as_mut_ptr() as u64, 0, 0)), 1);
    assert!(has_fd(&r, fd));
    assert!(!has_fd(&w, fd));
    reset();
}

#[test]
fn err_is_readable_and_writable_for_select() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(vfs::POLL_ERR)).unwrap() as usize;
    install_current_with_fdt(Some(fdt));
    let mut r = [0u8; 8];
    let mut w = [0u8; 8];
    let mut e = [0u8; 8];
    set_fd(&mut r, fd);
    set_fd(&mut w, fd);
    set_fd(&mut e, fd);

    assert_eq!(select_syscall::sys_select(&args((fd + 1) as u64,
        r.as_mut_ptr() as u64, w.as_mut_ptr() as u64, e.as_mut_ptr() as u64, 0)), 2);
    assert!(has_fd(&r, fd));
    assert!(has_fd(&w, fd));
    assert!(!has_fd(&e, fd));
    reset();
}

#[test]
fn fdset_copyout_fault_happens_after_polling() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(vfs::POLL_IN)).unwrap() as usize;
    install_current_with_fdt(Some(fdt));
    let mut r = [0u8; 8];
    set_fd(&mut r, fd);
    userbuf::FAIL_WRITE.store(true, Ordering::SeqCst);

    assert_eq!(select_syscall::sys_select(&args((fd + 1) as u64,
        r.as_mut_ptr() as u64, 0, 0, 0)), -(Errno::Efault.as_i32() as i64));
    assert_eq!(POLL_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn select_updates_nonzero_timeval_best_effort() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(vfs::POLL_IN)).unwrap() as usize;
    install_current_with_fdt(Some(fdt));
    let mut r = [0u8; 8];
    let mut tv = timeval(1, 234);
    set_fd(&mut r, fd);

    assert_eq!(select_syscall::sys_select(&args((fd + 1) as u64, r.as_mut_ptr() as u64, 0, 0, tv.as_mut_ptr() as u64)), 1);
    assert_eq!(read_i64(&tv, 0), 1);
    assert_eq!(read_i64(&tv, 8), 234);
    reset();
}

#[test]
fn negative_nfds_is_einval() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(fdt));

    assert_eq!(select_syscall::sys_select(&args(u64::MAX, 0, 0, 0, 0)),
        -(Errno::Einval.as_i32() as i64));
    reset();
}
