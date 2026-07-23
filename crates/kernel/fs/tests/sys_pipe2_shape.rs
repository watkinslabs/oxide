extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::{FdTable, OpenFlags, VfsError, POLL_OUT};

const O_ACCMODE: u32 = 0o3;

macro_rules! debug_ssh {
    ($($tt:tt)*) => {};
}

mod userbuf {
    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use syscall::errno::Errno;

    pub static WRITE_CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static LAST_PTR: AtomicU64 = AtomicU64::new(0);
    pub static FAIL_WRITE: AtomicBool = AtomicBool::new(false);

    pub fn reset() {
        WRITE_CALLS.store(0, Ordering::SeqCst);
        LAST_PTR.store(0, Ordering::SeqCst);
        FAIL_WRITE.store(false, Ordering::SeqCst);
    }

    pub fn write_i32_pair(ptr: u64, a: i32, b: i32) -> Result<(), i64> {
        WRITE_CALLS.fetch_add(1, Ordering::SeqCst);
        LAST_PTR.store(ptr, Ordering::SeqCst);
        if ptr == 0 || FAIL_WRITE.load(Ordering::SeqCst) {
            return Err(-(Errno::Efault.as_i32() as i64));
        }
        // SAFETY: test passes a valid pointer unless deliberately faulting.
        unsafe {
            core::ptr::write_volatile(ptr as *mut i32, a);
            core::ptr::write_volatile((ptr + 4) as *mut i32, b);
        }
        Ok(())
    }
}

#[path = "../../syscalls/src/anon_dname.rs"]
mod anon_dname;
#[path = "../../syscalls/src/293_pipe2.rs"]
mod pipe2_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_TID: AtomicU64 = AtomicU64::new(0x2200);

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
    userbuf::reset();
}

fn args(pipefd: u64, flags: u64) -> SyscallArgs {
    SyscallArgs { a0: pipefd, a1: flags, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn install_current_with_fdt(fdt: Option<Arc<FdTable>>) -> &'static Task {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    let task = Box::leak(Box::new(Task::new(tid as u32, "pipe2-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

#[test]
fn invalid_flags_precede_current_and_copyout() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let mut out = [-1i32; 2];
    let bad = OpenFlags::O_DIRECTORY.bits() as u64;

    assert_eq!(pipe2_syscall::sys_pipe2(&args(out.as_mut_ptr() as u64, bad)),
        -(Errno::Einval.as_i32() as i64));
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(out, [-1, -1]);
    reset();
}

#[test]
fn pipe_zero_flags_installs_read_and_write_ends_after_copyout() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    let mut out = [-1i32; 2];

    assert_eq!(pipe2_syscall::sys_pipe2(&args(out.as_mut_ptr() as u64, 0)), 0);
    assert_eq!(out, [0, 1]);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 1);
    let rf = fdt.get(out[0]).expect("read end installed");
    let wf = fdt.get(out[1]).expect("write end installed");
    assert_eq!(rf.flags().bits() & O_ACCMODE, OpenFlags::O_RDONLY.bits());
    assert_eq!(wf.flags().bits() & O_ACCMODE, OpenFlags::O_WRONLY.bits());
    assert!(!fdt.cloexec(out[0]).unwrap());
    assert!(!fdt.cloexec(out[1]).unwrap());
    assert_eq!(wf.write(b"x"), Ok(1));
    let mut b = [0u8; 1];
    assert_eq!(rf.read(&mut b), Ok(1));
    assert_eq!(b, [b'x']);
    reset();
}

#[test]
fn pipe2_flags_apply_to_correct_endpoints() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    let mut out = [-1i32; 2];
    let flags = (OpenFlags::O_CLOEXEC | OpenFlags::O_NONBLOCK | OpenFlags::O_DIRECT).bits() as u64;

    assert_eq!(pipe2_syscall::sys_pipe2(&args(out.as_mut_ptr() as u64, flags)), 0);
    let rf = fdt.get(out[0]).expect("read end installed");
    let wf = fdt.get(out[1]).expect("write end installed");
    assert!(fdt.cloexec(out[0]).unwrap());
    assert!(fdt.cloexec(out[1]).unwrap());
    assert!(rf.flags().contains(OpenFlags::O_NONBLOCK));
    assert!(wf.flags().contains(OpenFlags::O_NONBLOCK));
    assert!(!rf.flags().contains(OpenFlags::O_DIRECT));
    assert!(wf.flags().contains(OpenFlags::O_DIRECT));
    reset();
}

#[test]
fn o_direct_pipe_read_consumes_one_packet_and_discards_short_tail() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    let mut out = [-1i32; 2];
    let flags = (OpenFlags::O_NONBLOCK | OpenFlags::O_DIRECT).bits() as u64;

    assert_eq!(pipe2_syscall::sys_pipe2(&args(out.as_mut_ptr() as u64, flags)), 0);
    let rf = fdt.get(out[0]).expect("read end installed");
    let wf = fdt.get(out[1]).expect("write end installed");
    assert_eq!(wf.write(b"abcd"), Ok(4));
    assert_eq!(wf.write(b"ef"), Ok(2));
    let mut first = [0u8; 2];
    assert_eq!(rf.read(&mut first), Ok(2));
    assert_eq!(first, *b"ab");
    let mut second = [0u8; 8];
    assert_eq!(rf.read(&mut second), Ok(2));
    assert_eq!(&second[..2], b"ef");
    assert_eq!(rf.read(&mut second), Err(VfsError::Eagain));
    reset();
}

#[test]
fn stream_pipe_read_coalesces_writes_without_packet_discard() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    let mut out = [-1i32; 2];
    let flags = OpenFlags::O_NONBLOCK.bits() as u64;

    assert_eq!(pipe2_syscall::sys_pipe2(&args(out.as_mut_ptr() as u64, flags)), 0);
    let rf = fdt.get(out[0]).expect("read end installed");
    let wf = fdt.get(out[1]).expect("write end installed");
    assert_eq!(wf.write(b"abcd"), Ok(4));
    assert_eq!(wf.write(b"ef"), Ok(2));
    let mut first = [0u8; 2];
    assert_eq!(rf.read(&mut first), Ok(2));
    assert_eq!(first, *b"ab");
    let mut second = [0u8; 8];
    assert_eq!(rf.read(&mut second), Ok(4));
    assert_eq!(&second[..4], b"cdef");
    reset();
}

#[test]
fn pollout_tracks_current_pipe_capacity() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    let mut out = [-1i32; 2];
    let flags = OpenFlags::O_NONBLOCK.bits() as u64;

    assert_eq!(pipe2_syscall::sys_pipe2(&args(out.as_mut_ptr() as u64, flags)), 0);
    let rf = fdt.get(out[0]).expect("read end installed");
    let wf = fdt.get(out[1]).expect("write end installed");
    assert_eq!(fs::pipe::set_pipe_size(wf.inode(), 2), Ok(2));
    assert_ne!(wf.poll() & POLL_OUT, 0);
    assert_eq!(wf.write(b"xy"), Ok(2));
    assert_eq!(wf.poll() & POLL_OUT, 0);
    let mut b = [0u8; 1];
    assert_eq!(rf.read(&mut b), Ok(1));
    assert_ne!(wf.poll() & POLL_OUT, 0);
    reset();
}

#[test]
fn copyout_fault_rolls_back_both_reserved_fds() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    install_current_with_fdt(Some(Arc::clone(&fdt)));
    let mut out = [-1i32; 2];
    userbuf::FAIL_WRITE.store(true, Ordering::SeqCst);

    assert_eq!(pipe2_syscall::sys_pipe2(&args(out.as_mut_ptr() as u64, 0)),
        -(Errno::Efault.as_i32() as i64));
    assert_eq!(out, [-1, -1]);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(fdt.count(), 0);
    assert!(fdt.live_fds().is_empty());
    assert_eq!(fdt.get_unused_fd_flags(OpenFlags::empty(), vfs::FD_TABLE_MAX), Ok(0));
    reset();
}

#[test]
fn second_fd_reservation_failure_rolls_back_first_fd() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let fdt = Arc::new(FdTable::new());
    let task = install_current_with_fdt(Some(Arc::clone(&fdt)));
    // SAFETY: test task is private to this harness and not concurrently scheduled.
    task.set_rlimit(sched::rlimit::rlim::NOFILE, (1, 1));
    let mut out = [-1i32; 2];

    assert_eq!(pipe2_syscall::sys_pipe2(&args(out.as_mut_ptr() as u64, 0)),
        -(VfsError::Emfile as i64));
    assert_eq!(out, [-1, -1]);
    assert_eq!(userbuf::WRITE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(fdt.count(), 0);
    assert!(fdt.live_fds().is_empty());
    assert_eq!(fdt.get_unused_fd_flags(OpenFlags::empty(), vfs::FD_TABLE_MAX), Ok(0));
    reset();
}
