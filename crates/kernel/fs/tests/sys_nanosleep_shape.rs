extern crate alloc;

use alloc::boxed::Box;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SaHandler, SchedClass, Task};
use sched::signum::Signum;
use syscall::{errno::Errno, SyscallArgs};

#[path = "../../syscalls/src/035_nanosleep.rs"]
mod nanosleep_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_TID: AtomicU64 = AtomicU64::new(0x3500);

const SIG_IGN: u64 = 1;
const TEST_HANDLER: u64 = 0x5555_3500;

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
    nanosleep_syscall::set_test_now_ns(0);
}

fn args(req: u64, rem: u64) -> SyscallArgs {
    SyscallArgs { a0: req, a1: rem, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn timespec(sec: i64, nsec: i64) -> [i64; 2] { [sec, nsec] }

fn install_current() -> &'static Task {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    let task = Box::leak(Box::new(Task::new(tid as u32, "nanosleep-test", SchedClass::Normal { weight: 1024 })));
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn set_action(task: &Task, sig: Signum, handler: u64) {
    let act = SaHandler { handler, flags: 0, restorer: 0, mask: 0 };
    task.rt_sigaction(sig as usize, Some(act)).unwrap();
}

fn raise(task: &Task, sig: Signum) {
    task.sigpending.fetch_or(sig.bit(), Ordering::Release);
}

#[test]
fn nanosleep_null_req_faults_before_any_rem_check() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let mut rem = timespec(77, 88);

    assert_eq!(
        nanosleep_syscall::sys_nanosleep(&args(0, rem.as_mut_ptr() as u64)),
        -(Errno::Efault.as_i32() as i64)
    );
    assert_eq!(rem, timespec(77, 88));
    reset();
}

#[test]
fn nanosleep_rejects_invalid_timespec_after_copyin() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let req = timespec(0, 1_000_000_000);

    assert_eq!(
        nanosleep_syscall::sys_nanosleep(&args(req.as_ptr() as u64, 1)),
        -(Errno::Einval.as_i32() as i64),
        "bad rem is not checked before Linux timespec validation"
    );
    reset();
}

#[test]
fn nanosleep_zero_duration_succeeds_without_touching_rem() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let req = timespec(0, 0);
    let mut rem = timespec(11, 22);

    assert_eq!(nanosleep_syscall::sys_nanosleep(&args(req.as_ptr() as u64, rem.as_mut_ptr() as u64)), 0);
    assert_eq!(rem, timespec(11, 22));
    reset();
}

#[test]
fn nanosleep_actionable_signal_copies_rem_and_returns_restartblock() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let task = install_current();
    set_action(task, Signum::Sigusr1, TEST_HANDLER);
    raise(task, Signum::Sigusr1);
    nanosleep_syscall::set_test_now_ns(1_000_000_000);
    let req = timespec(2, 500_000_000);
    let mut rem = timespec(0, 0);

    assert_eq!(
        nanosleep_syscall::sys_nanosleep(&args(req.as_ptr() as u64, rem.as_mut_ptr() as u64)),
        syscall::restart::restart_block()
    );
    assert_eq!(rem, timespec(2, 500_000_000));
    reset();
}

#[test]
fn nanosleep_actionable_signal_with_bad_rem_faults_at_interrupt_time() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let task = install_current();
    set_action(task, Signum::Sigusr1, TEST_HANDLER);
    raise(task, Signum::Sigusr1);
    let req = timespec(1, 0);

    assert_eq!(
        nanosleep_syscall::sys_nanosleep(&args(req.as_ptr() as u64, 1)),
        -(Errno::Efault.as_i32() as i64)
    );
    reset();
}

#[test]
fn nanosleep_ignored_and_default_noop_signals_do_not_interrupt() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let task = install_current();
    set_action(task, Signum::Sigusr1, SIG_IGN);
    raise(task, Signum::Sigusr1);
    raise(task, Signum::Sigchld);
    raise(task, Signum::Sigcont);

    assert!(!nanosleep_syscall::nanosleep_actionable_signal_pending_for_test(task));
    assert_eq!(
        task.sigpending.load(Ordering::Acquire)
            & (Signum::Sigusr1.bit() | Signum::Sigchld.bit() | Signum::Sigcont.bit()),
        0
    );
    reset();
}

#[test]
fn nanosleep_masked_signal_does_not_interrupt_but_sigkill_does() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset();
    let task = install_current();
    set_action(task, Signum::Sigusr1, TEST_HANDLER);
    task.sigmask.store(Signum::Sigusr1.bit(), Ordering::Release);
    raise(task, Signum::Sigusr1);

    assert!(!nanosleep_syscall::nanosleep_actionable_signal_pending_for_test(task));
    raise(task, Signum::Sigkill);
    assert!(nanosleep_syscall::nanosleep_actionable_signal_pending_for_test(task));
    reset();
}

#[test]
fn restart_block_normalizes_to_user_visible_eintr() {
    assert_eq!(syscall::restart::restart_block(), -516);
    assert_eq!(
        syscall::restart::normalize_user_return(syscall::restart::restart_block()),
        -(Errno::Eintr.as_i32() as i64)
    );
}
