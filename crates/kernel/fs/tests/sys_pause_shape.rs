extern crate alloc;

use alloc::boxed::Box;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SaHandler, SchedClass, Task};
use sched::signum::Signum;
use syscall::{errno::Errno, SyscallArgs};

#[path = "../../syscalls/src/034_pause.rs"]
mod pause_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_TID: AtomicU64 = AtomicU64::new(0x3400);

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const TEST_HANDLER: u64 = 0x5555_3400;

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
}

fn args() -> SyscallArgs {
    SyscallArgs { a0: 0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn install_current() -> &'static Task {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    let task = Box::leak(Box::new(Task::new(tid as u32, "pause-test", SchedClass::Normal { weight: 1024 })));
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
fn pause_without_current_returns_eintr() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    assert_eq!(pause_syscall::sys_pause(&args()), -(Errno::Eintr.as_i32() as i64));
    reset();
}

#[test]
fn pause_caught_signal_returns_restart_nohand_for_dispatch_tail() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let task = install_current();
    set_action(task, Signum::Sigusr1, TEST_HANDLER);
    raise(task, Signum::Sigusr1);

    assert_eq!(pause_syscall::sys_pause(&args()), syscall::restart::restart_nohand());
    assert_ne!(task.sigpending.load(Ordering::Acquire) & Signum::Sigusr1.bit(), 0,
        "dispatch tail, not pause itself, consumes the deliverable signal");
    reset();
}

#[test]
fn pause_masked_signal_does_not_complete_in_hosted_probe() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let task = install_current();
    set_action(task, Signum::Sigusr1, TEST_HANDLER);
    task.sigmask.store(Signum::Sigusr1.bit(), Ordering::Release);
    raise(task, Signum::Sigusr1);

    assert!(!pause_syscall::pause_actionable_signal_pending_for_test(task));
    assert_eq!(pause_syscall::sys_pause(&args()), -(Errno::Eintr.as_i32() as i64),
        "hosted no-runqueue path must not spin forever when Linux would block");
    reset();
}

#[test]
fn pause_discards_explicitly_ignored_signal_and_keeps_waiting() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let task = install_current();
    set_action(task, Signum::Sigusr1, SIG_IGN);
    raise(task, Signum::Sigusr1);

    assert!(!pause_syscall::pause_actionable_signal_pending_for_test(task));
    assert_eq!(task.sigpending.load(Ordering::Acquire) & Signum::Sigusr1.bit(), 0);
    reset();
}

#[test]
fn pause_discards_default_noop_signals() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let task = install_current();
    set_action(task, Signum::Sigchld, SIG_DFL);
    raise(task, Signum::Sigchld);
    raise(task, Signum::Sigcont);

    assert!(!pause_syscall::pause_actionable_signal_pending_for_test(task));
    assert_eq!(task.sigpending.load(Ordering::Acquire) & (Signum::Sigchld.bit() | Signum::Sigcont.bit()), 0);
    reset();
}

#[test]
fn pause_unblockable_signal_bypasses_mask() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let task = install_current();
    task.sigmask.store(u64::MAX, Ordering::Release);
    raise(task, Signum::Sigkill);

    assert!(pause_syscall::pause_actionable_signal_pending_for_test(task));
    assert_eq!(pause_syscall::sys_pause(&args()), syscall::restart::restart_nohand());
    reset();
}

#[test]
fn pause_default_stop_signal_does_not_complete_as_eintr() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let task = install_current();
    raise(task, Signum::Sigstop);

    assert!(!pause_syscall::pause_actionable_signal_pending_for_test(task),
        "default stop is handled by job-control stop/restart, not user EINTR");
    assert_eq!(task.sigpending.load(Ordering::Acquire) & Signum::Sigstop.bit(), 0);
    reset();
}
