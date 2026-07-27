extern crate alloc;

use alloc::boxed::Box;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::SyscallArgs;

#[path = "../../syscalls/src/037_alarm.rs"]
mod alarm_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_TID: AtomicU64 = AtomicU64::new(0x3700);

const NSEC_PER_SEC: u64 = 1_000_000_000;

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
    alarm_syscall::set_test_now_ns(0);
}

fn args(seconds: u64) -> SyscallArgs {
    SyscallArgs { a0: seconds, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn install_current() -> &'static Task {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    let task = Box::leak(Box::new(Task::new(tid as u32, "alarm-test", SchedClass::Normal { weight: 1024 })));
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

#[test]
fn alarm_sets_relative_deadline_and_clears_itimer_interval() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let task = install_current();
    alarm_syscall::set_test_now_ns(10 * NSEC_PER_SEC);
    task.alarm_ns.store(20 * NSEC_PER_SEC, Ordering::Release);
    task.alarm_interval_ns.store(2 * NSEC_PER_SEC, Ordering::Release);

    assert_eq!(alarm_syscall::sys_alarm(&args(3)), 10);
    assert_eq!(task.alarm_ns.load(Ordering::Acquire), 13 * NSEC_PER_SEC);
    assert_eq!(task.alarm_interval_ns.load(Ordering::Acquire), 0,
        "Linux alarm_setitimer programs ITIMER_REAL with zero interval");
    reset();
}

#[test]
fn alarm_disarm_returns_linux_rounded_remaining_time() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let task = install_current();
    alarm_syscall::set_test_now_ns(10 * NSEC_PER_SEC);
    task.alarm_ns.store(10 * NSEC_PER_SEC + 1, Ordering::Release);

    assert_eq!(alarm_syscall::sys_alarm(&args(0)), 1,
        "Linux alarm never returns 0 for a pending sub-second alarm");
    assert_eq!(task.alarm_ns.load(Ordering::Acquire), 0);
    reset();
}

#[test]
fn alarm_uses_linux_unsigned_int_argument_width() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let task = install_current();
    alarm_syscall::set_test_now_ns(NSEC_PER_SEC);

    assert_eq!(alarm_syscall::sys_alarm(&args((1_u64 << 32) | 7)), 0);
    assert_eq!(task.alarm_ns.load(Ordering::Acquire), 8 * NSEC_PER_SEC);
    reset();
}
