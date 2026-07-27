extern crate alloc;

use alloc::boxed::Box;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use syscall::SyscallArgs;

#[path = "../../syscalls/src/039_getpid.rs"]
mod getpid_syscall;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());

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
    SyscallArgs { a0: u64::MAX, a1: u64::MAX, a2: u64::MAX, a3: u64::MAX, a4: u64::MAX, a5: u64::MAX }
}

fn install_current(tid: u32, tgid: u32, vtgid: u32) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(tid, "getpid-test", SchedClass::Normal { weight: 1024 })));
    task.tgid.store(tgid, Ordering::Release);
    task.vtgid.store(vtgid, Ordering::Release);
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

#[test]
fn getpid_returns_thread_group_id_not_thread_id() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    install_current(0x3901, 77, 0);

    assert_eq!(getpid_syscall::sys_getpid(&args()), 77,
        "Linux sys_getpid returns task_tgid_vnr(current), not task_pid_vnr(current)");
    reset();
}

#[test]
fn getpid_returns_namespace_visible_tgid_when_present() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    install_current(0x3902, 0xdead, 12);

    assert_eq!(getpid_syscall::sys_getpid(&args()), 12,
        "Linux task_tgid_vnr reports the caller's namespace-visible TGID");
    reset();
}

#[test]
fn getpid_without_current_uses_boot_fallback() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();

    assert_eq!(getpid_syscall::sys_getpid(&args()), 1);
    reset();
}
