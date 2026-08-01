extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};

use super::clock::schedule;
use super::types::*;

static NEXT_PID: AtomicI32 = AtomicI32::new(1);
static CURRENT_KTHREAD: AtomicPtr<LinuxTaskStruct> = AtomicPtr::new(null_mut());

pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("kthread_create", kthread_create as *const () as usize),
        ("wake_up_process", wake_up_process as *const () as usize),
        ("kthread_should_stop", kthread_should_stop as *const () as usize),
        ("kthread_stop", kthread_stop as *const () as usize),
        ("kthread_associate_blkcg", kthread_associate_blkcg as *const () as usize),
        ("set_current_state", set_current_state as *const () as usize),
    ] { export(name, addr, false); }
}

pub(super) extern "C" fn kthread_create(threadfn: Option<KthreadFn>, data: *mut u8, namefmt: *const u8) -> *mut LinuxTaskStruct {
    let Some(func) = threadfn else { return null_mut(); };
    let pid = NEXT_PID.fetch_add(1, Ordering::AcqRel);
    let name = leak_name(namefmt);
    let task = Box::new(LinuxTaskStruct {
        pid,
        should_stop: AtomicI32::new(0),
        result: AtomicI32::new(0),
        done: AtomicBool::new(false),
        started: AtomicBool::new(false),
        start: null_mut(),
    });
    let task = Box::into_raw(task);
    let start = Box::into_raw(Box::new(KthreadStart { task, func, data, name }));
    // SAFETY: task points to the allocation just created above.
    unsafe { (*task).start = start; }
    task
}

pub(super) extern "C" fn wake_up_process(task: *mut LinuxTaskStruct) -> i32 {
    if task.is_null() { return 0; }
    // SAFETY: non-null task pointer was allocated by kthread_create.
    let start = unsafe {
        if (*task).started.swap(true, Ordering::AcqRel) { return 0; }
        (*task).start
    };
    if start.is_null() { return 0; }
    #[cfg(target_os = "oxide-kernel")]
    {
        let tid = sched::live::next_tid();
        // SAFETY: runqueue is live; start points to a KthreadStart owned by task.
        if unsafe { sched::live::spawn_kernel_thread(tid, (*start).name, kthread_entry, start as usize) }.is_err() { return 0; }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    kthread_entry_hosted(start);
    1
}

pub(super) extern "C" fn kthread_should_stop() -> i32 {
    let task = CURRENT_KTHREAD.load(Ordering::Acquire);
    if task.is_null() { return 0; }
    // SAFETY: current kthread pointer is set only while the backing task lives.
    unsafe { (*task).should_stop.load(Ordering::Acquire) }
}

pub(super) extern "C" fn kthread_stop(task: *mut LinuxTaskStruct) -> i32 {
    if task.is_null() { return 0; }
    // SAFETY: non-null task pointer was allocated by kthread_create.
    unsafe { (*task).should_stop.store(1, Ordering::Release); }
    // SAFETY: task is the kthread_create Box, and kthread_stop below is the only code that frees
    // it — the trampoline only ever stores into result/done — so it stays live for this spin.
    while unsafe { !(*task).done.load(Ordering::Acquire) } {
        schedule();
    }
    // SAFETY: task is stopped and no longer referenced by the trampoline.
    unsafe {
        let result = (*task).result.load(Ordering::Acquire);
        drop(Box::from_raw((*task).start));
        drop(Box::from_raw(task));
        result
    }
}

pub(super) extern "C" fn kthread_associate_blkcg(_css: *mut u8) -> i32 { 0 }
pub(super) extern "C" fn set_current_state(state: i32) { let _ = state; }

#[cfg(target_os = "oxide-kernel")]
extern "C" fn kthread_entry(arg: usize) -> ! {
    let start = arg as *mut KthreadStart;
    run_kthread(start);
    if let Some(cur) = sched::live::current() { sched::live::mark_done(cur); }
    // SAFETY: schedule() requires the caller to be the running task on this CPU and to own the
    // switch — this is the kthread's own entry trampoline, running as that task, and mark_done on
    // the line above already took it off the runnable set, so nothing re-picks it and the call
    // never returns into a stale frame.
    unsafe {
        sched::live::schedule();
    }
    loop { core::hint::spin_loop(); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn kthread_entry_hosted(start: *mut KthreadStart) {
    if !start.is_null() {
        // SAFETY: hosted kthread start pointer is allocated by kthread_create.
        let _ = unsafe { (*start).name };
    }
    run_kthread(start);
}

fn run_kthread(start: *mut KthreadStart) {
    if start.is_null() { return; }
    // SAFETY: start is allocated by kthread_create and remains owned by task until stop.
    let task = unsafe { (*start).task };
    CURRENT_KTHREAD.store(task, Ordering::Release);
    // SAFETY: start fields are immutable after kthread_create.
    let result = unsafe { ((*start).func)((*start).data) };
    // SAFETY: task pointer is valid until kthread_stop observes done.
    unsafe {
        (*task).result.store(result, Ordering::Release);
        (*task).done.store(true, Ordering::Release);
    }
    CURRENT_KTHREAD.store(null_mut(), Ordering::Release);
}

fn leak_name(namefmt: *const u8) -> &'static str {
    if namefmt.is_null() { return DEFAULT_KTHREAD_NAME; }
    let mut out = String::new();
    let mut i = 0usize;
    loop {
        // SAFETY: Linux caller passes a NUL-terminated format string.
        let b = unsafe { *namefmt.add(i) };
        if b == 0 || b == b'%' { break; }
        out.push(b as char);
        i += 1;
    }
    if out.is_empty() { DEFAULT_KTHREAD_NAME } else { Box::leak(out.into_boxed_str()) }
}
