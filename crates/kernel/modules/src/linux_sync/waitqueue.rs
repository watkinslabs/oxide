// Linux waitqueue shim — `init_waitqueue_head`, `wake_up*`,
// `prepare_to_wait_event`, `finish_wait`.
//
// Split out of `linux_sync.rs` at the 500-line cap (`docs/08§7`). The
// interesting one is `prepare_to_wait_event`: Linux returns `-ERESTARTSYS`
// from it (`kernel/sched/wait.c:309`) and `___wait_event` propagates that
// (`include/linux/wait.h:315-318`), so a shim returning a flat `0` makes every
// module-side `wait_event_interruptible` UNINTERRUPTIBLE.

use core::ffi::c_void;
use core::sync::atomic::Ordering;

use super::{LINUX_ERESTARTSYS, LinuxSwaitQueueHead, LINUX_TASK_INTERRUPTIBLE, LINUX_TASK_WAKEKILL,
            LinuxWaitQueueEntry, LinuxWaitQueueHead, TASK_WAKE, WAIT_QUEUE,
            wait_cell, waitq_u32};

pub(super) extern "C" fn init_waitqueue_head(w: *mut LinuxWaitQueueHead) {
    if w.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned wait-queue storage.
    unsafe { (*w).seq = 0; }
}
pub(super) extern "C" fn __init_waitqueue_head(w: *mut LinuxWaitQueueHead, _name: *const u8, _key: *mut c_void) {
    init_waitqueue_head(w);
}
pub(super) extern "C" fn __init_swait_queue_head(w: *mut LinuxSwaitQueueHead, _name: *const u8, _key: *mut c_void) {
    if w.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned simple wait-queue storage.
    unsafe { (*w).seq = 0; }
}
pub(super) extern "C" fn wake_up(w: *mut LinuxWaitQueueHead) { wake_up_all(w); }
pub(super) extern "C" fn __wake_up(w: *mut LinuxWaitQueueHead, _mode: u32, _nr: i32, _key: *mut c_void) -> i32 {
    if _nr == 1 { wake_up_one(w); } else { wake_up_all(w); }
    1
}
fn wake_up_one(w: *mut LinuxWaitQueueHead) {
    if w.is_null() { return; }
    waitq_u32(w).fetch_add(1, Ordering::Release);
    wait_cell(w as usize, WAIT_QUEUE).wake_one();
}
pub(super) extern "C" fn wake_up_all(w: *mut LinuxWaitQueueHead) {
    if w.is_null() { return; }
    waitq_u32(w).fetch_add(1, Ordering::Release);
    wait_cell(w as usize, WAIT_QUEUE).wake_all();
}
pub(super) extern "C" fn waitqueue_active(w: *mut LinuxWaitQueueHead) -> i32 {
    if w.is_null() { 0 } else { wait_cell(w as usize, WAIT_QUEUE).active() as i32 }
}
pub(super) extern "C" fn init_wait_entry(e: *mut LinuxWaitQueueEntry, flags: i32) {
    if e.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned wait entry storage.
    unsafe { (*e).flags = flags as u32; (*e).private = core::ptr::null_mut(); (*e).func = core::ptr::null_mut(); (*e).seq = 0; }
}
/// Linux `prepare_to_wait_event` (`kernel/sched/wait.c:289-320`). The
/// `-ERESTARTSYS` at `wait.c:309` is the entire reason `wait_event_interruptible`
/// is interruptible at all: `___wait_event` propagates this return
/// (`include/linux/wait.h:315-318`). Returning a flat `0`, as this shim did,
/// made every module-side `wait_event_interruptible` UNINTERRUPTIBLE — a
/// signal could never break the loop.
pub(super) extern "C" fn prepare_to_wait_event(w: *mut LinuxWaitQueueHead, e: *mut LinuxWaitQueueEntry, state: i32) -> isize {
    if e.is_null() { return 0; }
    let cell = if w.is_null() { None } else { Some(wait_cell(w as usize, WAIT_QUEUE)) };
    let gate = cell.map(|c| c.gate.lock());
    // `signal_pending_state(state, current)`: bail BEFORE enqueueing, exactly
    // as `wait.c:295-309` does, so a caller that never parks still sees the
    // restart.
    if let Some(wait_state) = wait_state_for(state) {
        if signal_pending_state_current(wait_state) {
            drop(gate);
            return -LINUX_ERESTARTSYS as isize;
        }
    }
    let seq = if w.is_null() { 0 } else { waitq_u32(w).load(Ordering::Acquire) };
    // SAFETY: non-null pointer names caller-owned wait entry storage.
    unsafe { (*e).seq = seq; (*e).flags |= TASK_WAKE | state as u32; }
    if let Some(c) = cell { c.park_locked(); }
    drop(gate);
    0
}

/// `signal_pending_state`'s first line: `if (!(state & (TASK_INTERRUPTIBLE |
/// TASK_WAKEKILL))) return 0;` — a plain `TASK_UNINTERRUPTIBLE` sleep is never
/// broken by a signal. `None` means exactly that.
/// # C: O(1)
fn wait_state_for(state: i32) -> Option<sched::WaitState> {
    if state & LINUX_TASK_INTERRUPTIBLE != 0 { return Some(sched::WaitState::Interruptible); }
    if state & LINUX_TASK_WAKEKILL != 0 { return Some(sched::WaitState::Killable); }
    None
}

/// [`sched::signal_pending_state`] for the running task.
/// # C: O(N_sig)
#[cfg(target_os = "oxide-kernel")]
fn signal_pending_state_current(state: sched::WaitState) -> bool {
    sched::live::current().map(|t| sched::signal_pending_state(t, state)).unwrap_or(false)
}

/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
fn signal_pending_state_current(_state: sched::WaitState) -> bool { false }
pub(super) extern "C" fn finish_wait(w: *mut LinuxWaitQueueHead, e: *mut LinuxWaitQueueEntry) {
    if e.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned wait entry storage.
    unsafe { (*e).flags &= !TASK_WAKE; }
    if !w.is_null() { wait_cell(w as usize, WAIT_QUEUE).finish_waiter(); }
    #[cfg(target_os = "oxide-kernel")]
    if let Some(t) = sched::live::current() { t.set_state(sched::TaskState::Runnable); }
}
