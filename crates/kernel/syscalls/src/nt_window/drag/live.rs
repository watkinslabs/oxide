//! Live routing for the drag-detect, drag-transfer and input-idle ordinals
//! against the canonical per-process window owner.
use super::super::*;
use crate::nt_wine_window::drag_raw::{self, DragStep, IdleWake};
use crate::nt_wine_window::queue_raw::wait;
use ipc::win32_window::{queue_status, MessageFilter, WM_MOUSEHWHEEL, WM_MOUSEMOVE};

const FALSE: u64 = 0;
const TRUE: u64 = 1;
/// A pseudo-handle naming the caller's own process.
const CURRENT_PROCESS: u64 = u64::MAX;

/// Route one drag or input-idle ordinal. # C: O(1) plus the arm's own cost
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let arg = |index: usize| args.get(index).copied().unwrap_or(0);
    match ordinal {
        drag_raw::DRAG_DETECT => Some(drag_detect(arg(0), arg(1) as i32, arg(2) as i32)),
        drag_raw::DRAG_OBJECT => Some(drag_raw::DRAG_OBJECT_NONE),
        drag_raw::WAIT_FOR_INPUT_IDLE => Some(wait_for_input_idle(arg(0), arg(1) as u32)),
        _ => None,
    }
}

/// One non-display metric, from the same canonical owner every metric query
/// reads. # C: O(1)
fn metric(index: i32) -> i32 { ipc::win32_gdi::system_metric_default(index).unwrap_or(0) }

/// Track one press until the pointer leaves the drag square or the button
/// comes up. The coordinates are client relative, as the reference's are.
/// A press whose button is already up is no gesture at all.
/// # C: O(N_queued mouse messages); # Sleeps: yes
fn drag_detect(hwnd: u64, x: i32, y: i32) -> u64 {
    let state = keyboard::get_key_state_current(drag_raw::VK_LBUTTON as u64) as u16;
    if !drag_raw::left_button_down(state) { return FALSE; }
    let rect = drag_raw::drag_rect(x, y, metric(drag_raw::SM_CXDRAG), metric(drag_raw::SM_CYDRAG));
    user_input::set_capture_for_current(hwnd, 0);
    let filter = MessageFilter { hwnd: None, first: WM_MOUSEMOVE, last: WM_MOUSEHWHEEL };
    loop {
        while let Some(message) = peek_for_current(filter) {
            match drag_raw::drag_step(message.message, message.lparam, rect) {
                DragStep::Released => { user_input::release_capture_for_current(); return FALSE; }
                DragStep::Escaped => { user_input::release_capture_for_current(); return TRUE; }
                DragStep::Continue => {}
            }
        }
        // An interrupted park leaves the gesture: a kernel loop may not ignore
        // a pending signal the way the reference's user-mode loop does.
        if message_queue::msg_wait(0, 0, wait::INFINITE, queue_status::QS_ALLINPUT) == wait::WAIT_IO_COMPLETION {
            user_input::release_capture_for_current();
            return FALSE;
        }
    }
}

/// Remove one message in the mouse range from the calling thread's queue.
/// # C: O(N_nt_processes + N_queued)
fn peek_for_current(filter: MessageFilter) -> Option<ipc::win32_window::WinMessage> {
    let tid = owner::current_tid()?;
    owner::with_state_mut(|state| state.peek_for_thread(tid, filter, true))?
}

/// Latch that the calling process has drained its input and wake every thread
/// parked on an input-idle wait. The latch is never cleared, as the event the
/// reference signals here is manual reset and reset by nothing.
/// # C: O(N_nt_processes)
pub(crate) fn mark_idle_for_current() {
    let Some(cur) = sched::live::current().filter(|task| task.is_nt_personality()) else { return; };
    let group = Arc::clone(&cur.thread_group);
    let mut waiters = Vec::new();
    {
        let mut entries = GUI.lock();
        entries.retain(|entry| entry.group.upgrade().is_some());
        let Some(entry) = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return; };
        if entry.idle { return; }
        entry.idle = true;
        for entry in entries.iter() { if waiters.try_reserve(1).is_ok() { waiters.push(Arc::clone(&entry.wait)); } }
    }
    for wait in waiters { wait.wake_all(); }
}

/// Whether one process has latched its input-idle state. # C: O(N_nt_processes)
fn process_is_idle(group: &Arc<sched::thread_group::ThreadGroup>) -> bool {
    GUI.lock().iter().any(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, group)) && entry.idle)
}

/// Resolve the named process, then wait until it drains its input, ends, or
/// the caller's timeout expires. A process that has already ended, and one
/// already idle, both report success immediately.
/// # C: O(N_nt_processes); # Sleeps: yes
fn wait_for_input_idle(process: u64, timeout_ms: u32) -> u64 {
    let Some(cur) = sched::live::current().filter(|task| task.is_nt_personality()) else {
        return drag_raw::idle_result(IdleWake::Failed);
    };
    let target = if process == CURRENT_PROCESS { Arc::clone(&cur.thread_group) } else {
        let table = cur.thread_group.nt_handles();
        let Some(task) = crate::nt_process_handles::process_task(process, table,
            crate::nt_process_handles::PROCESS_QUERY_INFORMATION_ACCESS) else {
            return drag_raw::idle_result(IdleWake::Failed);
        };
        Arc::clone(&task.thread_group)
    };
    let waiter = with_entry_wait();
    let start = timekeeper::monotonic_ns();
    let deadline = wait::deadline_ns(start, timeout_ms);
    loop {
        if target.group_exit_status().is_some() { return drag_raw::idle_result(IdleWake::ProcessEnded); }
        if process_is_idle(&target) { return drag_raw::idle_result(IdleWake::Idle); }
        let now = timekeeper::monotonic_ns();
        let elapsed = now.saturating_sub(start).saturating_div(1_000_000);
        if drag_raw::idle_expired(timeout_ms, elapsed) || deadline.is_some_and(|limit| now >= limit) {
            return drag_raw::idle_result(IdleWake::TimedOut);
        }
        let Some(waiter) = waiter.as_ref() else { return drag_raw::idle_result(IdleWake::Failed); };
        let group = Arc::clone(&target);
        // SAFETY: wait_for_input_idle owns the wait-list and thread-group references
        // for the whole park and rechecks both the idle latch and the exit status
        // after every wake, before answering.
        let outcome = unsafe { sched::live::wait_event_interruptible_until(waiter, deadline.unwrap_or(0), timekeeper::monotonic_ns,
            || group.group_exit_status().is_some() || process_is_idle(&group)) };
        if outcome != sched::task::WaitOutcome::Ready && outcome != sched::task::WaitOutcome::TimedOut {
            return drag_raw::idle_result(IdleWake::Failed);
        }
    }
}

/// The calling process's own wait list, which every idle latch wakes.
/// # C: O(N_nt_processes)
fn with_entry_wait() -> Option<Arc<sched::live::WaitList>> {
    let cur = sched::live::current()?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(owner::new_entry(&group)); entries.len() - 1 });
    Some(Arc::clone(&entries[index].wait))
}
