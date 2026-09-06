// Current-thread caret blink deadline wrappers (`31fl`).

use alloc::sync::Arc;
use ipc::win32_window::WindowId;
use crate::nt_window::GUI;
use super::{publish_transition, CaretRenderSink};

fn current() -> Option<(Arc<sched::thread_group::ThreadGroup>, u64)> {
    let current = sched::live::current()?;
    current.is_nt_personality().then_some((Arc::clone(&current.thread_group), current.tid as u64))
}

fn window_id(hwnd: u64) -> Option<WindowId> { u32::try_from(hwnd).ok().and_then(WindowId::from_raw) }

/// Arm the current queue's canonical caret deadline after visible-state change.
pub(crate) fn arm_for_current(hwnd: u64, generation: u64, now_ns: u64, interval_ms: u32) -> bool {
    let Some(window) = window_id(hwnd) else { return false; };
    let Some((group, tid)) = current() else { return false; };
    let mut entries = GUI.lock();
    let Some(entry) = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, &group))) else { return false; };
    entry.state.arm_current_caret_blink(tid, window, generation, now_ns, interval_ms).is_ok()
}

/// Clear the current queue's deadline for a caret/window teardown or hide.
pub(crate) fn clear_for_current(hwnd: Option<u64>) -> bool {
    let window = match hwnd { Some(raw) => { let Some(window) = window_id(raw) else { return false; }; Some(window) }, None => None };
    let Some((group, tid)) = current() else { return false; };
    let mut entries = GUI.lock();
    let Some(entry) = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, &group))) else { return false; };
    entry.state.clear_current_caret_blink(tid, window).unwrap_or(false)
}

fn expire_with_sink<S: CaretRenderSink + ?Sized>(now_ns: u64, sink: &mut S) -> u64 {
    let Some((group, tid)) = current() else { return 0; };
    let commit = { let mut entries = GUI.lock(); let Some(entry) = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, &group))) else { return 0; }; entry.state.expire_current_caret_blink(tid, now_ns).ok().flatten() };
    commit.map_or(0, |commit| publish_transition(sink, tid, commit.transition, commit.generation) as u64)
}

/// Apply an expired current-thread blink and publish after releasing GUI.
pub(crate) fn expire_for_current(now_ns: u64) -> u64 {
    let mut sink = super::publish::Current;
    expire_with_sink(now_ns, &mut sink)
}

/// Return the current queue's deadline for the GetMessage wait predicate.
pub(crate) fn deadline_for_current() -> Option<u64> {
    let Some((group, tid)) = current() else { return None; };
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, &group)))?;
    entry.state.current_caret_blink_deadline(tid).ok().flatten()
}

/// Return the one live deadline used by GetMessage timed waiting.
///
/// Both sources are canonical queue state: the caret deadline and the
/// existing WindowTimer vector. `None` means that this queue has no timed
/// wakeup; callers must not encode it as an immediate deadline.
pub(crate) fn retrieval_deadline_for_current() -> Option<u64> {
    let Some((group, tid)) = current() else { return None; };
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, &group)))?;
    entry.state.next_retrieval_deadline(tid)
}
