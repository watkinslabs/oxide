// Current-thread caret blink deadline wrappers (`31fl`).

use alloc::sync::Arc;
use crate::nt_window::GUI;
use super::{publish_transition, CaretRenderSink};

fn current() -> Option<(Arc<sched::thread_group::ThreadGroup>, u64)> {
    let current = sched::live::current()?;
    current.is_nt_personality().then_some((Arc::clone(&current.thread_group), current.tid as u64))
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
/// No production caller (KI-0669); `retrieval_deadline_for_current` owns the
/// real GetMessage predicate. Kept for its own tested behavior.
#[allow(dead_code)]
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
