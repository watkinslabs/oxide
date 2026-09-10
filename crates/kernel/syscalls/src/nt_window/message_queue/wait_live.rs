//! Message/object wait loop; the same queue predicate governs initial and parked admission.
use super::super::*;
use crate::nt_wine_window::queue_raw::wait;

/// Wait until the queue holds work in one of the named classes, one of the
/// named objects signals, or the timeout expires. The queue occupies the wait
/// slot after the caller's objects and shares their process wait list, so an
/// object another thread signals releases this wait at once.
/// # C: O(N_objects + N_queued); # Sleeps: yes
pub(crate) fn msg_wait(count: u32, handles: u64, timeout_ms: u32, mask: u32) -> u32 {
    if !wait::count_admitted(count) {
        crate::nt_rtl::set_last_win32_error(wait::ERROR_INVALID_PARAMETER as u64);
        return wait::WAIT_FAILED;
    }
    let Some(cur) = sched::live::current().filter(|cur| cur.is_nt_personality()) else { return wait::WAIT_FAILED; };
    let Ok(objects) = crate::nt_dispatch::resolve_wait_objects(handles, count) else {
        crate::nt_rtl::set_last_win32_error(wait::ERROR_INVALID_PARAMETER as u64);
        return wait::WAIT_FAILED;
    };
    let group = Arc::clone(&cur.thread_group);
    let tid = cur.tid as u64;
    let deadline = wait::deadline_ns(timekeeper::monotonic_ns(), timeout_ms);
    loop {
        let now = timekeeper::monotonic_ns();
        let Some((ready, queue_deadline, wait_list)) = super::live::with_entry(|entry, tid| {
            entry.state.expire_timers(now);
            (super::ready::queue(entry,tid,mask), entry.state.next_retrieval_deadline(tid), Arc::clone(&entry.wait))
        }) else { return wait::WAIT_FAILED; };
        let expired = deadline.is_some_and(|limit| now >= limit);
        let signaled = objects.iter().map(|object| object.is_signaled_at(tid, now));
        if let Some(status) = wait::step_result(wait::step(signaled, ready, expired), count) { return status; }
        let park = sched::nt_object::merge_wait_deadline(deadline.unwrap_or(0), queue_deadline);
        // SAFETY: msg_wait holds owned wait-list and object references and rechecks
        // queue status plus object state after every wake, before answering.
        let outcome = unsafe { sched::live::wait_event_interruptible_until(&wait_list, park, timekeeper::monotonic_ns, || {
            let now = timekeeper::monotonic_ns();
            let object_signaled = objects.iter().any(|object| object.is_signaled_at(tid, now));
            let mut entries = GUI.lock();
            entries.retain(|entry| entry.group.upgrade().is_some());
            let queue_ready = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
                .is_some_and(|entry| super::ready::queue(entry,tid,mask));
            wait::wake_condition(queue_ready, object_signaled)
        }) };
        if outcome == sched::task::WaitOutcome::Ready || outcome == sched::task::WaitOutcome::TimedOut { continue; }
        return wait::WAIT_IO_COMPLETION;
    }
}
