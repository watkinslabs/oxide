//! Native NT thread-pool and timer-queue lifecycle boundaries.
#![cfg(target_os = "oxide-kernel")]
use syscall::nt::{NtCall, NtService};
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;

/// Validate NT callback lifecycle boundaries owned by the current thread group.
/// # C: O(1)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::TpSimpleTryPost {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        // Simple-post objects are retained by the native pool for callback
        // execution; no detached callback state is created without that owner.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::TpSetPoolStackInformation {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a1 == 0 {
            return Some(STATUS_INVALID_PARAMETER);
        }
        // Pool stack information belongs to the locked native pool object;
        // no state is mutated until that object owner exists.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::TpQueryPoolStackInformation {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a1 == 0 {
            return Some(STATUS_INVALID_PARAMETER);
        }
        // Pool stack information belongs to the locked native pool object;
        // no output structure is populated until that object owner exists.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::TpCallbackMayRunLong {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // The callback instance is owned by the callback dispatcher. Without
        // that owner, changing worker availability would create untracked
        // execution state, so no success status is reported for a fake one.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::TpAllocWork {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // Work objects own callback state, pool membership, and queued-work
        // lifetime; no user-visible work pointer is published before that
        // native ownership boundary exists.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::TpAllocWait {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // Wait objects own callback state, pool membership, and wait-queue
        // lifetime; no user-visible wait pointer is published before that
        // native ownership boundary exists.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::TpAllocTimer {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // Timer objects own callback state, pool membership, and timer-queue
        // lifetime; no user-visible timer pointer is published before that
        // native ownership boundary exists.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::TpAllocPool {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // The pool owns worker threads, callback queues, and shutdown state;
        // no user-visible pool pointer is published before that owner exists.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::TpAllocIoCompletion {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // I/O completion objects own a file registration, completion queue,
        // and user callback trampoline; none has a native owner yet.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::TpAllocCleanupGroup {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // A cleanup group owns user callback objects and callback-drain state;
        // no kernel object may be returned until that ownership boundary exists.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::RtlQueueWorkItem {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // The scheduler workqueue executes kernel WorkFn values. A Windows
        // callback is a user instruction pointer and needs a user-thread
        // callback trampoline/ownership path before it can be queued safely.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::RtlRegisterWait { return Some(register(call)); }
    if call.service == NtService::RtlDeregisterWait {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        if call.args.a0 == 0 { return Some(STATUS_INVALID_HANDLE); }
        let mut waits = cur.thread_group.nt_waits.lock();
        let Some(index) = waits.iter().position(|wait| wait.0 == call.args.a0) else { return Some(STATUS_INVALID_HANDLE); };
        waits.swap_remove(index); return Some(0);
    }
    if call.service == NtService::RtlDeregisterWaitEx {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // Keep the wait record live when the completion-event form is not
        // supported; deregistration must not lose state before returning the
        // unsupported result.
        if call.args.a1 != 0 { return Some(STATUS_NOT_IMPLEMENTED); }
        let mut waits = cur.thread_group.nt_waits.lock();
        let Some(index) = waits.iter().position(|wait| wait.0 == call.args.a0) else { return Some(STATUS_INVALID_HANDLE); };
        waits.swap_remove(index);
        return Some(0);
    }
    if call.service == NtService::RtlCreateTimerQueue {
        if call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::RtlDeleteTimer {
        if call.args.a0 == 0 || call.args.a1 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::RtlDeleteTimerQueueEx {
        if call.args.a0 == 0 { return Some(STATUS_INVALID_HANDLE); }
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::RtlUpdateTimer {
        if call.args.a0 == 0 || call.args.a1 == 0 { return Some(STATUS_INVALID_HANDLE); }
        // Timer-queue callback state is distinct from native waitable timers;
        // its callback execution path must be owned before an update can
        // mutate a live queue entry safely.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service != NtService::RtlCreateTimer { return None; }
    if call.args.a0 == 0 || call.args.a1 == 0 || call.args.a2 == 0 {
        return Some(STATUS_INVALID_PARAMETER);
    }
    // Native waitable timers already use the scheduler timer owner. A timer
    // queue additionally owns callback dispatch, cancellation, and callback
    // completion; that userspace callback contract is not present yet.
    Some(STATUS_NOT_IMPLEMENTED)
}

fn register(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a1 == 0 || call.args.a2 == 0 { return STATUS_INVALID_PARAMETER; }
    if call.args.a1 > u32::MAX as u64 || !cur.thread_group.nt_handles.contains(sched::nt_object::NtHandle::from_raw(call.args.a1 as u32)) { return STATUS_INVALID_HANDLE; }
    let sequence = cur.thread_group.nt_wait_next.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let Some(token) = sequence.checked_add(0x8000_0000_0000_0000) else { return STATUS_INVALID_PARAMETER; };
    cur.thread_group.nt_waits.lock().push((token, call.args.a1, call.args.a2, call.args.a3, call.args.a4 as u32, call.args.a5 as u32));
    if uaccess::put_user_u64(call.args.a0, token).is_err() { let mut waits = cur.thread_group.nt_waits.lock(); waits.retain(|wait| wait.0 != token); return STATUS_INVALID_PARAMETER; }
    0
}
