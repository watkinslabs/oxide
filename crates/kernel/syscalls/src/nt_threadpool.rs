//! Native NT thread-pool and timer-queue lifecycle boundaries.
#![cfg(target_os = "oxide-kernel")]
use syscall::nt::{NtCall, NtService};
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const WT_EXECUTEINWAITTHREAD: u32 = 0x0000_0004;
const WT_EXECUTEONLYONCE: u32 = 0x0000_0008;
const WT_EXECUTELONGFUNCTION: u32 = 0x0000_0010;
const WT_EXECUTEINPERSISTENTTHREAD: u32 = 0x0000_0080;
const WT_TRANSFER_IMPERSONATION: u32 = 0x0000_0100;
const WT_SUPPORTED: u32 = WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE
    | WT_EXECUTELONGFUNCTION | WT_EXECUTEINPERSISTENTTHREAD | WT_TRANSFER_IMPERSONATION;

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
        return Some(allocate_callback(call, false));
    }
    if call.service == NtService::TpAllocTimer {
        return Some(allocate_callback(call, true));
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
        let mut waits = cur.thread_group.nt_callbacks.lock();
        let Some(index) = waits.iter().position(|wait| wait.token == call.args.a0) else { return Some(STATUS_INVALID_HANDLE); };
        waits.swap_remove(index); return Some(0);
    }
    if call.service == NtService::RtlDeregisterWaitEx {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let completion = if call.args.a1 == 0 { None } else {
            if call.args.a1 > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
            let table = cur.thread_group.nt_handles();
            let event = sched::nt_object::NtHandle::from_raw(call.args.a1 as u32);
            let Some(object) = table.get(event, SYNCHRONIZE_ACCESS) else { return Some(STATUS_INVALID_HANDLE); };
            if object.kind() != sched::nt_object::NtObjectType::Event { return Some(STATUS_INVALID_HANDLE); }
            Some(object)
        };
        let mut waits = cur.thread_group.nt_callbacks.lock();
        let Some(index) = waits.iter().position(|wait| wait.token == call.args.a0) else { return Some(STATUS_INVALID_HANDLE); };
        waits.swap_remove(index);
        if let Some(event) = completion { let _ = event.signal_for_wait(cur.tid as u64); }
        return Some(0);
    }
    if call.service == NtService::RtlCreateTimerQueue {
        return Some(create_timer_queue(call));
    }
    if call.service == NtService::RtlDeleteTimer {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a1 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let mut callbacks = cur.thread_group.nt_callbacks.lock();
        let Some(index) = callbacks.iter().position(|entry| entry.token == call.args.a1
            && matches!(entry.kind, sched::nt_callback::RegistrationKind::Timer { queue, .. } if queue == call.args.a0)) else {
            return Some(STATUS_INVALID_HANDLE);
        };
        callbacks.swap_remove(index);
        if call.args.a2 != 0 && call.args.a2 != u64::MAX {
            let table = cur.thread_group.nt_handles();
            let event = sched::nt_object::NtHandle::from_raw(call.args.a2 as u32);
            if let Some(object) = table.get(event, SYNCHRONIZE_ACCESS) {
                if let Some(event) = object.event() { event.set(); }
            }
        }
        return Some(0);
    }
    if call.service == NtService::RtlDeleteTimerQueueEx {
        return Some(delete_timer_queue(call));
    }
    if call.service == NtService::RtlUpdateTimer {
        return Some(update_timer(call));
    }
    if call.service != NtService::RtlCreateTimer { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a1 == 0 || call.args.a2 == 0 {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let token = cur.thread_group.nt_wait_next.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
        .checked_add(0x4000_0000_0000_0000).unwrap_or(0);
    if token == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let queue = match ensure_timer_queue(&cur, call.args.a0) { Some(queue) => queue, None => return Some(STATUS_INVALID_HANDLE) };
    let flags = crate::nt_dispatch::stack_argument(6).unwrap_or(0);
    if flags > u32::MAX as u64 { return Some(STATUS_INVALID_PARAMETER); }
    cur.thread_group.nt_callbacks.lock().push(sched::nt_callback::Registration {
        token, callback: call.args.a2, context: call.args.a3,
        kind: sched::nt_callback::RegistrationKind::Timer {
            queue, due_ms: call.args.a4 as u32, period_ms: call.args.a5 as u32, flags: flags as u32,
        },
    });
    if uaccess::put_user_u64(call.args.a1, token).is_err() {
        cur.thread_group.nt_callbacks.lock().retain(|entry| entry.token != token);
        return Some(STATUS_INVALID_PARAMETER);
    }
    let delay_ns = (call.args.a4 as u64).saturating_mul(1_000_000);
    if !sched::live::queue_delayed_work_on(0, timer_work, token as usize,
        timekeeper::monotonic_ns(), delay_ns) {
        cur.thread_group.nt_callbacks.lock().retain(|entry| entry.token != token);
        return Some(STATUS_NO_MEMORY);
    }
    Some(0)
}

fn timer_work(token: usize) {
    let token = token as u64;
    let mut target = None;
    for task in sched::registry::snapshot() {
        let callbacks = task.thread_group.nt_callbacks.lock();
        let Some(entry) = callbacks.iter().find(|entry| entry.token == token) else { continue; };
        let sched::nt_callback::RegistrationKind::Timer { period_ms, .. } = &entry.kind else { continue; };
        target = Some((alloc::sync::Arc::clone(&task), entry.callback, entry.context, *period_ms));
        drop(callbacks);
        break;
    }
    let Some((task, callback, context, period_ms)) = target else { return; };
    if task.nt_apc_queue.push(sched::nt_apc::Apc { routine: callback,
        argument1: context, argument2: 1, argument3: 0, flags: 0 }).is_ok() {
        task.nt_apc_queue.request_delivery();
    }
    if period_ms != 0 {
        let _ = sched::live::queue_delayed_work_on(0, timer_work, token as usize,
            timekeeper::monotonic_ns(), (period_ms as u64).saturating_mul(1_000_000));
    }
}

fn next_token(cur: &sched::Task, prefix: u64) -> Option<u64> {
    cur.thread_group.nt_wait_next.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
        .checked_add(prefix).filter(|token| *token != 0)
}

fn ensure_timer_queue(cur: &sched::Task, raw: u64) -> Option<u64> {
    if raw != 0 {
        let callbacks = cur.thread_group.nt_callbacks.lock();
        return callbacks.iter().any(|entry| entry.token == raw
            && matches!(entry.kind, sched::nt_callback::RegistrationKind::TimerQueue)).then_some(raw);
    }
    let mut callbacks = cur.thread_group.nt_callbacks.lock();
    if let Some(queue) = callbacks.iter().find(|entry|
        matches!(entry.kind, sched::nt_callback::RegistrationKind::TimerQueue)).map(|entry| entry.token) { return Some(queue); }
    let token = next_token(cur, 0x1000_0000_0000_0000)?;
    callbacks.push(sched::nt_callback::Registration { token, callback: 0, context: 0,
        kind: sched::nt_callback::RegistrationKind::TimerQueue });
    Some(token)
}

fn create_timer_queue(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(token) = next_token(&cur, 0x1000_0000_0000_0000) else { return STATUS_INVALID_PARAMETER; };
    cur.thread_group.nt_callbacks.lock().push(sched::nt_callback::Registration { token, callback: 0,
        context: 0, kind: sched::nt_callback::RegistrationKind::TimerQueue });
    if uaccess::put_user_u64(call.args.a0, token).is_err() {
        cur.thread_group.nt_callbacks.lock().retain(|entry| entry.token != token);
        return STATUS_INVALID_PARAMETER;
    }
    0
}

fn delete_timer_queue(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 == 0 { return STATUS_INVALID_HANDLE; }
    let mut callbacks = cur.thread_group.nt_callbacks.lock();
    let exists = callbacks.iter().any(|entry| entry.token == call.args.a0
        && matches!(entry.kind, sched::nt_callback::RegistrationKind::TimerQueue));
    if !exists { return STATUS_INVALID_HANDLE; }
    callbacks.retain(|entry| entry.token != call.args.a0
        && !matches!(entry.kind, sched::nt_callback::RegistrationKind::Timer { queue, .. } if queue == call.args.a0));
    if call.args.a1 != 0 && call.args.a1 != u64::MAX {
        let event = sched::nt_object::NtHandle::from_raw(call.args.a1 as u32);
        if let Some(object) = cur.thread_group.nt_handles().get(event, SYNCHRONIZE_ACCESS) {
            if let Some(event) = object.event() { event.set(); }
        }
    }
    0
}

fn update_timer(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a1 == 0
        || call.args.a2 > u32::MAX as u64 || call.args.a3 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let mut callbacks = cur.thread_group.nt_callbacks.lock();
    let Some(entry) = callbacks.iter_mut().find(|entry| entry.token == call.args.a1) else { return STATUS_INVALID_HANDLE; };
    let sched::nt_callback::RegistrationKind::Timer { queue, due_ms, period_ms, .. } = &mut entry.kind else { return STATUS_INVALID_HANDLE; };
    if *queue != call.args.a0 { return STATUS_INVALID_HANDLE; }
    *due_ms = call.args.a2 as u32; *period_ms = call.args.a3 as u32;
    0
}

fn register(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a1 == 0 || call.args.a2 == 0 { return STATUS_INVALID_PARAMETER; }
    if call.args.a1 > u32::MAX as u64 || call.args.a5 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let handle = sched::nt_object::NtHandle::from_raw(call.args.a1 as u32);
    let table = cur.thread_group.nt_handles();
    let Some(object) = table.get(handle, SYNCHRONIZE_ACCESS) else { return STATUS_INVALID_HANDLE; };
    if !matches!(object.kind(), sched::nt_object::NtObjectType::Event
        | sched::nt_object::NtObjectType::Semaphore | sched::nt_object::NtObjectType::Mutant
        | sched::nt_object::NtObjectType::Timer | sched::nt_object::NtObjectType::Process
        | sched::nt_object::NtObjectType::Thread) { return STATUS_INVALID_HANDLE; }
    if call.args.a5 as u32 & !WT_SUPPORTED != 0 { return STATUS_INVALID_PARAMETER; }
    let sequence = cur.thread_group.nt_wait_next.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let Some(token) = sequence.checked_add(0x8000_0000_0000_0000) else { return STATUS_INVALID_PARAMETER; };
    cur.thread_group.nt_callbacks.lock().push(sched::nt_callback::Registration {
        token, callback: call.args.a2, context: call.args.a3,
        kind: sched::nt_callback::RegistrationKind::Wait {
            object: call.args.a1, timeout_ms: call.args.a4 as u32, flags: call.args.a5 as u32,
        },
    });
    if uaccess::put_user_u64(call.args.a0, token).is_err() { let mut waits = cur.thread_group.nt_callbacks.lock(); waits.retain(|wait| wait.token != token); return STATUS_INVALID_PARAMETER; }
    if object.is_signaled_at(cur.tid as u64, timekeeper::monotonic_ns())
        && object.try_wait_at(cur.tid as u64, timekeeper::monotonic_ns()) {
        if cur.nt_apc_queue.push(sched::nt_apc::Apc { routine: call.args.a2,
            argument1: call.args.a3, argument2: 0, argument3: 0, flags: 0 }).is_err() {
            cur.thread_group.nt_callbacks.lock().retain(|wait| wait.token != token);
            return STATUS_INVALID_PARAMETER;
        }
        cur.nt_apc_queue.request_delivery();
    }
    0
}

fn allocate_callback(call: NtCall, timer: bool) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a1 == 0 { return STATUS_INVALID_PARAMETER; }
    if !uaccess::access_ok(call.args.a1, 1) { return STATUS_INVALID_PARAMETER; }
    let token = cur.thread_group.nt_wait_next.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
        .checked_add(if timer { 0x4000_0000_0000_0000 } else { 0x2000_0000_0000_0000 }).unwrap_or(0);
    if token == 0 { return STATUS_INVALID_PARAMETER; }
    // The process thread-group owns the opaque object until a corresponding
    // release operation exists. It is not a success-only pointer: callback
    // code/context are retained for the later wait/timer dispatch path.
    cur.thread_group.nt_callbacks.lock().push(sched::nt_callback::Registration {
        token, callback: call.args.a1, context: call.args.a2,
        kind: sched::nt_callback::RegistrationKind::Callback,
    });
    if uaccess::put_user_u64(call.args.a0, token).is_err() {
        cur.thread_group.nt_callbacks.lock().retain(|entry| entry.token != token);
        return STATUS_INVALID_PARAMETER;
    }
    0
}
