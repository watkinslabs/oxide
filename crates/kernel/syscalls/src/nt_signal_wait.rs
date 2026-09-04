//! Native NT signal-and-wait operation.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_TIMEOUT: u64 = 0x0000_0102;
const STATUS_ALERTED: u64 = 0x0000_0101;
const STATUS_USER_APC: u64 = 0x0000_00c0;
const STATUS_OBJECT_TYPE_MISMATCH: u64 = 0xc000_0024;
const STATUS_MUTANT_NOT_OWNED: u64 = 0xc000_0046;
const STATUS_SEMAPHORE_LIMIT_EXCEEDED: u64 = 0xc000_0047;
const EVENT_MODIFY_STATE: u32 = 2;
const SEMAPHORE_MODIFY_STATE: u32 = 2;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

pub fn dispatch(call: NtCall) -> Option<u64> {
    let Ok(NtObjectCall::SignalAndWait { signal, wait, alertable, timeout }) = syscall::nt::decode_object(call) else { return None; };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || alertable > 1 { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    let signal = sched::nt_object::NtHandle::from_raw(signal);
    let Some(signal_object) = table.get(signal, 0) else { return Some(STATUS_INVALID_HANDLE); };
    let signal_access = match signal_object.kind() {
        sched::nt_object::NtObjectType::Event => EVENT_MODIFY_STATE,
        sched::nt_object::NtObjectType::Semaphore => SEMAPHORE_MODIFY_STATE,
        sched::nt_object::NtObjectType::Mutant => SYNCHRONIZE_ACCESS,
        _ => return Some(STATUS_OBJECT_TYPE_MISMATCH),
    };
    if table.access(signal).unwrap_or(0) & signal_access != signal_access { return Some(STATUS_ACCESS_DENIED); }
    let wait = sched::nt_object::NtHandle::from_raw(wait);
    let Some(wait_object) = table.get(wait, 0) else { return Some(STATUS_INVALID_HANDLE); };
    if table.access(wait).unwrap_or(0) & SYNCHRONIZE_ACCESS != SYNCHRONIZE_ACCESS { return Some(STATUS_ACCESS_DENIED); }
    if !matches!(wait_object.kind(), sched::nt_object::NtObjectType::Event | sched::nt_object::NtObjectType::Semaphore | sched::nt_object::NtObjectType::Mutant | sched::nt_object::NtObjectType::Timer) {
        return Some(STATUS_OBJECT_TYPE_MISMATCH);
    }
    let deadline = match crate::nt_dispatch::wait_deadline(timeout) { Ok(deadline) => deadline, Err(status) => return Some(status) };
    // Validate both handles and the timeout before changing the signal
    // object. The wait operand is fully admitted before signaling so an
    // invalid wait cannot produce a successful signal side effect.
    if let Err(error) = signal_object.signal_for_wait(cur.tid as u64) {
        return Some(match error {
            sched::nt_object::NtSignalError::Unsupported => STATUS_OBJECT_TYPE_MISMATCH,
            sched::nt_object::NtSignalError::LimitExceeded => STATUS_SEMAPHORE_LIMIT_EXCEEDED,
            sched::nt_object::NtSignalError::NotOwner => STATUS_MUTANT_NOT_OWNED,
        });
    }
    table.wake_waiters();
    let outcome = if let Some(event) = wait_object.event() {
        if alertable != 0 { unsafe { event.wait_alertable(deadline, timekeeper::monotonic_ns, || cur.nt_apc_queue.request_delivery()) }.into() }
        else { unsafe { event.wait(deadline, timekeeper::monotonic_ns) }.into() }
    } else if let Some(semaphore) = wait_object.semaphore() {
        if alertable != 0 { unsafe { semaphore.wait_alertable(deadline, timekeeper::monotonic_ns, || cur.nt_apc_queue.request_delivery()) } }
        else { unsafe { semaphore.wait(deadline, timekeeper::monotonic_ns).into() } }
    } else if let Some(mutant) = wait_object.mutant() {
        if alertable != 0 { unsafe { mutant.wait_alertable(cur.tid as u64, deadline, timekeeper::monotonic_ns, || cur.nt_apc_queue.request_delivery()) } }
        else { unsafe { mutant.wait(cur.tid as u64, deadline, timekeeper::monotonic_ns).into() } }
    } else if let Some(timer) = wait_object.timer() {
        if alertable != 0 { unsafe { timer.wait_alertable(deadline, timekeeper::monotonic_ns, || cur.nt_apc_queue.request_delivery()) } }
        else { unsafe { timer.wait(deadline, timekeeper::monotonic_ns).into() } }
    } else {
        return Some(STATUS_OBJECT_TYPE_MISMATCH);
    };
    Some(match outcome {
        sched::live::NtWaitOutcome::Ready => STATUS_SUCCESS,
        sched::live::NtWaitOutcome::TimedOut => STATUS_TIMEOUT,
        sched::live::NtWaitOutcome::UserApc => STATUS_USER_APC,
        sched::live::NtWaitOutcome::Interrupted => STATUS_ALERTED,
    })
}
