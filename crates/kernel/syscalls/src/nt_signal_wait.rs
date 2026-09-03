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
const EVENT_MODIFY_STATE: u32 = 2;
const SYNCHRONIZE: u32 = 0x0010_0000;

pub fn dispatch(call: NtCall) -> Option<u64> {
    let Ok(NtObjectCall::SignalAndWait { signal, wait, alertable, timeout }) = syscall::nt::decode_object(call) else { return None; };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || alertable > 1 { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    let signal = sched::nt_object::NtHandle::from_raw(signal);
    let Some(signal_object) = table.get(signal, EVENT_MODIFY_STATE) else { return Some(if table.contains(signal) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
    let Some(event) = signal_object.event() else { return Some(STATUS_INVALID_HANDLE); };
    let wait = sched::nt_object::NtHandle::from_raw(wait);
    let Some(wait_object) = table.get(wait, SYNCHRONIZE) else { return Some(if table.contains(wait) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
    let deadline = match crate::nt_dispatch::wait_deadline(timeout) { Ok(deadline) => deadline, Err(status) => return Some(status) };
    // Validate both handles and the timeout before changing the signal
    // object. Wine's server queues the wait first, then signals atomically;
    // an invalid wait handle must not turn into a successful signal side
    // effect.
    event.set(); table.wake_waiters();
    let outcome = if let Some(event) = wait_object.event() {
        // SAFETY: the object Arc keeps the event alive across the scheduler wait.
        unsafe { event.wait(deadline, timekeeper::monotonic_ns) }
    } else if let Some(semaphore) = wait_object.semaphore() {
        unsafe { semaphore.wait(deadline, timekeeper::monotonic_ns) }
    } else if let Some(mutant) = wait_object.mutant() {
        unsafe { mutant.wait(cur.tid as u64, deadline, timekeeper::monotonic_ns) }
    } else if let Some(timer) = wait_object.timer() {
        unsafe { timer.wait(deadline, timekeeper::monotonic_ns) }
    } else { return Some(STATUS_INVALID_HANDLE); };
    Some(match outcome {
        sched::WaitOutcome::Ready => STATUS_SUCCESS,
        sched::WaitOutcome::TimedOut => STATUS_TIMEOUT,
        sched::WaitOutcome::Interrupted => if alertable != 0 { STATUS_USER_APC } else { STATUS_ALERTED },
    })
}
