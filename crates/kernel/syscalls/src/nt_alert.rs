//! Alert-by-thread-id services over the per-thread alert flag.
//!
//! The three services share one primitive: a single auto-reset flag per
//! thread. A wait that is satisfied by the flag reports the alerted status
//! rather than plain success, which is what lets the Win32 address-wait
//! primitives distinguish a wake from an expiry. A thread id that names no
//! live thread of this personality is a client-id error, not an access error.

use syscall::nt::NtCall;
#[cfg(target_os = "oxide-kernel")]
use syscall::nt::NtService;

/// Status codes this boundary produces.
pub const STATUS_SUCCESS: u64 = 0x0000_0000;
pub const STATUS_ALERTED: u64 = 0x0000_0101;
pub const STATUS_TIMEOUT: u64 = 0x0000_0102;
pub const STATUS_INVALID_CID: u64 = 0xc000_000b;
pub const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
pub const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
/// Ids one multiple-alert array may carry. The array is read whole before any
/// flag is raised, so a bound is required for the read itself.
pub const MAX_ALERT_IDS: u64 = 4096;

/// Status a completed alert wait reports. An alert outranks an expiry that
/// lands in the same wakeup, because the flag has already been consumed by
/// the time the outcome is examined.
/// # C: O(1)
pub fn wait_status(outcome: sched::WaitOutcome) -> u64 {
    match outcome {
        sched::WaitOutcome::Ready => STATUS_ALERTED,
        sched::WaitOutcome::TimedOut => STATUS_TIMEOUT,
        sched::WaitOutcome::Interrupted => STATUS_ALERTED,
    }
}

/// Whether one raw thread-id argument can name a thread at all. The value is
/// carried as a handle-width word but is a client id: anything wider than the
/// id space names no thread.
/// # C: O(1)
pub fn plausible_thread_id(raw: u64) -> bool { raw != 0 && raw <= u32::MAX as u64 }

/// Dispatch the three alert-by-thread-id services. # C: O(1) plus the wait
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::NtAlertThreadByThreadId => Some(alert_one(call.args.a0)),
        NtService::NtAlertMultipleThreadByThreadId => Some(alert_many(call.args.a0, call.args.a1)),
        NtService::NtWaitForAlertByThreadId => Some(wait_for_alert(call.args.a1)),
        _ => None,
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn dispatch(_call: NtCall) -> Option<u64> { None }

/// The task one thread-id argument names, when it is an NT thread. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn alert_target(raw: u64) -> Option<alloc::sync::Arc<sched::Task>> {
    if !plausible_thread_id(raw) { return None; }
    let task = sched::registry::lookup(raw as u32)?;
    if !task.is_nt_personality() { return None; }
    Some(task)
}

#[cfg(target_os = "oxide-kernel")]
fn alert_one(raw: u64) -> u64 {
    let Some(task) = alert_target(raw) else { return STATUS_INVALID_CID; };
    task.nt_alert.alert();
    STATUS_SUCCESS
}

/// Every id is admitted before any flag is raised, so a bad id in the array
/// leaves no thread alerted at all.
#[cfg(target_os = "oxide-kernel")]
fn alert_many(array: u64, count: u64) -> u64 {
    if count == 0 { return STATUS_SUCCESS; }
    if count > MAX_ALERT_IDS { return STATUS_INVALID_PARAMETER; }
    if array == 0 { return STATUS_ACCESS_VIOLATION; }
    let mut targets = alloc::vec::Vec::new();
    if targets.try_reserve_exact(count as usize).is_err() { return STATUS_INVALID_PARAMETER; }
    for index in 0..count {
        let Some(slot) = array.checked_add(index.saturating_mul(8)) else { return STATUS_ACCESS_VIOLATION; };
        let Ok(raw) = uaccess::get_user_u64(slot) else { return STATUS_ACCESS_VIOLATION; };
        let Some(task) = alert_target(raw) else { return STATUS_INVALID_CID; };
        targets.push(task);
    }
    for task in targets { task.nt_alert.alert(); }
    STATUS_SUCCESS
}

/// The address argument is not consulted: the flag is a thread property, and
/// the caller's own queue bookkeeping is what associates it with an address.
#[cfg(target_os = "oxide-kernel")]
fn wait_for_alert(timeout: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let pointer = if timeout == 0 { None } else {
        match syscall::UserPtr::<i64>::new(timeout) { Ok(pointer) => Some(pointer), Err(_) => return STATUS_ACCESS_VIOLATION }
    };
    let deadline = match crate::nt_dispatch::wait_deadline(pointer) {
        Ok(deadline) => deadline,
        Err(status) => return status,
    };
    // SAFETY: process context on the current task's own alert flag, holding
    // no lock that an alerting thread must acquire to wake it.
    wait_status(unsafe { cur.nt_alert.wait(deadline, timekeeper::monotonic_ns) })
}

#[cfg(test)]
#[path = "nt_alert/tests.rs"]
mod tests;
