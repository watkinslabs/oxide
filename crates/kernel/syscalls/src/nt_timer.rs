//! Native NT timer object services.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const TIMER_MODIFY_STATE: u32 = 2;
const TIMER_ALL_ACCESS: u32 = 0x001f_0003;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;

/// Create, arm, or cancel a waitable native timer. Relative NT due times are
/// converted to the kernel monotonic clock; absolute system-time deadlines
/// are rejected until the NT wall-clock epoch is owned by this personality.
pub fn dispatch(call: NtCall) -> Option<u64> {
    let object = match syscall::nt::decode_object(call) {
        Ok(object @ (NtObjectCall::CreateTimer { .. } | NtObjectCall::SetTimer { .. } | NtObjectCall::CancelTimer { .. })) => object,
        _ => return None,
    };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    Some(match object {
        NtObjectCall::CreateTimer { handle, desired_access, timer_type } => {
            if desired_access & !TIMER_ALL_ACCESS != 0 || timer_type > 1 { return Some(STATUS_INVALID_PARAMETER); }
            let object = table.new_timer(timer_type == 0);
            let Some(native) = table.insert(object, desired_access) else { return Some(STATUS_NO_MEMORY); };
            if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() {
                let _ = table.close(native); STATUS_INVALID_PARAMETER
            } else { STATUS_SUCCESS }
        }
        NtObjectCall::SetTimer { handle, due_time, period_ms } => {
            if period_ms > 0x7fff_ffff || due_time > 0 { return Some(STATUS_INVALID_PARAMETER); }
            let native = sched::nt_object::NtHandle::from_raw(handle);
            let Some(object) = table.get(native, TIMER_MODIFY_STATE) else { return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            if object.kind() != sched::nt_object::NtObjectType::Timer { return Some(STATUS_INVALID_HANDLE); }
            let Some(timer) = object.timer() else { return Some(STATUS_INVALID_HANDLE); };
            let ticks = due_time.checked_neg().unwrap_or(0) as u64;
            let delay_ns = ticks.checked_mul(100).unwrap_or(u64::MAX);
            let due = timekeeper::monotonic_ns().saturating_add(delay_ns);
            timer.arm(due, (period_ms as u64).saturating_mul(1_000_000));
            table.wake_waiters(); STATUS_SUCCESS
        }
        NtObjectCall::CancelTimer { handle, previous } => {
            let native = sched::nt_object::NtHandle::from_raw(handle);
            let Some(object) = table.get(native, TIMER_MODIFY_STATE) else { return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            if object.kind() != sched::nt_object::NtObjectType::Timer { return Some(STATUS_INVALID_HANDLE); }
            let Some(timer) = object.timer() else { return Some(STATUS_INVALID_HANDLE); };
            let was_signaled = timer.cancel();
            if let Some(previous) = previous { if uaccess::put_user_u32(previous.as_u64(), was_signaled as u32).is_err() { return Some(STATUS_INVALID_PARAMETER); } }
            table.wake_waiters(); STATUS_SUCCESS
        }
        _ => return None,
    })
}
