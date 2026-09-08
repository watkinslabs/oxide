//! Native NT timer object services.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
/// A timer armed with the resume flag succeeds; the flag itself is reported
/// as ignored rather than refused.
const STATUS_TIMER_RESUME_IGNORED: u64 = 0x4000_0025;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_OBJECT_NAME_COLLISION: u64 = 0xc000_0035;
const STATUS_OBJECT_TYPE_MISMATCH: u64 = 0xc000_0024;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
use crate::nt_access::{TIMER, TIMER_MODIFY_STATE};
const NT_EPOCH_OFFSET_NS: u64 = 11_644_473_600_000_000_000;

/// Create, arm, or cancel a waitable native timer. Relative NT due times are
/// converted to the kernel monotonic clock; absolute system-time deadlines
/// use the shared NT wall-clock conversion owned by the timekeeper.
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::SetTimer { return Some(set_timer(call)); }
    let object = match syscall::nt::decode_object(call) {
        Ok(object @ (NtObjectCall::CreateTimer { .. } | NtObjectCall::CancelTimer { .. })) => object,
        _ => return None,
    };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    Some(match object {
        NtObjectCall::CreateTimer { handle, desired_access, attributes, timer_type } => {
            if timer_type > 1 { return Some(STATUS_INVALID_PARAMETER); }
            let Some(granted_access) = TIMER.grant(desired_access) else { return Some(STATUS_INVALID_PARAMETER); };
            let object = table.new_timer(timer_type == 0);
            if attributes != 0 {
                let Some(path) = crate::nt_directory::resolve_object_path(attributes, &table) else { return Some(STATUS_INVALID_PARAMETER); };
                let (object, state) = sched::nt_object::publish_timer(&path, object);
                if state == sched::nt_object::NamedObjectState::TypeMismatch { return Some(STATUS_OBJECT_TYPE_MISMATCH); }
                if state == sched::nt_object::NamedObjectState::ParentMissing { return Some(STATUS_OBJECT_NAME_NOT_FOUND); }
                let Some(native) = table.insert(object, granted_access) else { return Some(STATUS_NO_MEMORY); };
                if uaccess::put_user_u64(handle.as_u64(), u64::from(native.raw())).is_err() { let _ = table.close(native); return Some(STATUS_INVALID_PARAMETER); }
                return Some(if state == sched::nt_object::NamedObjectState::Existing { STATUS_OBJECT_NAME_COLLISION } else { STATUS_SUCCESS });
            }
            let Some(native) = table.insert(object, granted_access) else { return Some(STATUS_NO_MEMORY); };
            if uaccess::put_user_u64(handle.as_u64(), u64::from(native.raw())).is_err() {
                let _ = table.close(native); STATUS_INVALID_PARAMETER
            } else { STATUS_SUCCESS }
        }
        NtObjectCall::CancelTimer { handle, previous } => {
            let native = sched::nt_object::NtHandle::from_raw(handle);
            let Some(object) = table.get(native, TIMER_MODIFY_STATE) else { return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            if object.kind() != sched::nt_object::NtObjectType::Timer { return Some(STATUS_INVALID_HANDLE); }
            let Some(timer) = object.timer() else { return Some(STATUS_INVALID_HANDLE); };
            let was_signaled = timer.cancel();
            // The previous state is one `BOOLEAN` byte; a four-byte store
            // would write three bytes the caller never gave this service.
            if let Some(previous) = previous { if uaccess::copy_to_user(previous.as_u64(), &[was_signaled as u8]).is_err() { return Some(STATUS_ACCESS_VIOLATION); } }
            table.wake_waiters(); STATUS_SUCCESS
        }
        _ => return None,
    })
}

pub(crate) fn timer_deadline(due_time: i64) -> Option<u64> {
    if due_time <= 0 {
        let ticks = (-(due_time as i128)) as u128;
        let delta = ticks.checked_mul(100)?;
        return Some(timekeeper::monotonic_ns().saturating_add(u64::try_from(delta).ok()?));
    }
    let target = (due_time as u64).checked_mul(100)?.checked_sub(NT_EPOCH_OFFSET_NS)?;
    let now = timekeeper::realtime_ns();
    Some(if target <= now { timekeeper::monotonic_ns() } else {
        timekeeper::monotonic_ns().saturating_add(target - now)
    })
}

/// Arm one waitable timer from the seven-argument service shape: the due time
/// is a pointer to a signed hundred-nanosecond count, the period a `ULONG` of
/// milliseconds in a frame word, and the previous-state output an optional
/// one-byte `BOOLEAN` pointer. Reading the due time or the period from a
/// neighbouring argument armed the timer at an unrelated deadline.
/// # C: O(1) plus two user accesses
fn set_timer(call: NtCall) -> u64 {
    let Some(state) = crate::nt_dispatch::stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
    let request = crate::nt_obj_sig::set_timer([call.args.a0, call.args.a1, call.args.a2,
        call.args.a3, call.args.a4, call.args.a5, state]);
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    if request.when == 0 { return STATUS_ACCESS_VIOLATION; }
    // An APC on expiry needs a timer-APC owner; claiming success for a
    // callback that will never run is the refusal this must not become.
    if request.callback != 0 { return STATUS_NOT_IMPLEMENTED; }
    let Ok(due_time) = uaccess::get_user_u64(request.when) else { return STATUS_ACCESS_VIOLATION; };
    let table = cur.thread_group.nt_handles();
    let native = sched::nt_object::NtHandle::from_raw(request.handle);
    let Some(object) = table.get(native, TIMER_MODIFY_STATE) else { return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
    if object.kind() != sched::nt_object::NtObjectType::Timer { return STATUS_INVALID_HANDLE; }
    let Some(timer) = object.timer() else { return STATUS_INVALID_HANDLE; };
    let Some(due) = timer_deadline(due_time as i64) else { return STATUS_INVALID_PARAMETER; };
    let Some(period_ns) = (request.period as u64).checked_mul(1_000_000) else { return STATUS_INVALID_PARAMETER; };
    let signaled = timer.is_signaled_at(timekeeper::monotonic_ns());
    timer.arm(due, period_ns);
    table.wake_waiters();
    if request.state != 0 && uaccess::copy_to_user(request.state, &[signaled as u8]).is_err() { return STATUS_ACCESS_VIOLATION; }
    if request.resume { STATUS_TIMER_RESUME_IGNORED } else { STATUS_SUCCESS }
}
