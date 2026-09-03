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
const STATUS_OBJECT_NAME_COLLISION: u64 = 0xc000_0035;
const STATUS_OBJECT_TYPE_MISMATCH: u64 = 0xc000_0024;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const TIMER_ALLOWED_ACCESS: u32 = TIMER_ALL_ACCESS | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
const NT_EPOCH_OFFSET_NS: u64 = 11_644_473_600_000_000_000;

/// Create, arm, or cancel a waitable native timer. Relative NT due times are
/// converted to the kernel monotonic clock; absolute system-time deadlines
/// use the shared NT wall-clock conversion owned by the timekeeper.
pub fn dispatch(call: NtCall) -> Option<u64> {
    let object = match syscall::nt::decode_object(call) {
        Ok(object @ (NtObjectCall::CreateTimer { .. } | NtObjectCall::SetTimer { .. } | NtObjectCall::CancelTimer { .. })) => object,
        _ => return None,
    };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    Some(match object {
        NtObjectCall::CreateTimer { handle, desired_access, attributes, timer_type } => {
            if desired_access & !TIMER_ALLOWED_ACCESS != 0 || timer_type > 1 { return Some(STATUS_INVALID_PARAMETER); }
            let granted_access = if desired_access & GENERIC_ALL != 0 { desired_access | TIMER_ALL_ACCESS } else { desired_access };
            let object = table.new_timer(timer_type == 0);
            if attributes != 0 {
                let Some(path) = crate::nt_directory::resolve_object_path(attributes, &table) else { return Some(STATUS_INVALID_PARAMETER); };
                let (object, state) = sched::nt_object::publish_timer(&path, object);
                if state == sched::nt_object::NamedObjectState::TypeMismatch { return Some(STATUS_OBJECT_TYPE_MISMATCH); }
                if state == sched::nt_object::NamedObjectState::ParentMissing { return Some(STATUS_OBJECT_NAME_NOT_FOUND); }
                let Some(native) = table.insert(object, granted_access) else { return Some(STATUS_NO_MEMORY); };
                if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() { let _ = table.close(native); return Some(STATUS_INVALID_PARAMETER); }
                return Some(if state == sched::nt_object::NamedObjectState::Existing { STATUS_OBJECT_NAME_COLLISION } else { STATUS_SUCCESS });
            }
            let Some(native) = table.insert(object, granted_access) else { return Some(STATUS_NO_MEMORY); };
            if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() {
                let _ = table.close(native); STATUS_INVALID_PARAMETER
            } else { STATUS_SUCCESS }
        }
        NtObjectCall::SetTimer { handle, due_time, period_ms } => {
            if period_ms > 0x7fff_ffff { return Some(STATUS_INVALID_PARAMETER); }
            let native = sched::nt_object::NtHandle::from_raw(handle);
            let Some(object) = table.get(native, TIMER_MODIFY_STATE) else { return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            if object.kind() != sched::nt_object::NtObjectType::Timer { return Some(STATUS_INVALID_HANDLE); }
            let Some(timer) = object.timer() else { return Some(STATUS_INVALID_HANDLE); };
            let Some(due) = timer_deadline(due_time) else { return Some(STATUS_INVALID_PARAMETER); };
            let Some(period_ns) = (period_ms as u64).checked_mul(1_000_000) else { return Some(STATUS_INVALID_PARAMETER); };
            timer.arm(due, period_ns);
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

fn timer_deadline(due_time: i64) -> Option<u64> {
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
