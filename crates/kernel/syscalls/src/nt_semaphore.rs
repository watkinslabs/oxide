//! Native NT semaphore adapters over the scheduler's counting primitive.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_OBJECT_NAME_COLLISION: u64 = 0xc000_0035;
const STATUS_OBJECT_TYPE_MISMATCH: u64 = 0xc000_0024;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
use crate::nt_access::{SEMAPHORE, SEMAPHORE_MODIFY_STATE};

/// Dispatch named/unnamed semaphore creation and release using the canonical
/// scheduler-backed count and wakeup protocol. # C: O(1)
pub fn dispatch(call: NtCall) -> Option<u64> {
    let object = match syscall::nt::decode_object(call) {
        Ok(object @ (NtObjectCall::CreateSemaphore { .. } | NtObjectCall::ReleaseSemaphore { .. })) => object,
        _ => return None,
    };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    Some(match object {
        NtObjectCall::CreateSemaphore { handle, desired_access, attributes, initial, maximum } => {
            if initial < 0 || maximum <= 0 || initial > maximum
                || maximum > u32::MAX as i64 { return Some(STATUS_INVALID_PARAMETER); }
            let Some(granted_access) = SEMAPHORE.grant(desired_access) else { return Some(STATUS_INVALID_PARAMETER); };
            if attributes != 0 {
                let Some(path) = crate::nt_directory::resolve_object_path(attributes, &table) else { return Some(STATUS_INVALID_PARAMETER); };
                let (object, state) = sched::nt_object::create_semaphore(&path, initial, maximum);
                if state == sched::nt_object::NamedObjectState::TypeMismatch { return Some(STATUS_OBJECT_TYPE_MISMATCH); }
                if state == sched::nt_object::NamedObjectState::ParentMissing { return Some(STATUS_OBJECT_NAME_NOT_FOUND); }
                let Some(native) = table.insert(object, granted_access) else { return Some(STATUS_NO_MEMORY); };
                if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() { let _ = table.close(native); return Some(STATUS_INVALID_PARAMETER); }
                return Some(if state == sched::nt_object::NamedObjectState::Existing { STATUS_OBJECT_NAME_COLLISION } else { STATUS_SUCCESS });
            }
            let object = table.new_semaphore(initial, maximum);
            let Some(native) = table.insert(object, granted_access) else { return Some(STATUS_NO_MEMORY); };
            if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() {
                let _ = table.close(native);
                STATUS_INVALID_PARAMETER
            } else { STATUS_SUCCESS }
        }
        NtObjectCall::ReleaseSemaphore { handle, count, previous } => {
            if count == 0 { return Some(STATUS_INVALID_PARAMETER); }
            let native = sched::nt_object::NtHandle::from_raw(handle);
            let Some(object) = table.get(native, SEMAPHORE_MODIFY_STATE) else {
                return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE });
            };
            if object.kind() != sched::nt_object::NtObjectType::Semaphore { return Some(STATUS_INVALID_HANDLE); }
            let Some(semaphore) = object.semaphore() else { return Some(STATUS_INVALID_HANDLE); };
            let Some(old) = semaphore.release(count) else { return Some(STATUS_INVALID_PARAMETER); };
            table.wake_waiters();
            if let Some(previous) = previous {
                if uaccess::put_user_u32(previous.as_u64(), old).is_err() { return Some(STATUS_INVALID_PARAMETER); }
            }
            STATUS_SUCCESS
        }
        _ => return None,
    })
}

