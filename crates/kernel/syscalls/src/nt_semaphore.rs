//! Native NT semaphore adapters over the scheduler's counting primitive.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const SEMAPHORE_MODIFY_STATE: u32 = 2;
const SEMAPHORE_ALL_ACCESS: u32 = 0x001f_0003;

/// Dispatch unnamed semaphore creation and release using the canonical
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
            if attributes != 0 || desired_access & !SEMAPHORE_ALL_ACCESS != 0
                || initial < 0 || maximum <= 0 || initial > maximum
                || maximum > u32::MAX as i64 { return Some(STATUS_INVALID_PARAMETER); }
            let object = table.new_semaphore(initial, maximum);
            let Some(native) = table.insert(object, desired_access) else { return Some(STATUS_NO_MEMORY); };
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
            if let Some(previous) = previous {
                if uaccess::put_user_u32(previous.as_u64(), old).is_err() { return Some(STATUS_INVALID_PARAMETER); }
            }
            STATUS_SUCCESS
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn access_masks_match_native_semaphore_contract() {
        assert_eq!(super::SEMAPHORE_MODIFY_STATE, 2);
        assert_eq!(super::SEMAPHORE_ALL_ACCESS, 0x001f_0003);
    }
}
