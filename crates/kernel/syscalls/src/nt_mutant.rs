//! Native NT mutant adapters; unnamed mutants provide Wine mutex semantics.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_INVALID_INFO_CLASS: u64 = 0xc000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;
const MUTANT_ALL_ACCESS: u32 = 0x001f_0001;
const MUTANT_MODIFY_STATE: u32 = 1;

/// Dispatch unnamed mutant creation and release; wait ownership remains in the
/// canonical scheduler-backed object and is shared with wait-any/wait-all.
/// # C: O(1)
pub fn dispatch(call: NtCall) -> Option<u64> {
    let object = match syscall::nt::decode_object(call) {
        Ok(object @ (NtObjectCall::CreateMutant { .. } | NtObjectCall::ReleaseMutant { .. } | NtObjectCall::QueryMutant { .. })) => object,
        _ => return None,
    };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    Some(match object {
        NtObjectCall::CreateMutant { handle, desired_access, attributes, initial_owner } => {
            if attributes != 0 || initial_owner > 1 || desired_access & !MUTANT_ALL_ACCESS != 0 { return Some(STATUS_INVALID_PARAMETER); }
            let owner = if initial_owner != 0 { Some(cur.tid as u64) } else { None };
            let object = table.new_mutant(owner);
            let Some(native) = table.insert(object, desired_access) else { return Some(STATUS_NO_MEMORY); };
            if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() {
                let _ = table.close(native); STATUS_INVALID_PARAMETER
            } else { STATUS_SUCCESS }
        }
        NtObjectCall::ReleaseMutant { handle, previous } => {
            let native = sched::nt_object::NtHandle::from_raw(handle);
            let Some(object) = table.get(native, MUTANT_MODIFY_STATE) else {
                return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE });
            };
            if object.kind() != sched::nt_object::NtObjectType::Mutant { return Some(STATUS_INVALID_HANDLE); }
            let Some(mutant) = object.mutant() else { return Some(STATUS_INVALID_HANDLE); };
            let Ok(old) = mutant.release(cur.tid as u64) else { return Some(STATUS_ACCESS_DENIED); };
            if let Some(previous) = previous {
                if uaccess::put_user_u32(previous.as_u64(), old as u32).is_err() { return Some(STATUS_INVALID_PARAMETER); }
            }
            STATUS_SUCCESS
        }
        NtObjectCall::QueryMutant { handle, class, info, length, return_length } => {
            if class != 0 { return Some(STATUS_INVALID_INFO_CLASS); }
            if length != 8 { return Some(STATUS_INFO_LENGTH_MISMATCH); }
            let native = sched::nt_object::NtHandle::from_raw(handle);
            let Some(object) = table.get(native, MUTANT_MODIFY_STATE) else {
                return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE });
            };
            if object.kind() != sched::nt_object::NtObjectType::Mutant { return Some(STATUS_INVALID_HANDLE); }
            let Some(mutant) = object.mutant() else { return Some(STATUS_INVALID_HANDLE); };
            let (count, owned, abandoned) = mutant.basic_info(cur.tid as u64);
            let mut bytes = [0u8; 8]; bytes[..4].copy_from_slice(&count.to_ne_bytes()); bytes[4] = owned as u8; bytes[5] = abandoned as u8;
            if uaccess::copy_to_user(info.as_u64(), &bytes).is_err() { return Some(STATUS_INVALID_PARAMETER); }
            if let Some(return_length) = return_length { if uaccess::put_user_u32(return_length.as_u64(), 8).is_err() { return Some(STATUS_INVALID_PARAMETER); } }
            STATUS_SUCCESS
        }
        _ => return None,
    })
}
