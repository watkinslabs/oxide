//! Native NT process/thread handle acquisition for the current NT process.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_INVALID_CID: u64 = 0xc000_000b;
const STATUS_INVALID_INFO_CLASS: u64 = 0xc000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const PROCESS_ALL_ACCESS: u32 = 0x001f_0fff;
const THREAD_ALL_ACCESS: u32 = 0x001f_03ff;
const SYNCHRONIZE: u32 = 0x0010_0000;
const PROCESS_QUERY_INFORMATION: u32 = 0x0000_0400;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x0000_1000;
const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
const PROCESS_BASIC_INFORMATION_BYTES: usize = 48;

/// Open a task identity into the caller's process-local NT handle table.
/// Only identities in the current NT process are admitted until the native
/// process namespace gains a cross-process owner. # C: O(log N)
pub fn dispatch(call: NtCall) -> Option<u64> {
    let object = match syscall::nt::decode_object(call) {
        Ok(object @ (NtObjectCall::OpenProcess { .. } | NtObjectCall::OpenThread { .. })) => object,
        Ok(NtObjectCall::QueryProcess { process, class, info, length, return_length }) => {
            return query_process(process, class, info, length, return_length);
        }
        _ => return None,
    };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    let (handle, desired_access, attributes, client_id, thread) = match object {
        NtObjectCall::OpenProcess { handle, desired_access, attributes, client_id } =>
            (handle, desired_access, attributes, client_id, false),
        NtObjectCall::OpenThread { handle, desired_access, attributes, client_id } =>
            (handle, desired_access, attributes, client_id, true),
        _ => return None,
    };
    if desired_access & !(if thread { THREAD_ALL_ACCESS } else { PROCESS_ALL_ACCESS }) != 0
        || !valid_object_attributes(attributes) { return Some(STATUS_INVALID_PARAMETER); }
    let process_id = match uaccess::get_user_u64(client_id.as_u64()) { Ok(value) => value, Err(_) => return Some(STATUS_INVALID_PARAMETER) };
    let thread_id = match uaccess::get_user_u64(client_id.as_u64() + 8) { Ok(value) => value, Err(_) => return Some(STATUS_INVALID_PARAMETER) };
    let current_process = cur.tgid.load(core::sync::atomic::Ordering::Acquire) as u64;
    if thread {
        let current_thread = cur.tid as u64;
        if process_id != current_process || thread_id != current_thread { return Some(STATUS_INVALID_CID); }
    } else if process_id != current_process || thread_id != 0 { return Some(STATUS_INVALID_CID); }
    let Some(task) = sched::registry::lookup(if thread { cur.tid } else { cur.tgid.load(core::sync::atomic::Ordering::Acquire) }) else {
        return Some(STATUS_INVALID_CID);
    };
    let object = if thread { table.new_thread(task) } else { table.new_process(task) };
    let access = desired_access | SYNCHRONIZE;
    let Some(native) = table.insert(object, access) else { return Some(STATUS_NO_MEMORY); };
    if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() {
        let _ = table.close(native);
        return Some(STATUS_INVALID_PARAMETER);
    }
    Some(STATUS_SUCCESS)
}

fn query_process(process: u64, class: u32, info: syscall::UserPtr<u8>, length: u32,
    return_length: Option<syscall::UserPtr<u32>>) -> Option<u64> {
    if process == u64::MAX { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    if class != PROCESS_BASIC_INFORMATION_CLASS { return Some(STATUS_INVALID_INFO_CLASS); }
    if (length as usize) < PROCESS_BASIC_INFORMATION_BYTES { return Some(STATUS_INFO_LENGTH_MISMATCH); }
    let table = cur.thread_group.nt_handles();
    if process > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
    let handle = sched::nt_object::NtHandle::from_raw(process as u32);
    let Some(object) = table.get(handle, PROCESS_QUERY_LIMITED_INFORMATION)
        .or_else(|| table.get(handle, PROCESS_QUERY_INFORMATION)) else {
        return Some(if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE });
    };
    if object.kind() != sched::nt_object::NtObjectType::Process { return Some(STATUS_INVALID_HANDLE); }
    let Some(target) = object.task() else { return Some(STATUS_INVALID_HANDLE); };
    let mut out = [0u8; PROCESS_BASIC_INFORMATION_BYTES];
    out[8..16].copy_from_slice(&target.nt_peb().to_ne_bytes());
    out[32..40].copy_from_slice(&(target.tgid.load(core::sync::atomic::Ordering::Acquire) as u64).to_ne_bytes());
    out[40..48].copy_from_slice(&(target.parent_tid.load(core::sync::atomic::Ordering::Acquire) as u64).to_ne_bytes());
    if uaccess::copy_to_user(info.as_u64(), &out).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    if let Some(return_length) = return_length {
        if uaccess::put_user_u32(return_length.as_u64(), PROCESS_BASIC_INFORMATION_BYTES as u32).is_err() {
            return Some(STATUS_INVALID_PARAMETER);
        }
    }
    Some(STATUS_SUCCESS)
}

fn valid_object_attributes(attributes: Option<syscall::UserPtr<u8>>) -> bool {
    let Some(attributes) = attributes else { return true; };
    let address = attributes.as_u64();
    let Ok(length) = uaccess::get_user_u32(address) else { return false; };
    length >= 48 && uaccess::get_user_u64(address + 8).ok() == Some(0)
        && uaccess::get_user_u64(address + 16).ok() == Some(0)
}
