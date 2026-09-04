//! Native NT handle duplication over the process-local object table.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const DUPLICATE_CLOSE_SOURCE: u32 = 1;
const DUPLICATE_SAME_ACCESS: u32 = 2;
const CURRENT_PROCESS: u64 = u64::MAX;

/// Duplicate one process-local NT handle after validating the complete
/// request. The target is an output pointer in the copied request record.
pub fn dispatch(call: NtCall) -> Option<u64> {
    let Ok(NtObjectCall::DuplicateObject { request }) = syscall::nt::decode_object(call) else { return None; };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let base = request.as_u64();
    let Some(source_process) = read_u64(base) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(source) = read_u32_at(base, 8) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(target_process) = read_u64_at(base, 16) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(target) = read_u64_at(base, 24) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(desired_access) = read_u32_at(base, 32) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(attributes) = read_u32_at(base, 36) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(options) = read_u32_at(base, 40) else { return Some(STATUS_INVALID_PARAMETER); };
    if source_process != CURRENT_PROCESS || target_process != CURRENT_PROCESS || target == 0
        || attributes != 0 || options & !(DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS) != 0 {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let table = cur.thread_group.nt_handles();
    let source_handle = sched::nt_object::NtHandle::from_raw(source);
    let Some(granted) = table.access(source_handle) else { return Some(STATUS_INVALID_HANDLE); };
    let access = if options & DUPLICATE_SAME_ACCESS != 0 { granted } else {
        if desired_access & !granted != 0 { return Some(STATUS_ACCESS_DENIED); }
        desired_access
    };
    let Some(duplicate) = table.duplicate(source_handle, access) else { return Some(STATUS_INVALID_HANDLE); };
    if uaccess::put_user_u32(target, duplicate.raw()).is_err() {
        let _ = table.close(duplicate);
        return Some(STATUS_INVALID_PARAMETER);
    }
    if options & DUPLICATE_CLOSE_SOURCE != 0 { let _ = table.close_duplicate_source(source_handle); }
    Some(STATUS_SUCCESS)
}

fn read_u32(address: u64) -> Option<u32> { uaccess::get_user_u32(address).ok() }
fn read_u64(address: u64) -> Option<u64> { uaccess::get_user_u64(address).ok() }
fn read_u32_at(address: u64, offset: u64) -> Option<u32> { read_u32(address.checked_add(offset)?) }
fn read_u64_at(address: u64, offset: u64) -> Option<u64> { read_u64(address.checked_add(offset)?) }
