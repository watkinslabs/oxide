//! Native current-process virtual-memory copy for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

use crate::nt_process_memory_policy::{completion_status, destination_fault_status};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const CURRENT_PROCESS: u64 = u64::MAX;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_VM_WRITE: u32 = 0x0020;

/// Copy memory within the current NT address space using the canonical
/// user-access fault boundary; remote address-space ownership remains explicit.
/// # C: O(size / page)
pub fn dispatch(call: NtCall) -> Option<u64> {
    let read = match call.service {
        NtService::NtReadVirtualMemory => true,
        NtService::NtWriteVirtualMemory => false,
        _ => return None,
    };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let desired_access = if read { PROCESS_VM_READ } else { PROCESS_VM_OPERATION | PROCESS_VM_WRITE };
    let size = match usize::try_from(call.args.a3) { Ok(size) => size, Err(_) => return Some(STATUS_INVALID_PARAMETER) };
    let destination_valid = if size == 0 { true } else {
        crate::userbuf::validate_user_buf_writable(call.args.a2, call.args.a3, 1).is_ok()
    };
    if let Some(status) = destination_fault_status(size, destination_valid) { return Some(status); }
    let same_process = if call.args.a0 == CURRENT_PROCESS { true } else {
        if call.args.a0 > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
        let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
        let table = cur.thread_group.nt_handles();
        let Some(object) = table.get(handle, desired_access) else {
            return Some(if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE });
        };
        let Some(target) = object.task() else { return Some(STATUS_INVALID_HANDLE); };
        alloc::sync::Arc::ptr_eq(&target.thread_group, &cur.thread_group)
    };
    if !same_process { return Some(STATUS_NOT_IMPLEMENTED); }
    let copied = elf_load::nt_memory::copy_current_process(read, call.args.a1, call.args.a2, size).copied;
    if call.args.a4 != 0 && uaccess::put_user_u64(call.args.a4, copied as u64).is_err() {
        return Some(STATUS_ACCESS_VIOLATION);
    }
    Some(completion_status(size, copied))
}
