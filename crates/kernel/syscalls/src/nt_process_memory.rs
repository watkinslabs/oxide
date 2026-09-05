//! Native current-process virtual-memory copy for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

use crate::nt_process_memory_policy::{completion_status, copy_operands, destination_fault_status, write_destination_fault_status, write_source_fault_status};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
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
    let target = if call.args.a0 == CURRENT_PROCESS { None } else {
        if call.args.a0 > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
        let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
        let table = cur.thread_group.nt_handles();
        let Some(object) = table.get(handle, desired_access) else {
            return Some(if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE });
        };
        let Some(target) = object.task() else { return Some(STATUS_INVALID_HANDLE); };
        Some(target)
    };
    let same_process = target.as_ref().map_or(true, |task| alloc::sync::Arc::ptr_eq(&task.thread_group, &cur.thread_group));
    let (source, destination) = copy_operands(read, call.args.a1, call.args.a2);
    let copied = if same_process {
        if read {
            let destination_valid = if size == 0 { true } else { crate::userbuf::validate_user_buf_writable(destination, call.args.a3, 1).is_ok() };
            if let Some(status) = destination_fault_status(size, destination_valid) { return Some(status); }
        } else {
            let source_valid = if size == 0 { true } else { crate::userbuf::validate_user_buf_readable(source, call.args.a3, 1).is_ok() };
            if let Some(status) = write_source_fault_status(size, source_valid) { return Some(status); }
            let destination_valid = if size == 0 { true } else { crate::userbuf::validate_user_buf_writable(destination, call.args.a3, 1).is_ok() };
            if let Some(status) = write_destination_fault_status(size, destination_valid) { return Some(status); }
        }
        elf_load::nt_memory::copy_current_process(read, source, destination, size).copied
    } else {
        let Some(task) = target else { return Some(STATUS_INVALID_HANDLE); };
        let Some(mm) = task.clone_mm() else { return Some(STATUS_INVALID_HANDLE); };
        if read {
            let destination_valid = if size == 0 { true } else { crate::userbuf::validate_user_buf_writable(destination, call.args.a3, 1).is_ok() };
            if let Some(status) = destination_fault_status(size, destination_valid) { return Some(status); }
        } else {
            let source_valid = if size == 0 { true } else { crate::userbuf::validate_user_buf_readable(source, call.args.a3, 1).is_ok() };
            if let Some(status) = write_source_fault_status(size, source_valid) { return Some(status); }
        }
        copy_remote_process(read, &mm, source, destination, size)
    };
    if call.args.a4 != 0 && uaccess::put_user_u64(call.args.a4, copied as u64).is_err() {
        return Some(STATUS_ACCESS_VIOLATION);
    }
    Some(completion_status(size, copied))
}

fn copy_remote_process(read: bool, target: &vmm::AddressSpace, source: u64,
                       destination: u64, size: usize) -> usize {
    const PAGE: usize = hal::PAGE_SIZE_BYTES as usize;
    let mut copied = 0;
    let mut scratch = [0u8; PAGE];
    while copied < size {
        let Some(src) = source.checked_add(copied as u64) else { break; };
        let Some(dst) = destination.checked_add(copied as u64) else { break; };
        let count = (size - copied).min(PAGE);
        let remote = if read { src } else { dst };
        let Some(page) = hal::UserVirtAddr::new(remote & !(PAGE as u64 - 1)) else { break; };
        let Some(vma) = target.find_vma(page) else { break; };
        let allowed = if read { vma.prot.contains(vmm::VmaProt::READ) || vma.prot.contains(vmm::VmaProt::EXEC) }
            else { vma.prot.contains(vmm::VmaProt::WRITE) };
        if !allowed { break; }
        let access = if read && !vma.prot.contains(vmm::VmaProt::READ) { vmm::FaultAccess::Exec }
            else if read { vmm::FaultAccess::Read } else { vmm::FaultAccess::Write };
        if pmm::user_as::prefault_user_range_with_access(target, remote & !(PAGE as u64 - 1), count as u64, access).is_err() { break; }
        let n = if read {
            let n = unsafe { pmm::user_as::read_foreign_user(target.root_pa(), src, &mut scratch[..count]) };
            if n != 0 && uaccess::copy_to_user(dst, &scratch[..n]).is_err() { break; }
            n
        } else {
            if uaccess::copy_from_user(&mut scratch[..count], src).is_err() { break; }
            unsafe { pmm::user_as::write_foreign_user(target.root_pa(), dst, &scratch[..count]) }
        };
        if n == 0 { break; }
        copied += n;
        if n != count { break; }
    }
    copied
}
