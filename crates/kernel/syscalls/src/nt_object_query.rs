//! Native object metadata query for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_INVALID_INFO_CLASS: u64 = 0xc000_0003;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;
const OBJECT_BASIC_INFORMATION: u32 = 0;
const OBJECT_BASIC_INFORMATION_BYTES: usize = 56;
const OBJECT_NAME_INFORMATION: u32 = 1;
const OBJECT_TYPE_INFORMATION: u32 = 2;
const OBJECT_NAME_HEADER_BYTES: usize = 16;
const OBJECT_TYPE_HEADER_BYTES: usize = 104;

/// Return the handle's granted access in the x64 object-basic layout.
/// # C: O(1) plus usercopy
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::QueryObject { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let return_length = call.args.a4;
    if return_length != 0 && uaccess::put_user_u32(return_length, 0).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let Some(object) = table.get(handle, 0) else { return Some(STATUS_INVALID_HANDLE); };
    match call.args.a1 as u32 {
        OBJECT_BASIC_INFORMATION => {
            let Some((access, handle_count)) = table.access_and_handle_count(handle) else { return Some(STATUS_INVALID_HANDLE); };
            if return_length != 0 && uaccess::put_user_u32(return_length, OBJECT_BASIC_INFORMATION_BYTES as u32).is_err() { return Some(STATUS_INVALID_PARAMETER); }
            if (call.args.a3 as usize) < OBJECT_BASIC_INFORMATION_BYTES { return Some(STATUS_INFO_LENGTH_MISMATCH); }
            if call.args.a2 == 0 { return Some(STATUS_INVALID_PARAMETER); }
            let mut output = [0u8; OBJECT_BASIC_INFORMATION_BYTES];
            output[4..8].copy_from_slice(&access.to_le_bytes());
            output[8..12].copy_from_slice(&handle_count.to_le_bytes());
            if uaccess::copy_to_user(call.args.a2, &output).is_err() { return Some(STATUS_INVALID_PARAMETER); }
            Some(STATUS_SUCCESS)
        }
        OBJECT_NAME_INFORMATION => query_name(&object, call.args.a2, call.args.a3 as usize, return_length),
        OBJECT_TYPE_INFORMATION => query_type(object.kind(), call.args.a2, call.args.a3 as usize, return_length),
        _ => Some(STATUS_INVALID_INFO_CLASS),
    }
}

fn query_name(object: &sched::nt_object::NtObject, output: u64, length: usize, return_length: u64) -> Option<u64> {
    let name = sched::nt_object::object_name(object).unwrap_or_default();
    if name.is_empty() {
        if return_length != 0 && uaccess::put_user_u32(return_length, OBJECT_NAME_HEADER_BYTES as u32).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        if length < OBJECT_NAME_HEADER_BYTES { return Some(STATUS_INFO_LENGTH_MISMATCH); }
        if output == 0 { return Some(STATUS_INVALID_PARAMETER); }
        if uaccess::copy_to_user(output, &[0u8; OBJECT_NAME_HEADER_BYTES]).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        return Some(STATUS_SUCCESS);
    }
    let units: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    let bytes = units.len().checked_mul(2)?.checked_add(2)?;
    let required = OBJECT_NAME_HEADER_BYTES.checked_add(bytes)?;
    if return_length != 0 && uaccess::put_user_u32(return_length, required as u32).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    if length < required { return Some(STATUS_INFO_LENGTH_MISMATCH); }
    if output == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let mut buffer = alloc::vec![0u8; required];
    buffer[0..2].copy_from_slice(&(bytes as u16 - 2).to_ne_bytes());
    buffer[2..4].copy_from_slice(&(bytes as u16).to_ne_bytes());
    buffer[8..16].copy_from_slice(&(output + OBJECT_NAME_HEADER_BYTES as u64).to_ne_bytes());
    for (index, unit) in units.iter().enumerate() { buffer[OBJECT_NAME_HEADER_BYTES + index * 2..OBJECT_NAME_HEADER_BYTES + index * 2 + 2].copy_from_slice(&unit.to_ne_bytes()); }
    if uaccess::copy_to_user(output, &buffer).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_SUCCESS)
}

fn query_type(kind: sched::nt_object::NtObjectType, output: u64, length: usize, return_length: u64) -> Option<u64> {
    let name = match kind {
        sched::nt_object::NtObjectType::Process => "Process", sched::nt_object::NtObjectType::Thread => "Thread",
        sched::nt_object::NtObjectType::File => "File", sched::nt_object::NtObjectType::Directory => "Directory",
        sched::nt_object::NtObjectType::Section => "Section", sched::nt_object::NtObjectType::SymbolicLink => "SymbolicLink",
        sched::nt_object::NtObjectType::Event => "Event", sched::nt_object::NtObjectType::Semaphore => "Semaphore",
        sched::nt_object::NtObjectType::Mutant => "Mutant", sched::nt_object::NtObjectType::Timer => "Timer",
        sched::nt_object::NtObjectType::CompletionPort => "IoCompletion", sched::nt_object::NtObjectType::Token => "Token",
        sched::nt_object::NtObjectType::Key => "Key", sched::nt_object::NtObjectType::Job => "Job",
        sched::nt_object::NtObjectType::NamedPipe => "NamedPipe", sched::nt_object::NtObjectType::ActivationContext => "ActivationContext",
    };
    let units: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    let bytes = units.len().checked_mul(2)?.checked_add(2)?;
    let required = OBJECT_TYPE_HEADER_BYTES.checked_add(bytes)?;
    if return_length != 0 && uaccess::put_user_u32(return_length, required as u32).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    if length < required { return Some(STATUS_INFO_LENGTH_MISMATCH); }
    if output == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let mut buffer = alloc::vec![0u8; required];
    buffer[8..10].copy_from_slice(&(bytes as u16 - 2).to_ne_bytes());
    buffer[10..12].copy_from_slice(&(bytes as u16).to_ne_bytes());
    buffer[16..24].copy_from_slice(&(output + OBJECT_TYPE_HEADER_BYTES as u64).to_ne_bytes());
    for (index, unit) in units.iter().enumerate() { buffer[OBJECT_TYPE_HEADER_BYTES + index * 2..OBJECT_TYPE_HEADER_BYTES + index * 2 + 2].copy_from_slice(&unit.to_ne_bytes()); }
    if uaccess::copy_to_user(output, &buffer).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_SUCCESS)
}
