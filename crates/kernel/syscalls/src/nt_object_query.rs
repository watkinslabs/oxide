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

/// Return the handle's granted access in the x64 object-basic layout.
/// # C: O(1) plus usercopy
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::QueryObject { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let return_length = call.args.a4;
    if return_length != 0 && uaccess::put_user_u32(return_length, 0).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    if call.args.a1 as u32 != OBJECT_BASIC_INFORMATION { return Some(STATUS_INVALID_INFO_CLASS); }
    let table = cur.thread_group.nt_handles();
    let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let Some(access) = table.access(handle) else { return Some(STATUS_INVALID_HANDLE); };
    if return_length != 0 && uaccess::put_user_u32(return_length, OBJECT_BASIC_INFORMATION_BYTES as u32).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    if (call.args.a3 as usize) < OBJECT_BASIC_INFORMATION_BYTES { return Some(STATUS_INFO_LENGTH_MISMATCH); }
    if call.args.a2 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let mut output = [0u8; OBJECT_BASIC_INFORMATION_BYTES];
    output[4..8].copy_from_slice(&access.to_le_bytes());
    if uaccess::copy_to_user(call.args.a2, &output).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_SUCCESS)
}
