//! Native object-manager directory boundary for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;

/// Validate an object-manager directory open and report an absent namespace entry.
/// # C: O(1) plus one user write
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::OpenDirectoryObject { return None; }
    if call.args.a0 == 0 || call.args.a2 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    if uaccess::put_user_u32(call.args.a0, 0).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    let mut length = [0u8; 4];
    if uaccess::copy_from_user(&mut length, call.args.a2).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    if u32::from_le_bytes(length) < 24 { return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_OBJECT_NAME_NOT_FOUND)
}
