//! Process API-set namespace query boundary for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const UNICODE_STRING_BYTES: usize = 16;

/// Report whether a name belongs to the process API-set schema.
/// # C: O(name length) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::ApiSetQueryApiSetPresenceEx { return None; }
    if call.args.a0 == 0 || call.args.a1 == 0 || call.args.a2 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut descriptor, call.args.a0).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    let length = u16::from_le_bytes([descriptor[0], descriptor[1]]) as usize;
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    if length == 0 || length & 1 != 0 || buffer == 0 || length > 1024 { return Some(STATUS_INVALID_PARAMETER); }
    let mut wide = Vec::new(); wide.resize(length, 0);
    if uaccess::copy_from_user(&mut wide, buffer).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    for pair in wide.chunks_exact(2) {
        if u16::from_le_bytes([pair[0], pair[1]]) == b'.' as u16 { return Some(STATUS_INVALID_PARAMETER); }
    }
    // ApiSetMap is not installed in the PEB yet, so the name is neither in
    // the schema nor present. This is the defined absent-map result.
    if uaccess::copy_to_user(call.args.a1, &[0]).is_err() || uaccess::copy_to_user(call.args.a2, &[0]).is_err() {
        return Some(STATUS_INVALID_PARAMETER);
    }
    Some(STATUS_SUCCESS)
}
