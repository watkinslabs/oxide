//! DOS path classification used by the Windows loader personality.
#![cfg(target_os = "oxide-kernel")]
use syscall::nt::{NtCall, NtService};
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;

/// Classify a DOS path using the Windows separator and drive rules.
/// # C: O(1) plus four bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlDetermineDosPathNameTypeU { return None; }
    if call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let mut path = [0u16; 4];
    for (index, value) in path.iter_mut().enumerate() {
        let address = match call.args.a0.checked_add((index * 2) as u64) { Some(value) => value, None => return Some(STATUS_INVALID_PARAMETER) };
        let mut bytes = [0u8; 2];
        if uaccess::copy_from_user(&mut bytes, address).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        *value = u16::from_le_bytes(bytes);
    }
    let separator = |value| value == b'\\' as u16 || value == b'/' as u16;
    Some(if separator(path[0]) {
        if !separator(path[1]) { 4 } else if path[2] != b'.' as u16 && path[2] != b'?' as u16 { 1 }
        else if separator(path[3]) { 6 } else if path[3] != 0 { 1 } else { 7 }
    } else if path[0] == 0 || path[1] != b':' as u16 { 5 }
    else if separator(path[2]) { 2 } else { 3 })
}
