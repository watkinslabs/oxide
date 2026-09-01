//! DOS path classification used by the Windows loader personality.
#![cfg(target_os = "oxide-kernel")]
extern crate alloc;
use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;

/// Classify a DOS path using the Windows separator and drive rules.
/// # C: O(1) plus four bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlIsDosDeviceNameU { return Some(is_dos_device_name(call.args.a0)); }
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

fn is_dos_device_name(address: u64) -> u64 {
    if address == 0 { return 0; }
    let mut path = Vec::new();
    for index in 0..32768usize {
        let Some(slot) = address.checked_add((index * 2) as u64) else { return 0; };
        let mut bytes = [0u8; 2];
        if uaccess::copy_from_user(&mut bytes, slot).is_err() { return 0; }
        let value = u16::from_le_bytes(bytes);
        if value == 0 { break; }
        path.push(value);
    }
    if path.is_empty() { return 0; }
    let separator = |value: u16| value == b'\\' as u16 || value == b'/' as u16;
    let path_type = if separator(path[0]) {
        if path.len() < 2 || !separator(path[1]) { 4 }
        else if path.get(2).copied() != Some(b'.' as u16) && path.get(2).copied() != Some(b'?' as u16) { 1 }
        else if path.get(3).copied().is_some_and(separator) { 6 }
        else if path.get(3).copied().is_some_and(|v| v != 0) { 1 } else { 7 }
    } else if path.len() < 2 || path[1] != b':' as u16 { 5 }
    else if path.get(2).copied().is_some_and(separator) { 2 } else { 3 };
    if path_type == 1 { return 0; }
    if path_type == 6 {
        if path.len() == 7 && equal_ascii(&path, b"\\\\.\\CON") { return (6u64) | (8u64 << 16); }
        return 0;
    }
    let mut start = if path_type == 2 || path_type == 3 { 2 } else { 0 };
    for index in start..path.len() { if separator(path[index]) { start = index + 1; } }
    let mut end = start;
    while end < path.len() && path[end] != b'.' as u16 && path[end] != b':' as u16 { end += 1; }
    if end == start { return 0; }
    end -= 1;
    while end >= start && path[end] == b' ' as u16 { if end == 0 { return 0; } end -= 1; }
    let length = end - start + 1;
    let device = &path[start..=end];
    let valid = match length {
        3 => equal_ascii(device, b"AUX") || equal_ascii(device, b"CON") || equal_ascii(device, b"NUL") || equal_ascii(device, b"PRN"),
        4 => (equal_ascii(&device[..3], b"COM") || equal_ascii(&device[..3], b"LPT")) && device[3] >= b'1' as u16 && device[3] <= b'9' as u16,
        6 => equal_ascii(device, b"CONIN$"),
        7 => equal_ascii(device, b"CONOUT$"),
        _ => false,
    };
    if valid { (length as u64 * 2) | (((start * 2) as u64) << 16) } else { 0 }
}

fn equal_ascii(value: &[u16], expected: &[u8]) -> bool {
    value.len() == expected.len() && value.iter().zip(expected).all(|(left, right)| (*left as u8).to_ascii_uppercase() == right.to_ascii_uppercase() && *left <= 0x7f)
}
