//! Native Unicode string integer parsing for the Windows RTL boundary.
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;

/// Parse a counted UTF-16 string using the Windows RTL base and sign rules.
/// # C: O(string length) plus usercopy
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlUnicodeStringToInteger { return None; }
    Some(parse(call.args.a0, call.args.a1 as u32, call.args.a2))
}

fn parse(descriptor: u64, requested_base: u32, output: u64) -> u64 {
    let base = if requested_base == 0 { 10 } else if matches!(requested_base, 2 | 8 | 10 | 16) { requested_base } else { return STATUS_INVALID_PARAMETER; };
    if output == 0 { return STATUS_ACCESS_VIOLATION; }
    if descriptor == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; 16];
    if uaccess::copy_from_user(&mut header, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    let length = u16::from_le_bytes([header[0], header[1]]) as usize / 2;
    let buffer = u64::from_le_bytes(header[8..16].try_into().unwrap());
    if length != 0 && buffer == 0 { return STATUS_INVALID_PARAMETER; }
    let mut chars = Vec::new();
    let mut total = 0usize;
    while total < length {
        chars.push(match read_u16(buffer, total) { Some(value) => value, None => return STATUS_INVALID_PARAMETER });
        total += 1;
    }
    let mut index = 0usize;
    while index < total && chars[index] <= 0x20 { index += 1; }
    let negative = if index < total && chars[index] == b'-' as u16 { index += 1; true } else { if index < total && chars[index] == b'+' as u16 { index += 1; } false };
    let mut base = base;
    if requested_base == 0 && index + 1 < total && chars[index] == b'0' as u16 {
        match chars[index + 1] {
            value if value == b'b' as u16 => { base = 2; index += 2; }
            value if value == b'o' as u16 => { base = 8; index += 2; }
            value if value == b'x' as u16 => { base = 16; index += 2; }
            _ => {}
        }
    }
    let mut value = 0u32;
    while index < total {
        let digit = if (b'0' as u16..=b'9' as u16).contains(&chars[index]) { (chars[index] - b'0' as u16) as u32 }
        else if (b'A' as u16..=b'Z' as u16).contains(&chars[index]) { (chars[index] - b'A' as u16 + 10) as u32 }
        else if (b'a' as u16..=b'z' as u16).contains(&chars[index]) { (chars[index] - b'a' as u16 + 10) as u32 }
        else { base };
        if digit >= base { break; }
        value = value.wrapping_mul(base).wrapping_add(digit);
        index += 1;
    }
    if negative { value = 0u32.wrapping_sub(value); }
    if uaccess::put_user_u32(output, value).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}

fn read_u16(buffer: u64, index: usize) -> Option<u16> {
    let address = buffer.checked_add((index.checked_mul(2))? as u64)?;
    let mut bytes = [0u8; 2];
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    Some(u16::from_le_bytes(bytes))
}
