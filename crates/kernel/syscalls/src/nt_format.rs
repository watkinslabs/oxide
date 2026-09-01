//! Bounded native message formatting for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use alloc::{vec, vec::Vec};
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_BUFFER_OVERFLOW: u64 = 0x8000_0005;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;

/// Format literal NT message text while preserving bounded user writes.
/// # C: O(source UTF-16 units + output UTF-16 units)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if !matches!(call.service, NtService::RtlFormatMessage | NtService::RtlFormatMessageEx) { return None; }
    Some(format_message(call))
}

fn format_message(call: NtCall) -> u64 {
    let Some(buffer) = crate::nt_dispatch::stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
    let Some(size) = crate::nt_dispatch::stack_argument(7) else { return STATUS_INVALID_PARAMETER; };
    let Some(retsize) = crate::nt_dispatch::stack_argument(8) else { return STATUS_INVALID_PARAMETER; };
    if call.args.a0 == 0 || buffer == 0 || size == 0 || retsize == 0 { return STATUS_INVALID_PARAMETER; }
    if call.service == NtService::RtlFormatMessageEx && crate::nt_dispatch::stack_argument(9).unwrap_or(0) != 0 { return STATUS_NOT_IMPLEMENTED; }
    if call.args.a4 != 0 { return STATUS_NOT_IMPLEMENTED; }
    let source = read_source(call.args.a0);
    if source.is_empty() { return STATUS_INVALID_PARAMETER; }
    let mut output = Vec::new();
    let mut index = 0;
    while index < source.len() {
        if source[index] != b'%' as u16 {
            output.push(source[index]); index += 1; continue;
        }
        let Some(next) = source.get(index + 1).copied() else { return STATUS_INVALID_PARAMETER; };
        match next {
            x if x == b'%' as u16 => { output.push(next); index += 2; }
            x if x == b'n' as u16 => { output.extend_from_slice(&[b'\r' as u16, b'\n' as u16]); index += 2; }
            x if x == b'r' as u16 => { output.push(b'\r' as u16); index += 2; }
            x if x == b't' as u16 => { output.push(b'\t' as u16); index += 2; }
            x if x == b'0' as u16 => break,
            _ => return STATUS_NOT_IMPLEMENTED,
        }
    }
    let required = output.len().checked_add(1).and_then(|units| units.checked_mul(2)).unwrap_or(usize::MAX);
    if uaccess::put_user_u32(retsize, required as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    if required > size as usize { return STATUS_BUFFER_OVERFLOW; }
    let mut bytes = vec![0u8; required];
    for (index, unit) in output.iter().chain(core::iter::once(&0)).enumerate() { bytes[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes()); }
    if uaccess::copy_to_user(buffer, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn read_source(address: u64) -> Vec<u16> {
    let mut source = Vec::new();
    for index in 0..65536usize {
        let Some(address) = address.checked_add((index * 2) as u64) else { break; };
        let Ok(unit) = uaccess::get_user_u32(address) else { break; };
        let unit = unit as u16;
        if unit == 0 { break; }
        source.push(unit);
    }
    source
}
