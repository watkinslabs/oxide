//! Native OEM `STRING` to `UNICODE_STRING` conversion.
#![cfg(target_os = "oxide-kernel")]
use syscall::{nt::{NtCall, NtService}, SyscallArgs};
const INVALID: u64 = 0xc000_000d; const OVERFLOW: u64 = 0x8000_0005; const BAD_LENGTH: u64 = 0xc000_00f0; const NO_MEMORY: u64 = 0xc000_0017;
pub fn dispatch(call: NtCall) -> Option<u64> { (call.service == NtService::RtlOemStringToUnicodeString).then(|| convert(call.args.a0, call.args.a1, call.args.a2)) }
fn convert(target: u64, source: u64, allocate: u64) -> u64 {
    if target == 0 || source == 0 { return INVALID; }
    let mut oem = [0u8; 16]; let mut unicode = [0u8; 16];
    if uaccess::copy_from_user(&mut oem, source).is_err() || uaccess::copy_from_user(&mut unicode, target).is_err() { return INVALID; }
    let length = u16::from_le_bytes([oem[0], oem[1]]) as usize; let maximum = u16::from_le_bytes([oem[2], oem[3]]) as usize;
    let source_buffer = u64::from_le_bytes(oem[8..16].try_into().unwrap());
    if length > maximum || (length != 0 && source_buffer == 0) { return INVALID; }
    let Some(total) = length.checked_mul(2).and_then(|size| size.checked_add(2)) else { return BAD_LENGTH; };
    if total > u16::MAX as usize { return BAD_LENGTH; }
    let destination_maximum = u16::from_le_bytes([unicode[2], unicode[3]]) as usize; let mut destination = u64::from_le_bytes(unicode[8..16].try_into().unwrap()); let owned = allocate != 0;
    if owned { let call = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: total as u64, a3: 0, a4: 0, a5: 0 } }; let Some(buffer) = crate::nt_heap::dispatch(call).filter(|address| *address != 0) else { return NO_MEMORY; }; destination = buffer; }
    else if total > destination_maximum || destination == 0 { return OVERFLOW; }
    let mut wide = alloc::vec![0u8; total];
    for index in 0..length {
        let Some(source_address) = source_buffer.checked_add(index as u64) else { if owned { free(destination); } return INVALID; };
        let Some(output_offset) = index.checked_mul(2) else { if owned { free(destination); } return INVALID; };
        let mut byte = [0u8; 1];
        if uaccess::copy_from_user(&mut byte, source_address).is_err() { if owned { free(destination); } return INVALID; }
        let value = if byte[0].is_ascii() { byte[0] as u16 } else { 0xfffd };
        wide[output_offset..output_offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    if uaccess::copy_to_user(destination, &wide).is_err() { if owned { free(destination); } return INVALID; }
    let mut output = [0u8; 16]; output[0..2].copy_from_slice(&((length * 2) as u16).to_le_bytes()); output[2..4].copy_from_slice(&(total as u16).to_le_bytes()); output[8..16].copy_from_slice(&destination.to_le_bytes());
    if uaccess::copy_to_user(target, &output).is_err() { if owned { free(destination); } return INVALID; } 0
}
fn free(buffer: u64) { let call = NtCall { service: NtService::FreeHeap, args: SyscallArgs { a0: 0, a1: 0, a2: buffer, a3: 0, a4: 0, a5: 0 } }; let _ = crate::nt_heap::dispatch(call); }
