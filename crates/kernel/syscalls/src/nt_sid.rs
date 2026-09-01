//! Native SID allocation for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use syscall::{nt::{NtCall, NtService}, SyscallArgs};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_SID: u64 = 0xc000_0078;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const SID_REVISION: u8 = 1;
const SID_IDENTIFIER_AUTHORITY_BYTES: usize = 6;
const SID_FIXED_BYTES: usize = 8;
const MAX_SUBAUTHORITIES: u64 = 8;
const STATUS_BUFFER_OVERFLOW: u64 = 0x8000_0005;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const SID_MAX_SUB_AUTHORITIES: u64 = 15;

/// Allocate a heap-owned SID and initialize its native layout.
/// # C: O(1) plus bounded user copies and one VMM allocation
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlInitializeSid { return Some(initialize_sid(call.args.a0, call.args.a1, call.args.a2 & 0xff)); }
    if call.service == NtService::RtlIdentifierAuthoritySid { return Some(identifier_authority_sid(call.args.a0)); }
    if call.service == NtService::RtlFreeSid { return Some(free_sid(call.args.a0)); }
    if call.service == NtService::RtlEqualPrefixSid { return Some(equal_prefix_sid(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlEqualSid { return Some(equal_sid(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlConvertSidToUnicodeString {
        return Some(convert_to_unicode(call.args.a0, call.args.a1, call.args.a2 != 0));
    }
    if call.service == NtService::RtlCopySid {
        return Some(copy_sid(call.args.a0 as u32, call.args.a1, call.args.a2));
    }
    if call.service != NtService::RtlAllocateAndInitializeSid { return None; }
    Some(allocate_and_initialize(call))
}

fn initialize_sid(sid: u64, authority: u64, count: u64) -> u64 {
    if sid == 0 { return STATUS_INVALID_PARAMETER; }
    if count > SID_MAX_SUB_AUTHORITIES { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; SID_FIXED_BYTES];
    header[0] = SID_REVISION;
    header[1] = count as u8;
    if authority != 0 {
        let mut identifier = [0u8; SID_IDENTIFIER_AUTHORITY_BYTES];
        if uaccess::copy_from_user(&mut identifier, authority).is_err() { return STATUS_INVALID_PARAMETER; }
        header[2..8].copy_from_slice(&identifier);
    }
    if uaccess::copy_to_user(sid, &header).is_err() { return STATUS_INVALID_PARAMETER; }
    let zeros = [0u8; 15 * core::mem::size_of::<u32>()];
    if count != 0 && uaccess::copy_to_user(sid + SID_FIXED_BYTES as u64, &zeros[..count as usize * 4]).is_err() {
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}

fn identifier_authority_sid(sid: u64) -> u64 { sid.checked_add(2).unwrap_or(0) }

fn free_sid(sid: u64) -> u64 {
    if sid == 0 { return STATUS_SUCCESS; }
    let call = NtCall { service: NtService::FreeHeap, args: SyscallArgs { a0: 0, a1: 0, a2: sid, a3: 0, a4: 0, a5: 0 } };
    let _ = crate::nt_heap::dispatch(call);
    STATUS_SUCCESS
}

fn equal_prefix_sid(first: u64, second: u64) -> u64 {
    if first == 0 || second == 0 { return 0; }
    let mut left = [0u8; SID_FIXED_BYTES + 15 * 4];
    let mut right = [0u8; SID_FIXED_BYTES + 15 * 4];
    if uaccess::copy_from_user(&mut left[..SID_FIXED_BYTES], first).is_err()
        || uaccess::copy_from_user(&mut right[..SID_FIXED_BYTES], second).is_err() { return 0; }
    if left[0] != SID_REVISION || right[0] != SID_REVISION || left[1] == 0 || left[1] != right[1] || left[1] > 15 { return 0; }
    let size = SID_FIXED_BYTES + left[1] as usize * 4;
    if uaccess::copy_from_user(&mut left[SID_FIXED_BYTES..size], first + SID_FIXED_BYTES as u64).is_err()
        || uaccess::copy_from_user(&mut right[SID_FIXED_BYTES..size], second + SID_FIXED_BYTES as u64).is_err() { return 0; }
    let prefix = SID_FIXED_BYTES + (left[1] as usize - 1) * 4;
    u64::from(left[..prefix] == right[..prefix])
}

fn equal_sid(first: u64, second: u64) -> u64 {
    if first == 0 || second == 0 { return 0; }
    let mut left = [0u8; SID_FIXED_BYTES + 15 * 4];
    let mut right = [0u8; SID_FIXED_BYTES + 15 * 4];
    if uaccess::copy_from_user(&mut left[..SID_FIXED_BYTES], first).is_err()
        || uaccess::copy_from_user(&mut right[..SID_FIXED_BYTES], second).is_err() { return 0; }
    if left[0] != SID_REVISION || right[0] != SID_REVISION || left[1] == 0 || left[1] != right[1] || left[1] > 15 { return 0; }
    let size = SID_FIXED_BYTES + left[1] as usize * 4;
    if uaccess::copy_from_user(&mut left[SID_FIXED_BYTES..size], first + SID_FIXED_BYTES as u64).is_err()
        || uaccess::copy_from_user(&mut right[SID_FIXED_BYTES..size], second + SID_FIXED_BYTES as u64).is_err() { return 0; }
    u64::from(left[..size] == right[..size])
}

fn copy_sid(destination_length: u32, destination: u64, source: u64) -> u64 {
    if destination == 0 || source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; SID_FIXED_BYTES];
    if uaccess::copy_from_user(&mut header, source).is_err() || header[0] != SID_REVISION || header[1] as u64 > MAX_SUBAUTHORITIES { return STATUS_INVALID_SID; }
    let size = SID_FIXED_BYTES + header[1] as usize * core::mem::size_of::<u32>();
    if destination_length < size as u32 { return STATUS_BUFFER_TOO_SMALL; }
    let mut sid = [0u8; SID_FIXED_BYTES + 8 * core::mem::size_of::<u32>()];
    if uaccess::copy_from_user(&mut sid[..size], source).is_err() || uaccess::copy_to_user(destination, &sid[..size]).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn convert_to_unicode(string: u64, sid: u64, allocate: bool) -> u64 {
    if string == 0 || sid == 0 { return STATUS_INVALID_PARAMETER; }
    let mut descriptor = [0u8; 16];
    if uaccess::copy_from_user(&mut descriptor, string).is_err() { return STATUS_INVALID_PARAMETER; }
    let maximum = u16::from_le_bytes([descriptor[2], descriptor[3]]) as usize;
    let destination = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    let mut header = [0u8; SID_FIXED_BYTES];
    if uaccess::copy_from_user(&mut header, sid).is_err() || header[0] != SID_REVISION || header[1] as u64 > MAX_SUBAUTHORITIES {
        return STATUS_INVALID_SID;
    }
    let count = header[1] as usize;
    let sid_size = SID_FIXED_BYTES + count * core::mem::size_of::<u32>();
    let mut bytes = [0u8; SID_FIXED_BYTES + 8 * core::mem::size_of::<u32>()];
    if uaccess::copy_from_user(&mut bytes[..sid_size], sid).is_err() { return STATUS_INVALID_SID; }
    let authority = u64::from_be_bytes([0, 0, bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]);
    let mut text = alloc::vec::Vec::new();
    push_wide_ascii(&mut text, b'S');
    push_wide_ascii(&mut text, b'-'); push_decimal(&mut text, bytes[0] as u64);
    push_wide_ascii(&mut text, b'-'); push_decimal(&mut text, authority);
    for index in 0..count { push_wide_ascii(&mut text, b'-'); push_decimal(&mut text, u32::from_le_bytes(bytes[8 + index * 4..12 + index * 4].try_into().unwrap()) as u64); }
    text.push(0);
    let size = text.len() * 2;
    let target = if allocate {
        let heap = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: size as u64, a3: 0, a4: 0, a5: 0 } };
        let Some(value) = crate::nt_heap::dispatch(heap).filter(|value| *value != 0) else { return STATUS_NO_MEMORY; };
        value
    } else {
        if size > maximum || destination == 0 { return STATUS_BUFFER_OVERFLOW; }
        destination
    };
    let mut wide = alloc::vec![0u8; size];
    for (index, value) in text.iter().enumerate() { wide[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes()); }
    if uaccess::copy_to_user(target, &wide).is_err() {
        if allocate { free_heap(target); }
        return STATUS_INVALID_PARAMETER;
    }
    let mut output = descriptor;
    output[0..2].copy_from_slice(&((size - 2) as u16).to_le_bytes());
    output[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    output[8..16].copy_from_slice(&target.to_le_bytes());
    if uaccess::copy_to_user(string, &output).is_err() { if allocate { free_heap(target); } return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn push_wide_ascii(out: &mut alloc::vec::Vec<u16>, value: u8) { out.push(value as u16); }

fn push_decimal(out: &mut alloc::vec::Vec<u16>, mut value: u64) {
    let mut digits = [0u16; 20]; let mut count = 0;
    if value == 0 { out.push(0); return; }
    while value != 0 { digits[count] = b'0' as u16 + (value % 10) as u16; count += 1; value /= 10; }
    while count != 0 { count -= 1; out.push(digits[count]); }
}

fn free_heap(base: u64) {
    let free = NtCall { service: NtService::FreeHeap, args: SyscallArgs { a0: 0, a1: 0, a2: base, a3: 0, a4: 0, a5: 0 } };
    let _ = crate::nt_heap::dispatch(free);
}

fn allocate_and_initialize(call: NtCall) -> u64 {
    let authority = call.args.a0;
    let count = call.args.a1 & 0xff;
    let output = crate::nt_dispatch::stack_argument(10).unwrap_or(0);
    if count > MAX_SUBAUTHORITIES || output == 0 { return STATUS_INVALID_SID; }

    let mut identifier = [0u8; SID_IDENTIFIER_AUTHORITY_BYTES];
    if authority != 0 && uaccess::copy_from_user(&mut identifier, authority).is_err() {
        return STATUS_INVALID_PARAMETER;
    }
    let size = SID_FIXED_BYTES + count as usize * core::mem::size_of::<u32>();
    let heap = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: size as u64, a3: 0, a4: 0, a5: 0 } };
    let Some(base) = crate::nt_heap::dispatch(heap).filter(|value| *value != 0) else { return STATUS_NO_MEMORY; };

    let mut sid = [0u8; SID_FIXED_BYTES + 8 * core::mem::size_of::<u32>()];
    sid[0] = SID_REVISION;
    sid[1] = count as u8;
    sid[2..8].copy_from_slice(&identifier);
    let values = [call.args.a2, call.args.a3, call.args.a4, call.args.a5,
        crate::nt_dispatch::stack_argument(6).unwrap_or(0), crate::nt_dispatch::stack_argument(7).unwrap_or(0),
        crate::nt_dispatch::stack_argument(8).unwrap_or(0), crate::nt_dispatch::stack_argument(9).unwrap_or(0)];
    for index in 0..count as usize { sid[SID_FIXED_BYTES + index * 4..SID_FIXED_BYTES + index * 4 + 4].copy_from_slice(&(values[index] as u32).to_le_bytes()); }
    if uaccess::copy_to_user(base, &sid[..size]).is_err() || uaccess::put_user_u64(output, base).is_err() {
        let free = NtCall { service: NtService::FreeHeap, args: SyscallArgs { a0: 0, a1: 0, a2: base, a3: 0, a4: 0, a5: 0 } };
        let _ = crate::nt_heap::dispatch(free);
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}
