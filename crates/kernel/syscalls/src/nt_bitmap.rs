//! Native RTL bitmap mutation for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

/// Dispatch caller-owned RTL bitmap operations.
/// # C: O(count) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlFindClearBitsAndSet {
        return Some(find_clear_bits_and_set(call.args.a0, call.args.a1 as u32, call.args.a2 as u32) as u64);
    }
    if call.service != NtService::RtlClearBits { return None; }
    Some(clear_bits(call.args.a0, call.args.a1 as u32, call.args.a2 as u32))
}

fn find_clear_bits_and_set(bitmap: u64, count: u32, hint: u32) -> u32 {
    if bitmap == 0 || count == 0 { return u32::MAX; }
    let mut descriptor = [0u8; 16];
    if uaccess::copy_from_user(&mut descriptor, bitmap).is_err() { return u32::MAX; }
    let size = u32::from_le_bytes(descriptor[0..4].try_into().unwrap());
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    if count > size || buffer == 0 { return u32::MAX; }
    let start = if hint.checked_add(count).is_some_and(|end| end <= size) { hint } else { 0 };
    let mut end = size;
    let mut position = start;
    loop {
        if position.checked_add(count).is_some_and(|candidate| candidate <= end) && run_is_clear(buffer, position, count) {
            for bit in position..position + count {
                let Some(address) = buffer.checked_add((bit / 8) as u64) else { return u32::MAX; };
                let mut byte = [0u8; 1];
                if uaccess::copy_from_user(&mut byte, address).is_err() { return u32::MAX; }
                byte[0] |= 1 << (bit & 7);
                if uaccess::copy_to_user(address, &byte).is_err() { return u32::MAX; }
            }
            return position;
        }
        if position + 1 >= end {
            if start == 0 { return u32::MAX; }
            end = start;
            position = 0;
        } else {
            position += 1;
        }
    }
}

fn run_is_clear(buffer: u64, start: u32, count: u32) -> bool {
    for bit in start..start + count {
        let Some(address) = buffer.checked_add((bit / 8) as u64) else { return false; };
        let mut byte = [0u8; 1];
        if uaccess::copy_from_user(&mut byte, address).is_err() || byte[0] & (1 << (bit & 7)) != 0 { return false; }
    }
    true
}

fn clear_bits(bitmap: u64, start: u32, count: u32) -> u64 {
    if bitmap == 0 { return 0; }
    let mut descriptor = [0u8; 16];
    if uaccess::copy_from_user(&mut descriptor, bitmap).is_err() { return 0; }
    let size = u32::from_le_bytes(descriptor[0..4].try_into().unwrap());
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    if count == 0 || start >= size || count > size - start || buffer == 0 { return 0; }
    for bit in start..start + count {
        let Some(address) = buffer.checked_add((bit / 8) as u64) else { return 0; };
        let mut byte = [0u8; 1];
        if uaccess::copy_from_user(&mut byte, address).is_err() { return 0; }
        byte[0] &= !(1 << (bit & 7));
        if uaccess::copy_to_user(address, &byte).is_err() { return 0; }
    }
    0
}
