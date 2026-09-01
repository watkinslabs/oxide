//! Native RTL bitmap mutation for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

/// Dispatch caller-owned RTL bitmap operations.
/// # C: O(count) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlClearBits { return None; }
    Some(clear_bits(call.args.a0, call.args.a1 as u32, call.args.a2 as u32))
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
