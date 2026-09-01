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

/// Allocate a heap-owned SID and initialize its native layout.
/// # C: O(1) plus bounded user copies and one VMM allocation
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlAllocateAndInitializeSid { return None; }
    Some(allocate_and_initialize(call))
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
