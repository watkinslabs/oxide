//! Native x86-64 CONTEXT selection and copying for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;
const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_XSTATE: u32 = 0x40;
const CONTEXT_ALL: u32 = 0x1f;
const CONTEXT_HIGH_FLAGS: u32 = 0xd800_0000;
const FLAGS_OFFSET: u64 = 0x30;

/// Copy the selected portions of two caller-owned AMD64 contexts.
/// # C: O(context size) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlCopyContext { return None; }
    Some(copy_context(call.args.a0, call.args.a1 as u32, call.args.a2))
}

fn copy_context(destination: u64, requested: u32, source: u64) -> u64 {
    if destination == 0 || source == 0 { return STATUS_INVALID_PARAMETER; }
    if requested & CONTEXT_XSTATE != 0 { return STATUS_NOT_SUPPORTED; }
    if requested & !(CONTEXT_AMD64 | CONTEXT_ALL | CONTEXT_HIGH_FLAGS) != 0 { return STATUS_INVALID_PARAMETER; }
    let Some(destination_flags) = read_u32(destination + FLAGS_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    let Some(source_flags) = read_u32(source + FLAGS_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    if destination_flags & CONTEXT_AMD64 != CONTEXT_AMD64 || source_flags & CONTEXT_AMD64 != CONTEXT_AMD64 { return STATUS_INVALID_PARAMETER; }
    let selected = requested & source_flags;
    let ranges = [(0x38u64, 0x1u32), (0x3a, 0x4), (0x42, 0x1), (0x48, 0x10), (0x78, 0x2),
        (0x98, 0x1), (0xa0, 0x2), (0xf8, 0x1), (0x100, 0x8), (0x2a0, 0), (0x4b0, 0x10), (0x4d0, 0)];
    let mut start = None;
    for (boundary, flag) in ranges {
        if flag != 0 && selected & flag != 0 {
            if start.is_none() { start = Some(boundary); }
        } else if let Some(begin) = start.take() {
            if copy_range(destination, source, begin, boundary).is_err() { return STATUS_INVALID_PARAMETER; }
        }
    }
    if write_u32(destination + FLAGS_OFFSET, destination_flags | selected).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn copy_range(destination: u64, source: u64, start: u64, end: u64) -> Result<(), ()> {
    let length = usize::try_from(end.checked_sub(start).ok_or(())?).map_err(|_| ())?;
    let mut bytes = vec![0u8; length];
    uaccess::copy_from_user(&mut bytes, source.checked_add(start).ok_or(())?).map_err(|_| ())?;
    uaccess::copy_to_user(destination.checked_add(start).ok_or(())?, &bytes).map_err(|_| ())
}

fn read_u32(address: u64) -> Option<u32> { uaccess::get_user_u32(address).ok() }
fn write_u32(address: u64, value: u32) -> Result<(), ()> { uaccess::put_user_u32(address, value).map_err(|_| ()) }
