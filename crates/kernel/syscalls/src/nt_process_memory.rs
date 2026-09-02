//! Native current-process virtual-memory copy for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const STATUS_PARTIAL_COPY: u64 = 0x8000_000d;
const CURRENT_PROCESS: u64 = u64::MAX;
const CHUNK_BYTES: usize = 4096;

/// Copy memory within the current NT address space using the canonical
/// user-access fault boundary; remote address-space ownership remains explicit.
/// # C: O(size / CHUNK_BYTES)
pub fn dispatch(call: NtCall) -> Option<u64> {
    let read = match call.service {
        NtService::NtReadVirtualMemory => true,
        NtService::NtWriteVirtualMemory => false,
        _ => return None,
    };
    if call.args.a0 != CURRENT_PROCESS { return Some(STATUS_NOT_IMPLEMENTED); }
    let size = match usize::try_from(call.args.a3) { Ok(size) => size, Err(_) => return Some(STATUS_INVALID_PARAMETER) };
    if size != 0 && (call.args.a1 == 0 || call.args.a2 == 0) { return Some(STATUS_INVALID_PARAMETER); }
    let mut copied = 0usize;
    let mut scratch = [0u8; CHUNK_BYTES];
    while copied < size {
        let count = (size - copied).min(CHUNK_BYTES);
        let source = match call.args.a1.checked_add(copied as u64) { Some(value) => value, None => break };
        let destination = match call.args.a2.checked_add(copied as u64) { Some(value) => value, None => break };
        let result = if read {
            if uaccess::copy_from_user(&mut scratch[..count], source).is_err() { break; }
            uaccess::copy_to_user(destination, &scratch[..count])
        } else {
            if uaccess::copy_from_user(&mut scratch[..count], destination).is_err() { break; }
            uaccess::copy_to_user(source, &scratch[..count])
        };
        if result.is_err() { break; }
        copied += count;
    }
    if call.args.a4 != 0 && uaccess::put_user_u64(call.args.a4, copied as u64).is_err() {
        return Some(STATUS_INVALID_PARAMETER);
    }
    if copied == size { Some(STATUS_SUCCESS) } else { Some(STATUS_PARTIAL_COPY) }
}
