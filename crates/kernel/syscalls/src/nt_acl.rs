//! Native ACL mutation boundary for the Windows personality.
#![cfg(target_os = "oxide-kernel")]
use alloc::vec;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const ACL_HEADER_BYTES: usize = 8;
const ACE_HEADER_BYTES: usize = 4;

/// Delete one variable-sized ACE while preserving the caller-owned ACL.
/// # C: O(acl bytes)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlDeleteAce { return None; }
    if call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let mut header = [0u8; ACL_HEADER_BYTES];
    if uaccess::copy_from_user(&mut header, call.args.a0).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    let revision = header[0];
    let acl_size = u16::from_le_bytes([header[2], header[3]]) as usize;
    let ace_count = u16::from_le_bytes([header[4], header[5]]) as usize;
    if !(2..=4).contains(&revision) || acl_size < ACL_HEADER_BYTES { return Some(STATUS_INVALID_PARAMETER); }
    let index = call.args.a1 as usize;
    if index >= ace_count { return Some(STATUS_INVALID_PARAMETER); }
    let mut offsets = vec![0usize; ace_count + 1];
    let mut offset = ACL_HEADER_BYTES;
    for slot in offsets.iter_mut().take(ace_count) {
        *slot = offset;
        let mut ace_header = [0u8; ACE_HEADER_BYTES];
        if offset.checked_add(ACE_HEADER_BYTES).filter(|end| *end <= acl_size).is_none()
            || uaccess::copy_from_user(&mut ace_header, call.args.a0 + offset as u64).is_err() {
            return Some(STATUS_INVALID_PARAMETER);
        }
        let ace_size = u16::from_le_bytes([ace_header[2], ace_header[3]]) as usize;
        if ace_size < ACE_HEADER_BYTES || offset.checked_add(ace_size).filter(|end| *end <= acl_size).is_none() { return Some(STATUS_INVALID_PARAMETER); }
        offset += ace_size;
    }
    offsets[ace_count] = offset;
    let deleted_end = offsets[index + 1];
    let tail_len = offset - deleted_end;
    let mut tail = vec![0u8; tail_len];
    if tail_len != 0 && uaccess::copy_from_user(&mut tail, call.args.a0 + deleted_end as u64).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    if tail_len != 0 && uaccess::copy_to_user(call.args.a0 + offsets[index] as u64, &tail).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    header[4..6].copy_from_slice(&((ace_count - 1) as u16).to_le_bytes());
    if uaccess::copy_to_user(call.args.a0, &header).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_SUCCESS)
}
