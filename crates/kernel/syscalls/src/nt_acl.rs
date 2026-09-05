//! Native ACL mutation boundary for the Windows personality.
#![cfg(target_os = "oxide-kernel")]
use alloc::vec;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_SID: u64 = 0xc000_0078;
const STATUS_INVALID_ACL: u64 = 0xc000_0077;
const STATUS_REVISION_MISMATCH: u64 = 0xc000_0059;
const STATUS_ALLOTTED_SPACE_EXCEEDED: u64 = 0xc000_0099;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const ACL_HEADER_BYTES: usize = 8;
const ACE_HEADER_BYTES: usize = 4;
const SID_MAX_SUBAUTHORITIES: u8 = 15;
const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u64 = 0x11;
const SYSTEM_MANDATORY_LABEL_VALID_MASK: u64 = 0x7;

/// Delete one variable-sized ACE while preserving the caller-owned ACL.
/// # C: O(acl bytes)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlValidAcl { return Some(valid_acl(call.args.a0)); }
    if call.service == NtService::RtlFirstFreeAce {
        return Some(first_free_ace(call.args.a0, call.args.a1));
    }
    if call.service == NtService::RtlAddMandatoryAce {
        return Some(add_mandatory_ace(call.args.a0, call.args.a1, call.args.a2,
            call.args.a3, call.args.a4, call.args.a5));
    }
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

fn add_mandatory_ace(acl: u64, revision: u64, flags: u64, mask: u64, kind: u64, sid: u64) -> u64 {
    if acl == 0 || sid == 0 || kind != SYSTEM_MANDATORY_LABEL_ACE_TYPE
        || flags > u8::MAX as u64 || mask & !SYSTEM_MANDATORY_LABEL_VALID_MASK != 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; ACL_HEADER_BYTES];
    if uaccess::copy_from_user(&mut header, acl).is_err() { return STATUS_INVALID_ACL; }
    let acl_revision = header[0];
    let acl_size = u16::from_le_bytes([header[2], header[3]]) as usize;
    let ace_count = u16::from_le_bytes([header[4], header[5]]) as usize;
    if !(2..=4).contains(&acl_revision) || revision > 4 || revision < 2 { return STATUS_REVISION_MISMATCH; }
    if acl_size < ACL_HEADER_BYTES { return STATUS_INVALID_ACL; }
    let mut sid_header = [0u8; 2];
    if uaccess::copy_from_user(&mut sid_header, sid).is_err()
        || sid_header[0] != 1 || sid_header[1] > SID_MAX_SUBAUTHORITIES { return STATUS_INVALID_SID; }
    let sid_size = 8usize.checked_add(sid_header[1] as usize * 4).unwrap_or(usize::MAX);
    let mut cursor = ACL_HEADER_BYTES;
    for _ in 0..ace_count {
        let Some(end) = cursor.checked_add(ACE_HEADER_BYTES) else { return STATUS_INVALID_ACL; };
        if end > acl_size { return STATUS_INVALID_ACL; }
        let mut ace_header = [0u8; ACE_HEADER_BYTES];
        if uaccess::copy_from_user(&mut ace_header, acl + cursor as u64).is_err() { return STATUS_INVALID_ACL; }
        let size = u16::from_le_bytes([ace_header[2], ace_header[3]]) as usize;
        if size < ACE_HEADER_BYTES || cursor.checked_add(size).is_none_or(|end| end > acl_size) { return STATUS_INVALID_ACL; }
        cursor += size;
    }
    let ace_size = ACE_HEADER_BYTES + 4 + sid_size;
    if cursor.checked_add(ace_size).is_none_or(|end| end > acl_size) { return STATUS_ALLOTTED_SPACE_EXCEEDED; }
    let mut ace = vec![0u8; ace_size];
    ace[0] = SYSTEM_MANDATORY_LABEL_ACE_TYPE as u8;
    ace[1] = flags as u8;
    ace[2..4].copy_from_slice(&(ace_size as u16).to_le_bytes());
    ace[4..8].copy_from_slice(&(mask as u32).to_le_bytes());
    if uaccess::copy_from_user(&mut ace[8..], sid).is_err()
        || uaccess::copy_to_user(acl + cursor as u64, &ace).is_err() { return STATUS_ACCESS_VIOLATION; }
    header[0] = acl_revision.max(revision as u8);
    header[4..6].copy_from_slice(&((ace_count + 1) as u16).to_le_bytes());
    if uaccess::copy_to_user(acl, &header).is_err() { return STATUS_INVALID_ACL; }
    STATUS_SUCCESS
}

fn valid_acl(acl: u64) -> u64 {
    if acl == 0 { return 0; }
    let mut header = [0u8; ACL_HEADER_BYTES];
    if uaccess::copy_from_user(&mut header, acl).is_err() { return 0; }
    if !(2..=4).contains(&header[0]) { return 0; }
    let size = u16::from_le_bytes([header[2], header[3]]) as u64;
    let count = u16::from_le_bytes([header[4], header[5]]) as usize;
    let Some(end) = acl.checked_add(size) else { return 0; };
    let Some(mut ace) = acl.checked_add(ACL_HEADER_BYTES as u64) else { return 0; };
    for index in 0..=count {
        if ace > end { return 0; }
        if index == count { break; }
        if ace.checked_add(ACE_HEADER_BYTES as u64).is_none_or(|next| next > end) { return 0; }
        let mut ace_header = [0u8; ACE_HEADER_BYTES];
        if uaccess::copy_from_user(&mut ace_header, ace).is_err() { return 0; }
        let ace_size = u16::from_le_bytes([ace_header[2], ace_header[3]]) as u64;
        let Some(next) = ace.checked_add(ace_size) else { return 0; };
        if next > end { return 0; }
        ace = next;
    }
    1
}

fn first_free_ace(acl: u64, output: u64) -> u64 {
    if acl == 0 || output == 0 { return 0; }
    let mut header = [0u8; ACL_HEADER_BYTES];
    if uaccess::copy_from_user(&mut header, acl).is_err() { return 0; }
    let acl_size = u16::from_le_bytes([header[2], header[3]]) as u64;
    let ace_count = u16::from_le_bytes([header[4], header[5]]) as usize;
    if acl_size < ACL_HEADER_BYTES as u64 { return 0; }
    let end = match acl.checked_add(acl_size) { Some(end) => end, None => return 0 };
    let mut ace = match acl.checked_add(ACL_HEADER_BYTES as u64) { Some(ace) => ace, None => return 0 };
    for _ in 0..ace_count {
        if ace.checked_add(ACE_HEADER_BYTES as u64).is_none_or(|next| next > end) { return 0; }
        let mut ace_header = [0u8; ACE_HEADER_BYTES];
        if uaccess::copy_from_user(&mut ace_header, ace).is_err() { return 0; }
        let ace_size = u16::from_le_bytes([ace_header[2], ace_header[3]]) as u64;
        if ace_size < ACE_HEADER_BYTES as u64 || ace.checked_add(ace_size).is_none_or(|next| next > end) { return 0; }
        ace += ace_size;
    }
    if ace > end || uaccess::copy_to_user(output, &ace.to_le_bytes()).is_err() { return 0; }
    1
}
