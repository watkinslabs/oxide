//! Process API-set namespace query boundary for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const UNICODE_STRING_BYTES: usize = 16;
const TEB_PEB_OFFSET: u64 = 0x60;
const PEB_API_SET_OFFSET: u64 = 0x68;
const API_SET_HEADER_BYTES: u64 = 28;
const API_SET_ENTRY_BYTES: u64 = 24;
const API_SET_VALUE_BYTES: u64 = 20;

/// Report whether a name belongs to the process API-set schema.
/// # C: O(name length) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::ApiSetQueryApiSetPresenceEx { return None; }
    if call.args.a0 == 0 || call.args.a1 == 0 || call.args.a2 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut descriptor, call.args.a0).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    let length = u16::from_le_bytes([descriptor[0], descriptor[1]]) as usize;
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    if length == 0 || length & 1 != 0 || buffer == 0 || length > 1024 { return Some(STATUS_INVALID_PARAMETER); }
    let mut wide = Vec::new(); wide.resize(length, 0);
    if uaccess::copy_from_user(&mut wide, buffer).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    for pair in wide.chunks_exact(2) {
        if u16::from_le_bytes([pair[0], pair[1]]) == b'.' as u16 { return Some(STATUS_INVALID_PARAMETER); }
    }
    let Some(task) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !task.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let Some(peb) = uaccess::get_user_u64(task.nt_teb().checked_add(TEB_PEB_OFFSET).unwrap_or(0)).ok() else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(map) = uaccess::get_user_u64(peb.checked_add(PEB_API_SET_OFFSET).unwrap_or(0)).ok() else { return Some(STATUS_INVALID_PARAMETER); };
    let Some((in_schema, present)) = lookup(map, &wide) else { return Some(STATUS_INVALID_PARAMETER); };
    if uaccess::copy_to_user(call.args.a1, &[in_schema as u8]).is_err() || uaccess::copy_to_user(call.args.a2, &[present as u8]).is_err() {
        return Some(STATUS_INVALID_PARAMETER);
    }
    Some(STATUS_SUCCESS)
}

fn lookup(map: u64, name: &[u8]) -> Option<(bool, bool)> {
    let version = uaccess::get_user_u32(map).ok()?;
    let size = uaccess::get_user_u32(map.checked_add(4)?).ok()? as u64;
    let count = uaccess::get_user_u32(map.checked_add(12)?).ok()? as u64;
    let entries = uaccess::get_user_u32(map.checked_add(16)?).ok()? as u64;
    if version != 6 || count == 0 || count > 128 || size < API_SET_HEADER_BYTES || entries < API_SET_HEADER_BYTES { return None; }
    for index in 0..count {
        let entry = map.checked_add(entries)?.checked_add(index.checked_mul(API_SET_ENTRY_BYTES)?)?;
        let name_offset = uaccess::get_user_u32(entry.checked_add(4)?).ok()? as u64;
        let name_length = uaccess::get_user_u32(entry.checked_add(8)?).ok()? as usize;
        let values = uaccess::get_user_u32(entry.checked_add(16)?).ok()? as u64;
        let value_count = uaccess::get_user_u32(entry.checked_add(20)?).ok()? as u64;
        if name_length == 0 || name_length > 1024 || name_length & 1 != 0 || value_count == 0 || value_count > 16 { continue; }
        let mut candidate = vec![0u8; name_length];
        if uaccess::copy_from_user(&mut candidate, map.checked_add(name_offset)?).is_err() { return None; }
        if candidate.eq_ignore_ascii_case(name) {
            let value = map.checked_add(values)?;
            let value_offset = uaccess::get_user_u32(value.checked_add(12)?).ok()?;
            return Some((true, value_offset != 0));
        }
    }
    Some((false, false))
}
