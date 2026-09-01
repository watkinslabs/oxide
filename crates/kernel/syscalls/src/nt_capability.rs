//! Native capability SID derivation for the Windows personality.
#![cfg(target_os = "oxide-kernel")]
use alloc::vec;
use crypt::sha256::sha256;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const UNICODE_STRING_BYTES: usize = 16;
const MAX_NAME_BYTES: usize = 32766;
const SID_REVISION: u8 = 1;
const NT_AUTHORITY: u64 = 5;
const APP_PACKAGE_AUTHORITY: u64 = 15;
const BATCH_RID: u32 = 3;
const BUILTIN_DOMAIN_RID: u32 = 32;
const CAPABILITY_APP_RID: u32 = 0x400;

/// Derive application and group capability SIDs from a caller-owned name.
/// # C: O(name bytes) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlDeriveCapabilitySidsFromName { return None; }
    if call.args.a0 == 0 || call.args.a1 == 0 || call.args.a2 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut descriptor, call.args.a0).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    let length = u16::from_le_bytes([descriptor[0], descriptor[1]]) as usize;
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    if length > MAX_NAME_BYTES || length & 1 != 0 || (length != 0 && buffer == 0) { return Some(STATUS_INVALID_PARAMETER); }
    let mut name = vec![0u8; length];
    if length != 0 && uaccess::copy_from_user(&mut name, buffer).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    for unit in name.chunks_exact_mut(2) {
        let value = u16::from_le_bytes([unit[0], unit[1]]);
        let upper = if (b'a' as u16..=b'z' as u16).contains(&value) { value - 32 } else { value };
        unit.copy_from_slice(&upper.to_le_bytes());
    }
    let hash = sha256(&name);
    let mut cap = [0u8; 48];
    let mut group = [0u8; 44];
    write_sid(&mut cap, APP_PACKAGE_AUTHORITY, &[BATCH_RID, CAPABILITY_APP_RID], &hash);
    write_sid(&mut group, NT_AUTHORITY, &[BUILTIN_DOMAIN_RID], &hash);
    if uaccess::copy_to_user(call.args.a2, &cap).is_err() || uaccess::copy_to_user(call.args.a1, &group).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_SUCCESS)
}

fn write_sid(out: &mut [u8], authority: u64, prefix: &[u32], hash: &[u8; 32]) {
    out[0] = SID_REVISION; out[1] = (prefix.len() + 8) as u8;
    out[2..8].copy_from_slice(&authority.to_be_bytes()[2..]);
    for (index, value) in prefix.iter().enumerate() { out[8 + index * 4..12 + index * 4].copy_from_slice(&value.to_le_bytes()); }
    out[8 + prefix.len() * 4..].copy_from_slice(hash);
}
