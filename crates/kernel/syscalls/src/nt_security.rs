//! Baseline self-relative security descriptors for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use alloc::{vec, vec::Vec};
use syscall::nt::{NtCall, NtObjectCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const READ_CONTROL: u32 = 0x0002_0000;
const OWNER: u32 = 0x0000_0001;
const GROUP: u32 = 0x0000_0002;
const DACL: u32 = 0x0000_0004;
const SACL: u32 = 0x0000_0008;
const LABEL: u32 = 0x0000_0010;
const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
const SELF_RELATIVE: u16 = 0x8000;
const DACL_PRESENT: u16 = 0x0004;
const FULL_ACCESS: u32 = 0x001f_01ff;

/// Query the stable baseline descriptor attached to an NT object handle.
/// Linux credentials supply the owner/group identity; no Linux syscall path
/// reaches this adapter. # C: O(1) plus usercopy
pub fn dispatch(call: NtCall) -> Option<u64> {
    let Ok(NtObjectCall::QuerySecurity { handle, security_information, descriptor, length, return_length }) = syscall::nt::decode_object(call) else { return None; };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || security_information == 0 || security_information & !(OWNER | GROUP | DACL | SACL | LABEL) != 0 { return Some(STATUS_INVALID_PARAMETER); }
    if security_information & (SACL | LABEL) != 0 { return Some(STATUS_ACCESS_DENIED); }
    let table = cur.thread_group.nt_handles();
    let native = sched::nt_object::NtHandle::from_raw(handle);
    if table.get(native, READ_CONTROL).is_none() { return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); }
    let uid = cur.security.creds.euid.load(core::sync::atomic::Ordering::Acquire);
    let gid = cur.security.creds.egid.load(core::sync::atomic::Ordering::Acquire);
    let bytes = descriptor_bytes(security_information, uid, gid);
    let required = bytes.len() as u32;
    if let Some(out) = return_length { if uaccess::put_user_u32(out.as_u64(), required).is_err() { return Some(STATUS_INVALID_PARAMETER); } }
    if descriptor.as_u64() == 0 || length < required { return Some(STATUS_BUFFER_TOO_SMALL); }
    if uaccess::copy_to_user(descriptor.as_u64(), &bytes).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_SUCCESS)
}

fn sid(authority: u64, subauthority: u32) -> [u8; 16] {
    let mut out = [0u8; 16]; out[0] = 1; out[1] = 2;
    out[2..8].copy_from_slice(&authority.to_be_bytes());
    out[8..12].copy_from_slice(&21u32.to_le_bytes()); out[12..16].copy_from_slice(&subauthority.to_le_bytes()); out
}

fn descriptor_bytes(info: u32, uid: u32, gid: u32) -> Vec<u8> {
    let owner = if info & OWNER != 0 { Some(sid(5, uid)) } else { None };
    let group = if info & GROUP != 0 { Some(sid(5, gid)) } else { None };
    let dacl = if info & DACL != 0 { Some([2u8, 0, 28, 0, 1, 0, 0, 0, 0, 0, 20, 0, FULL_ACCESS as u8, (FULL_ACCESS >> 8) as u8, (FULL_ACCESS >> 16) as u8, (FULL_ACCESS >> 24) as u8, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) } else { None };
    let mut out = vec![0u8; 20]; let mut offset = 20u32;
    out[0] = SECURITY_DESCRIPTOR_REVISION; let mut control = SELF_RELATIVE;
    if dacl.is_some() { control |= DACL_PRESENT; } out[2..4].copy_from_slice(&control.to_le_bytes());
    for (field, data) in [(4usize, owner.map(|x| x.to_vec())), (8, group.map(|x| x.to_vec())), (16, dacl.map(|x| x.to_vec()))] {
        if let Some(data) = data { out[field..field + 4].copy_from_slice(&offset.to_le_bytes()); out.extend_from_slice(&data); offset += data.len() as u32; }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_offsets_and_acl_sizes_are_self_relative() {
        let bytes = descriptor_bytes(OWNER | GROUP | DACL, 1000, 1001);
        assert_eq!(bytes.len(), 80);
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), SELF_RELATIVE | DACL_PRESENT);
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 20);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 36);
        assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 52);
        assert_eq!(u16::from_le_bytes([bytes[54], bytes[55]]), 28);
        assert_eq!(u16::from_le_bytes([bytes[62], bytes[63]]), 20);
    }
}
