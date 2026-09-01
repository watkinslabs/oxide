//! Baseline self-relative security descriptors for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use alloc::{vec, vec::Vec};
use syscall::{nt::{NtCall, NtObjectCall}, SyscallArgs};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const READ_CONTROL: u32 = 0x0002_0000;
const OWNER: u32 = 0x0000_0001;
const GROUP: u32 = 0x0000_0002;
const DACL: u32 = 0x0000_0004;
const SACL: u32 = 0x0000_0008;
const LABEL: u32 = 0x0000_0010;
const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
const SELF_RELATIVE: u16 = 0x8000;
const DACL_PRESENT: u16 = 0x0004;
const DACL_DEFAULTED: u16 = 0x0008;
const SACL_PRESENT: u16 = 0x0010;
const SACL_DEFAULTED: u16 = 0x0020;
const FULL_ACCESS: u32 = 0x001f_01ff;
const TOKEN_QUERY: u32 = 0x0008;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u32 = 0x11;
const SYSTEM_MANDATORY_LABEL_VALID_MASK: u32 = 0x7;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const STATUS_UNKNOWN_REVISION: u64 = 0xc000_005a;
const STATUS_INVALID_SECURITY_DESCR: u64 = 0xc000_0079;
const DACL_OFFSET: u64 = 16;
const ABSOLUTE_DACL_OFFSET: u64 = 32;
const SACL_OFFSET: u64 = 12;
const ABSOLUTE_SACL_OFFSET: u64 = 24;
const ABSOLUTE_GROUP_OFFSET: u64 = 16;
const RELATIVE_GROUP_OFFSET: u64 = 8;
const ABSOLUTE_OWNER_OFFSET: u64 = 4;
const RELATIVE_OWNER_OFFSET: u64 = 4;
const OWNER_DEFAULTED: u16 = 0x0001;
const GROUP_DEFAULTED: u16 = 0x0002;
const CONTROL_IMMUTABLE: u32 = OWNER_DEFAULTED as u32 | GROUP_DEFAULTED as u32 | DACL_PRESENT as u32 | 0x0008 | SACL_PRESENT as u32 | SACL_DEFAULTED as u32 | 0x4000 | SELF_RELATIVE as u32;
const SECURITY_CONTROL_WORD_BYTES: usize = 4;

/// Query the stable baseline descriptor attached to an NT object handle.
/// Linux credentials supply the owner/group identity; no Linux syscall path
/// reaches this adapter. # C: O(1) plus usercopy
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == syscall::nt::NtService::RtlSetDaclSecurityDescriptor {
        return Some(set_dacl(call.args.a0, call.args.a1 != 0, call.args.a2, call.args.a3 != 0));
    }
    if call.service == syscall::nt::NtService::RtlSetControlSecurityDescriptor {
        return Some(set_control(call.args.a0, call.args.a1 as u32, call.args.a2 as u32));
    }
    if call.service == syscall::nt::NtService::RtlNewSecurityObject {
        return Some(new_security_object(call.args.a2));
    }
    if call.service == syscall::nt::NtService::RtlNewSecurityObjectEx {
        return Some(new_security_object(call.args.a2));
    }
    if call.service == syscall::nt::NtService::RtlNewSecurityObjectWithMultipleInheritance {
        return Some(new_security_object(call.args.a2));
    }
    if call.service == syscall::nt::NtService::RtlMapGenericMask {
        return Some(map_generic_mask(call.args.a0, call.args.a1));
    }
    if call.service == syscall::nt::NtService::RtlGetDaclSecurityDescriptor {
        return Some(get_dacl(call.args.a0, call.args.a1, call.args.a2, call.args.a3));
    }
    if call.service == syscall::nt::NtService::RtlGetGroupSecurityDescriptor {
        return Some(get_group(call.args.a0, call.args.a1, call.args.a2));
    }
    if call.service == syscall::nt::NtService::RtlGetOwnerSecurityDescriptor {
        return Some(get_owner(call.args.a0, call.args.a1, call.args.a2));
    }
    if call.service == syscall::nt::NtService::RtlGetSaclSecurityDescriptor {
        return Some(get_sacl(call.args.a0, call.args.a1, call.args.a2, call.args.a3));
    }
    if call.service == syscall::nt::NtService::RtlDeleteSecurityObject {
        if call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let descriptor = uaccess::get_user_u64(call.args.a0).unwrap_or(0);
        if descriptor != 0 {
            let _ = crate::nt_heap::dispatch(NtCall { service: syscall::nt::NtService::FreeHeap,
                args: SyscallArgs { a0: 1, a1: 0, a2: descriptor, a3: 0, a4: 0, a5: 0 } });
        }
        return Some(STATUS_SUCCESS);
    }
    if call.service == syscall::nt::NtService::RtlAddMandatoryAce {
        if call.args.a0 == 0 || call.args.a5 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        if call.args.a4 as u32 != SYSTEM_MANDATORY_LABEL_ACE_TYPE
            || (call.args.a3 as u32 & !SYSTEM_MANDATORY_LABEL_VALID_MASK) != 0 {
            return Some(STATUS_INVALID_PARAMETER);
        }
        // The security descriptor owner is not yet an NT self-relative ACL
        // mutator, so do not claim insertion succeeded.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == syscall::nt::NtService::NtAccessCheck { return Some(access_check(call)); }
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

fn set_dacl(descriptor: u64, present: bool, dacl: u64, defaulted: bool) -> u64 {
    if descriptor == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; 4];
    if uaccess::copy_from_user(&mut header, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    if header[0] != SECURITY_DESCRIPTOR_REVISION { return STATUS_UNKNOWN_REVISION; }
    let control = u16::from_le_bytes([header[2], header[3]]);
    if control & SELF_RELATIVE != 0 { return STATUS_INVALID_SECURITY_DESCR; }
    if !present {
        let updated = control & !DACL_PRESENT;
        if uaccess::copy_to_user(descriptor.saturating_add(2), &updated.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
        return STATUS_SUCCESS;
    }
    if uaccess::put_user_u64(descriptor.saturating_add(ABSOLUTE_DACL_OFFSET), dacl).is_err() { return STATUS_INVALID_PARAMETER; }
    let updated = if defaulted { control | DACL_PRESENT | DACL_DEFAULTED } else { (control | DACL_PRESENT) & !DACL_DEFAULTED };
    if uaccess::copy_to_user(descriptor.saturating_add(2), &updated.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn set_control(descriptor: u64, interest: u32, set: u32) -> u64 {
    if descriptor == 0 || !uaccess::access_ok(descriptor, SECURITY_CONTROL_WORD_BYTES) || descriptor & 3 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if (interest | set) & CONTROL_IMMUTABLE != 0 { return STATUS_INVALID_PARAMETER; }
    loop {
        let Ok(old) = uaccess::get_user_u32(descriptor) else { return STATUS_INVALID_PARAMETER; };
        let control = (old >> 16) as u16;
        let interest = interest as u16;
        let set = set as u16;
        let updated = (control | (interest & set)) & !(interest & !set);
        let next = (old & 0x0000_ffff) | (updated as u32) << 16;
        match uaccess::cmpxchg_user_u32(descriptor, old, next) {
            Ok(seen) if seen == old => return STATUS_SUCCESS,
            Ok(_) => continue,
            Err(_) => return STATUS_INVALID_PARAMETER,
        }
    }
}

fn new_security_object(output: u64) -> u64 {
    if output == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let uid = cur.security.creds.euid.load(core::sync::atomic::Ordering::Acquire);
    let gid = cur.security.creds.egid.load(core::sync::atomic::Ordering::Acquire);
    let bytes = descriptor_bytes(OWNER | GROUP | DACL, uid, gid);
    let allocation = crate::nt_heap::dispatch(NtCall { service: syscall::nt::NtService::AllocateHeap,
        args: SyscallArgs { a0: 1, a1: 0, a2: bytes.len() as u64, a3: 0, a4: 0, a5: 0 } });
    let Some(descriptor) = allocation.filter(|address| *address != 0) else { return STATUS_NO_MEMORY; };
    if uaccess::copy_to_user(descriptor, &bytes).is_err() || uaccess::put_user_u64(output, descriptor).is_err() {
        let _ = crate::nt_heap::dispatch(NtCall { service: syscall::nt::NtService::FreeHeap,
            args: SyscallArgs { a0: 1, a1: 0, a2: descriptor, a3: 0, a4: 0, a5: 0 } });
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}

fn get_group(descriptor: u64, target_group: u64, defaulted: u64) -> u64 {
    if descriptor == 0 || target_group == 0 || defaulted == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; 4];
    if uaccess::copy_from_user(&mut header, descriptor).is_err() || header[0] != SECURITY_DESCRIPTOR_REVISION { return STATUS_INVALID_PARAMETER; }
    let control = u16::from_le_bytes([header[2], header[3]]);
    let group_ptr = if control & SELF_RELATIVE != 0 {
        let Some(offset) = uaccess::get_user_u32(descriptor.saturating_add(RELATIVE_GROUP_OFFSET)).ok() else { return STATUS_INVALID_PARAMETER; };
        if offset == 0 { 0 } else { descriptor.saturating_add(offset as u64) }
    } else { uaccess::get_user_u64(descriptor.saturating_add(ABSOLUTE_GROUP_OFFSET)).ok().unwrap_or(0) };
    if uaccess::put_user_u64(target_group, group_ptr).is_err() || uaccess::copy_to_user(defaulted, &[(control & GROUP_DEFAULTED != 0) as u8]).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn get_owner(descriptor: u64, target_owner: u64, defaulted: u64) -> u64 {
    if descriptor == 0 || target_owner == 0 || defaulted == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; 4];
    if uaccess::copy_from_user(&mut header, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    let control = u16::from_le_bytes([header[2], header[3]]);
    let owner = if control & SELF_RELATIVE != 0 {
        let Some(offset) = uaccess::get_user_u32(descriptor.saturating_add(RELATIVE_OWNER_OFFSET)).ok() else { return STATUS_INVALID_PARAMETER; };
        if offset == 0 { 0 } else { descriptor.saturating_add(offset as u64) }
    } else { uaccess::get_user_u64(descriptor.saturating_add(ABSOLUTE_OWNER_OFFSET)).ok().unwrap_or(0) };
    if uaccess::put_user_u64(target_owner, owner).is_err()
        || uaccess::copy_to_user(defaulted, &[(control & OWNER_DEFAULTED != 0) as u8]).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn get_sacl(descriptor: u64, present: u64, target_sacl: u64, defaulted: u64) -> u64 {
    if descriptor == 0 || present == 0 || target_sacl == 0 || defaulted == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; 4];
    if uaccess::copy_from_user(&mut header, descriptor).is_err() || header[0] != SECURITY_DESCRIPTOR_REVISION { return STATUS_UNKNOWN_REVISION; }
    let control = u16::from_le_bytes([header[2], header[3]]);
    let is_present = control & SACL_PRESENT != 0;
    if uaccess::copy_to_user(present, &[is_present as u8]).is_err() { return STATUS_INVALID_PARAMETER; }
    if !is_present { return STATUS_SUCCESS; }
    let sacl = if control & SELF_RELATIVE != 0 {
        let Some(offset) = uaccess::get_user_u32(descriptor.saturating_add(SACL_OFFSET)).ok() else { return STATUS_INVALID_PARAMETER; };
        if offset == 0 { 0 } else { descriptor.saturating_add(offset as u64) }
    } else { uaccess::get_user_u64(descriptor.saturating_add(ABSOLUTE_SACL_OFFSET)).ok().unwrap_or(0) };
    if uaccess::put_user_u64(target_sacl, sacl).is_err()
        || uaccess::copy_to_user(defaulted, &[(control & SACL_DEFAULTED != 0) as u8]).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn get_dacl(descriptor: u64, present: u64, dacl: u64, defaulted: u64) -> u64 {
    if descriptor == 0 || present == 0 || dacl == 0 || defaulted == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; 4];
    if uaccess::copy_from_user(&mut header, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    if header[0] != SECURITY_DESCRIPTOR_REVISION { return STATUS_UNKNOWN_REVISION; }
    let control = u16::from_le_bytes([header[2], header[3]]);
    let (is_present, acl) = if control & SELF_RELATIVE != 0 {
        let mut offset = [0u8; 4];
        if uaccess::copy_from_user(&mut offset, descriptor.saturating_add(DACL_OFFSET)).is_err() { return STATUS_INVALID_PARAMETER; }
        let offset = u32::from_le_bytes(offset) as u64;
        (control & DACL_PRESENT != 0, if offset == 0 { 0 } else { descriptor.saturating_add(offset) })
    } else {
        let mut pointer = [0u8; 8];
        if uaccess::copy_from_user(&mut pointer, descriptor.saturating_add(ABSOLUTE_DACL_OFFSET)).is_err() { return STATUS_INVALID_PARAMETER; }
        (control & DACL_PRESENT != 0, u64::from_le_bytes(pointer))
    };
    let defaulted_value = is_present && control & 0x0400 != 0;
    if uaccess::copy_to_user(present, &[is_present as u8]).is_err()
        || uaccess::put_user_u64(dacl, acl).is_err()
        || uaccess::copy_to_user(defaulted, &[defaulted_value as u8]).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn access_check(call: NtCall) -> u64 {
    const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
    const PRIVILEGE_SET_BYTES: u32 = 20;
    if call.args.a0 == 0 || call.args.a1 == 0 || call.args.a3 == 0 || call.args.a4 == 0 || call.args.a5 == 0 { return STATUS_ACCESS_VIOLATION; }
    let Some(granted) = crate::nt_dispatch::stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
    let Some(access_status) = crate::nt_dispatch::stack_argument(7) else { return STATUS_INVALID_PARAMETER; };
    if granted == 0 || access_status == 0 { return STATUS_ACCESS_VIOLATION; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let token_handle = sched::nt_object::NtHandle::from_raw(call.args.a1 as u32);
    let Some(token_object) = table.get(token_handle, TOKEN_QUERY) else { return if table.contains(token_handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
    let Some(token) = token_object.token() else { return STATUS_INVALID_HANDLE; };
    let mut descriptor = [0u8; 20];
    if uaccess::copy_from_user(&mut descriptor, call.args.a0).is_err() || descriptor[0] != SECURITY_DESCRIPTOR_REVISION { return STATUS_ACCESS_VIOLATION; }
    let control = u16::from_le_bytes([descriptor[2], descriptor[3]]);
    if control & SELF_RELATIVE == 0 { return STATUS_ACCESS_VIOLATION; }
    let capacity = uaccess::get_user_u32(call.args.a5).unwrap_or(0);
    if uaccess::put_user_u32(call.args.a5, PRIVILEGE_SET_BYTES).is_err() { return STATUS_ACCESS_VIOLATION; }
    if capacity < PRIVILEGE_SET_BYTES { return 0xc000_0023; }
    if uaccess::copy_to_user(call.args.a4, &[0u8; PRIVILEGE_SET_BYTES as usize]).is_err() { return STATUS_ACCESS_VIOLATION; }
    let mut desired = call.args.a2 as u32;
    let Some(mapping) = read_mapping(call.args.a3) else { return STATUS_ACCESS_VIOLATION; };
    desired = map_generic(desired, mapping);
    let dacl = u32::from_le_bytes(descriptor[16..20].try_into().unwrap());
    let allowed = if control & DACL_PRESENT == 0 || dacl == 0 { desired } else { acl_access(call.args.a0, dacl, desired, token.uid(), token.gid()) };
    if uaccess::put_user_u32(granted, allowed).is_err() || uaccess::put_user_u32(access_status, if allowed == desired { STATUS_SUCCESS as u32 } else { STATUS_ACCESS_DENIED as u32 }).is_err() { return STATUS_ACCESS_VIOLATION; }
    STATUS_SUCCESS
}

fn read_mapping(address: u64) -> Option<[u32; 4]> {
    let mut bytes = [0u8; 16];
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    Some(core::array::from_fn(|index| u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())))
}

fn map_generic(mut desired: u32, mapping: [u32; 4]) -> u32 {
    if desired & GENERIC_READ != 0 { desired = desired & !GENERIC_READ | mapping[0]; }
    if desired & GENERIC_WRITE != 0 { desired = desired & !GENERIC_WRITE | mapping[1]; }
    if desired & GENERIC_EXECUTE != 0 { desired = desired & !GENERIC_EXECUTE | mapping[2]; }
    if desired & GENERIC_ALL != 0 { desired = desired & !GENERIC_ALL | mapping[3]; }
    desired
}

fn map_generic_mask(mask: u64, mapping: u64) -> u64 {
    if mask == 0 || mapping == 0 { return STATUS_INVALID_PARAMETER; }
    let Ok(mut value) = uaccess::get_user_u32(mask) else { return STATUS_INVALID_PARAMETER; };
    let Some(mapping) = read_mapping(mapping) else { return STATUS_INVALID_PARAMETER; };
    value = map_generic(value, mapping);
    if uaccess::put_user_u32(mask, value).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}

fn acl_access(sd: u64, offset: u32, desired: u32, uid: u32, gid: u32) -> u32 {
    let acl = match sd.checked_add(offset as u64) { Some(value) => value, None => return 0 };
    let mut header = [0u8; 8];
    if uaccess::copy_from_user(&mut header, acl).is_err() { return 0; }
    let size = u16::from_le_bytes([header[2], header[3]]) as u64;
    let count = u16::from_le_bytes([header[4], header[5]]).min(256);
    if size < 8 { return 0; }
    let mut granted = 0;
    let mut cursor = acl + 8;
    for _ in 0..count {
        let mut ace = [0u8; 8];
        if cursor.saturating_sub(acl) + 8 > size || uaccess::copy_from_user(&mut ace, cursor).is_err() { return 0; }
        let ace_size = u16::from_le_bytes([ace[2], ace[3]]) as u64;
        if ace_size < 20 || cursor.saturating_sub(acl) + ace_size > size { return 0; }
        let matches = sid_matches(cursor + 8, uid, gid);
        let mask = u32::from_le_bytes(ace[4..8].try_into().unwrap());
        if matches && ace[0] == 1 && mask & desired != 0 { return 0; }
        if matches && ace[0] == 0 { granted |= mask & desired; if granted == desired { return granted; } }
        cursor = match cursor.checked_add(ace_size) { Some(value) => value, None => return 0 };
    }
    granted
}

fn sid_matches(address: u64, uid: u32, gid: u32) -> bool {
    let mut sid = [0u8; 16];
    if uaccess::copy_from_user(&mut sid, address).is_err() || sid[0] != 1 || sid[1] != 2 { return false; }
    let authority = u64::from_be_bytes([0, 0, sid[2], sid[3], sid[4], sid[5], sid[6], sid[7]]);
    let subauthority = u32::from_le_bytes(sid[12..16].try_into().unwrap());
    (authority == 5 && (subauthority == uid || subauthority == gid)) || (authority == 1 && subauthority == 0)
}

fn sid(authority: u64, subauthority: u32) -> [u8; 16] {
    let mut out = [0u8; 16]; out[0] = 1; out[1] = 2;
    let authority = authority.to_be_bytes();
    out[2..8].copy_from_slice(&authority[2..]);
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
