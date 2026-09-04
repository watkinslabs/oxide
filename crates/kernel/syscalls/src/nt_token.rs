//! Native NT token handles over an immutable credential snapshot.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use syscall::nt::{NtCall, NtObjectCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_NOT_ALL_ASSIGNED: u64 = 0x0000_0106;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ADJUST_GROUPS: u32 = 0x0040;
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
const TOKEN_ALL_ACCESS: u32 = 0x000f_01ff;
const CURRENT_PROCESS: u64 = u64::MAX;
const CURRENT_THREAD: u64 = u64::MAX;
const TOKEN_BASIC_INFORMATION: u32 = 0;
const TOKEN_TYPE_INFORMATION: u32 = 8;
const TOKEN_USER: u32 = 1;
const TOKEN_GROUPS: u32 = 2;
const TOKEN_PRIVILEGES: u32 = 3;
const SE_PRIVILEGE_VALID_ATTRIBUTES: u32 = 0x8000_0007;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const TOKEN_DUPLICATE: u32 = 0x0002;
const TOKEN_PRIMARY: u32 = 1;
const TOKEN_IMPERSONATION: u32 = 2;
const STATUS_LUIDS_EXHAUSTED: u64 = 0xc000_0075;
static NEXT_NT_LUID: AtomicU64 = AtomicU64::new(1000);

pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == syscall::nt::NtService::NtFilterToken { return Some(filter_token(call)); }
    if call.service == syscall::nt::NtService::NtSetInformationToken { return Some(set_information(call)); }
    if call.service == syscall::nt::NtService::NtPrivilegeCheck { return Some(privilege_check(call)); }
    if call.service == syscall::nt::NtService::NtAdjustGroupsToken { return Some(adjust_groups(call)); }
    if call.service == syscall::nt::NtService::NtAdjustPrivilegesToken { return Some(adjust_privileges(call)); }
    if call.service == syscall::nt::NtService::NtAllocateLocallyUniqueId { return Some(allocate_luid(call)); }
    let Ok(object_call) = syscall::nt::decode_object(call) else { return None; };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    match object_call {
        NtObjectCall::DuplicateToken { token, access, attributes, effective_only, token_type, handle } => {
            if attributes != 0 || effective_only > 1 || !matches!(token_type, TOKEN_PRIMARY | TOKEN_IMPERSONATION)
                || access & !TOKEN_ALL_ACCESS != 0 { return Some(STATUS_INVALID_PARAMETER); }
            let native = sched::nt_object::NtHandle::from_raw(token);
            let Some(object) = table.get(native, TOKEN_DUPLICATE) else {
                return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE });
            };
            let Some(token) = object.token() else { return Some(STATUS_INVALID_HANDLE); };
            let Some(new_handle) = table.insert(table.duplicate_token(token), access) else { return Some(STATUS_INVALID_PARAMETER); };
            if uaccess::put_user_u32(handle.as_u64(), new_handle.raw()).is_err() {
                let _ = table.close(new_handle);
                return Some(STATUS_ACCESS_VIOLATION);
            }
            Some(STATUS_SUCCESS)
        }
        NtObjectCall::OpenProcessToken { process, desired_access, handle } => {
            if process != CURRENT_PROCESS || desired_access & !TOKEN_ALL_ACCESS != 0 { return Some(STATUS_INVALID_PARAMETER); }
            insert_token(&cur, desired_access, handle, &table)
        }
        NtObjectCall::OpenThreadToken { thread, desired_access, open_as_self, handle } => {
            if thread != CURRENT_THREAD || open_as_self > 1 || desired_access & !TOKEN_ALL_ACCESS != 0 { return Some(STATUS_INVALID_PARAMETER); }
            insert_token(&cur, desired_access, handle, &table)
        }
        NtObjectCall::QueryToken { token, class, info, length, return_length } => {
            let native = sched::nt_object::NtHandle::from_raw(token);
            let Some(object) = table.get(native, TOKEN_QUERY) else { return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }); };
            let Some(token) = object.token() else { return Some(STATUS_INVALID_HANDLE); };
            let (bytes, required) = match class {
                TOKEN_BASIC_INFORMATION => { let mut bytes = [0u8; 8]; bytes[..4].copy_from_slice(&token.uid().to_ne_bytes()); bytes[4..].copy_from_slice(&token.gid().to_ne_bytes()); (bytes.to_vec(), 8) }
                TOKEN_TYPE_INFORMATION => (1u32.to_ne_bytes().to_vec(), 4),
                TOKEN_USER | TOKEN_GROUPS | TOKEN_PRIVILEGES => {
                    let base = info.map(|ptr| ptr.as_u64()).unwrap_or(0);
                    let Some(bytes) = token.query_bytes(class, base) else { return Some(STATUS_INVALID_PARAMETER); };
                    let required = bytes.len() as u32;
                    (bytes, required)
                }
                _ => return Some(STATUS_INVALID_PARAMETER),
            };
            if let Some(return_length) = return_length { if uaccess::put_user_u32(return_length.as_u64(), required).is_err() { return Some(STATUS_INVALID_PARAMETER); } }
            if length < required { return Some(STATUS_BUFFER_TOO_SMALL); }
            let Some(info) = info else { return Some(STATUS_ACCESS_VIOLATION); };
            if uaccess::copy_to_user(info.as_u64(), &bytes).is_err() { return Some(STATUS_ACCESS_VIOLATION); }
            Some(STATUS_SUCCESS)
        }
        _ => None,
    }
}

fn filter_token(call: NtCall) -> u64 {
    if call.args.a0 > u32::MAX as u64 || call.args.a1 != 0 || call.args.a5 == 0 || call.args.a4 != 0 {
        return STATUS_NOT_IMPLEMENTED;
    }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let source = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let Some(object) = table.get(source, TOKEN_DUPLICATE) else {
        return if table.contains(source) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(token) = object.token() else { return STATUS_INVALID_HANDLE; };
    let disabled_sids = if call.args.a2 == 0 { Vec::new() } else {
        let Some(groups) = read_groups(call.args.a2, u64::MAX) else { return STATUS_INVALID_PARAMETER; };
        groups.into_iter().map(|group| group.sid).collect()
    };
    let disabled_privileges = if call.args.a3 == 0 { Vec::new() } else {
        let Some(privileges) = read_privileges(call.args.a3, u64::MAX) else { return STATUS_INVALID_PARAMETER; };
        privileges
    };
    let filtered = token.filtered(&disabled_sids, &disabled_privileges);
    let Some(new_handle) = table.insert(table.duplicate_token(alloc::sync::Arc::new(filtered)), TOKEN_ALL_ACCESS) else {
        return STATUS_INVALID_PARAMETER;
    };
    if uaccess::put_user_u32(call.args.a5, new_handle.raw()).is_err() {
        let _ = table.close(new_handle);
        return STATUS_ACCESS_VIOLATION;
    }
    STATUS_SUCCESS
}

fn set_information(call: NtCall) -> u64 {
    const TOKEN_DEFAULT_DACL: u32 = 6;
    const TOKEN_SESSION_ID: u32 = 12;
    const TOKEN_INTEGRITY_LEVEL: u32 = 25;
    if call.args.a0 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let class = call.args.a1 as u32;
    let required = match class { TOKEN_DEFAULT_DACL => 8, TOKEN_SESSION_ID => 4, TOKEN_INTEGRITY_LEVEL => 0, _ => return STATUS_NOT_IMPLEMENTED };
    if call.args.a3 < required { return STATUS_BUFFER_TOO_SMALL; }
    if required != 0 && call.args.a2 == 0 { return STATUS_ACCESS_VIOLATION; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let Some(object) = table.get(handle, if class == TOKEN_SESSION_ID { TOKEN_ADJUST_DEFAULT } else { 0 }) else {
        return if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(token) = object.token() else { return STATUS_INVALID_HANDLE; };
    match class {
        TOKEN_SESSION_ID => {
            let value = match uaccess::get_user_u32(call.args.a2) { Ok(value) => value, Err(_) => return STATUS_ACCESS_VIOLATION };
            token.set_session_id(value);
            STATUS_SUCCESS
        }
        TOKEN_INTEGRITY_LEVEL => STATUS_NOT_IMPLEMENTED,
        TOKEN_DEFAULT_DACL => STATUS_NOT_IMPLEMENTED,
        _ => STATUS_NOT_IMPLEMENTED,
    }
}

fn privilege_check(call: NtCall) -> u64 {
    const PRIVILEGE_SET_ALL_NECESSARY: u32 = 1;
    const SE_PRIVILEGE_ENABLED: u32 = 2;
    if call.args.a0 > u32::MAX as u64 || call.args.a1 == 0 || call.args.a2 == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let Some(object) = table.get(handle, TOKEN_QUERY) else { return if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
    let Some(token) = object.token() else { return STATUS_INVALID_HANDLE; };
    let count = match uaccess::get_user_u32(call.args.a1) { Ok(value) if value <= 64 => value, _ => return STATUS_INVALID_PARAMETER };
    let control_address = match call.args.a1.checked_add(4) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let control = match uaccess::get_user_u32(control_address) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    let privileges = token.privileges();
    let mut matched = 0u32;
    for index in 0..count as u64 {
        let Some(entry) = call.args.a1.checked_add(8).and_then(|base| base.checked_add(index.checked_mul(16)?)) else { return STATUS_INVALID_PARAMETER };
        let luid = match uaccess::get_user_u64(entry) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
        let Some(attributes_address) = entry.checked_add(8) else { return STATUS_INVALID_PARAMETER };
        let attributes = match uaccess::get_user_u32(attributes_address) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
        if privileges.iter().any(|privilege| privilege.luid == luid && privilege.attributes & SE_PRIVILEGE_ENABLED != 0 && attributes & SE_PRIVILEGE_ENABLED != 0) { matched += 1; }
    }
    let has_privileges = if control & PRIVILEGE_SET_ALL_NECESSARY != 0 { matched == count } else { matched != 0 };
    if uaccess::put_user_u32(call.args.a2, has_privileges as u32).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}

fn adjust_groups(call: NtCall) -> u64 {
    if call.args.a0 > u32::MAX as u64 || call.args.a1 > 1 || call.args.a4 != 0 || call.args.a5 != 0 { return STATUS_INVALID_PARAMETER; }
    if call.args.a1 == 0 && (call.args.a2 == 0 || call.args.a3 < 8) { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let Some(object) = table.get(handle, TOKEN_ADJUST_GROUPS) else { return if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
    let Some(token) = object.token() else { return STATUS_INVALID_HANDLE; };
    if call.args.a1 != 0 { token.replace_groups(default_groups(token.gid())); }
    else {
        let Some(groups) = read_groups(call.args.a2, call.args.a3) else { return STATUS_INVALID_PARAMETER; };
        token.replace_groups(groups);
    }
    STATUS_SUCCESS
}

fn read_groups(address: u64, length: u64) -> Option<Vec<sched::nt_object::NtTokenGroup>> {
    let count = uaccess::get_user_u32(address).ok()?;
    if count > 64 || 8u64.checked_add((count as u64).checked_mul(16)?)? > length { return None; }
    let mut groups = Vec::new();
    for index in 0..count as u64 {
        let entry = address.checked_add(8)?.checked_add(index.checked_mul(16)?)?;
        let sid_address = uaccess::get_user_u64(entry).ok()?;
        let attributes = uaccess::get_user_u32(entry.checked_add(8)?).ok()?;
        let mut sid = [0u8; 16];
        if sid_address == 0 || uaccess::copy_from_user(&mut sid, sid_address).is_err() || sid[0] != 1 || sid[1] > 2 { return None; }
        groups.push(sched::nt_object::NtTokenGroup { sid, attributes });
    }
    Some(groups)
}

fn default_groups(gid: u32) -> Vec<sched::nt_object::NtTokenGroup> {
    let mut sid = [0u8; 16]; sid[0] = 1; sid[1] = 2;
    let authority = 5u64.to_be_bytes();
    sid[2..8].copy_from_slice(&authority[2..]); sid[8..12].copy_from_slice(&21u32.to_le_bytes()); sid[12..16].copy_from_slice(&gid.to_le_bytes());
    alloc::vec![sched::nt_object::NtTokenGroup { sid, attributes: 4 }]
}

fn adjust_privileges(call: NtCall) -> u64 {
    if call.args.a0 > u32::MAX as u64 || call.args.a1 > 1 || call.args.a3 > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let disable_all = call.args.a1 != 0;
    if !disable_all && (call.args.a2 == 0 || call.args.a3 < 4) { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let Some(object) = table.get(handle, TOKEN_ADJUST_PRIVILEGES) else { return if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE }; };
    let Some(token) = object.token() else { return STATUS_INVALID_HANDLE; };
    let requested = if disable_all { Vec::new() } else { let Some(privileges) = read_privileges(call.args.a2, call.args.a3) else { return STATUS_INVALID_PARAMETER; }; privileges };
    let previous = token.privileges();
    let required = 4u64.checked_add(previous.len().checked_mul(12).unwrap_or(usize::MAX) as u64).unwrap_or(u64::MAX);
    if call.args.a4 != 0 && (call.args.a3 < required || call.args.a3 > u32::MAX as u64) { return STATUS_BUFFER_TOO_SMALL; }
    if call.args.a4 != 0 {
        if write_privileges(call.args.a4, &previous).is_err() { return STATUS_INVALID_PARAMETER; }
        if call.args.a5 != 0 && uaccess::put_user_u32(call.args.a5, required as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    let (_, all_assigned) = token.adjust_privileges(disable_all, &requested);
    if all_assigned { STATUS_SUCCESS } else { STATUS_NOT_ALL_ASSIGNED }
}

fn read_privileges(address: u64, length: u64) -> Option<Vec<sched::nt_object::NtTokenPrivilege>> {
    let count = uaccess::get_user_u32(address).ok()?;
    if count > 64 || 4u64.checked_add((count as u64).checked_mul(12)?)? > length { return None; }
    let mut privileges = Vec::new();
    for index in 0..count as u64 {
        let entry = address.checked_add(4)?.checked_add(index.checked_mul(12)?)?;
        let luid = uaccess::get_user_u64(entry).ok()?;
        let attributes = uaccess::get_user_u32(entry.checked_add(8)?).ok()?;
        if attributes & !SE_PRIVILEGE_VALID_ATTRIBUTES != 0 { return None; }
        privileges.push(sched::nt_object::NtTokenPrivilege { luid, attributes });
    }
    Some(privileges)
}

fn write_privileges(address: u64, privileges: &[sched::nt_object::NtTokenPrivilege]) -> Result<(), ()> {
    uaccess::put_user_u32(address, privileges.len() as u32).map_err(|_| ())?;
    for (index, privilege) in privileges.iter().enumerate() {
        let entry = address.checked_add(4).and_then(|base| base.checked_add((index as u64).checked_mul(12)?)).ok_or(())?;
        uaccess::put_user_u64(entry, privilege.luid).map_err(|_| ())?;
        uaccess::put_user_u32(entry + 8, privilege.attributes).map_err(|_| ())?;
    }
    Ok(())
}

fn allocate_luid(call: NtCall) -> u64 {
    if call.args.a0 == 0 { return STATUS_ACCESS_VIOLATION; }
    let luid = NEXT_NT_LUID.fetch_add(1, Ordering::Relaxed);
    if luid == u64::MAX { return STATUS_LUIDS_EXHAUSTED; }
    if uaccess::put_user_u64(call.args.a0, luid).is_err() { STATUS_ACCESS_VIOLATION } else { STATUS_SUCCESS }
}

fn insert_token(cur: &sched::Task, access: u32, output: syscall::UserPtr<u32>, table: &sched::nt_object::NtHandleTable) -> Option<u64> {
    let uid = cur.security.creds.euid.load(core::sync::atomic::Ordering::Acquire);
    let gid = cur.security.creds.egid.load(core::sync::atomic::Ordering::Acquire);
    let object = table.new_token(uid, gid);
    let Some(token) = object.token() else { return Some(STATUS_INVALID_PARAMETER); };
    token.add_privilege(sched::nt_object::NtTokenPrivilege { luid: 23, attributes: 3 });
    let mut groups = token.groups();
    if let Some(extra) = cur.security.creds.group_list() {
        groups.extend(extra.iter().copied().map(|gid| sched::nt_object::NtTokenGroup {
            sid: sched::nt_object::sid_for_id(gid), attributes: 4,
        }));
    }
    token.replace_groups(groups);
    let Some(handle) = table.insert(object, access) else { return Some(STATUS_INVALID_PARAMETER); };
    if uaccess::put_user_u32(output.as_u64(), handle.raw()).is_err() { let _ = table.close(handle); return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_SUCCESS)
}
