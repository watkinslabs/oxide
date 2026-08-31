//! Native NT token handles over an immutable credential snapshot.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ALL_ACCESS: u32 = 0x000f_01ff;
const CURRENT_PROCESS: u64 = u64::MAX;
const CURRENT_THREAD: u64 = u64::MAX;
const TOKEN_BASIC_INFORMATION: u32 = 0;
const TOKEN_TYPE_INFORMATION: u32 = 8;

pub fn dispatch(call: NtCall) -> Option<u64> {
    let Ok(object_call) = syscall::nt::decode_object(call) else { return None; };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    match object_call {
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
                _ => return Some(STATUS_INVALID_PARAMETER),
            };
            if length < required { return Some(STATUS_INVALID_PARAMETER); }
            if uaccess::copy_to_user(info.as_u64(), &bytes).is_err() { return Some(STATUS_INVALID_PARAMETER); }
            if let Some(return_length) = return_length { if uaccess::put_user_u32(return_length.as_u64(), required).is_err() { return Some(STATUS_INVALID_PARAMETER); } }
            Some(STATUS_SUCCESS)
        }
        _ => None,
    }
}

fn insert_token(cur: &sched::Task, access: u32, output: syscall::UserPtr<u32>, table: &sched::nt_object::NtHandleTable) -> Option<u64> {
    let uid = cur.security.creds.euid.load(core::sync::atomic::Ordering::Acquire);
    let gid = cur.security.creds.egid.load(core::sync::atomic::Ordering::Acquire);
    let Some(handle) = table.insert(table.new_token(uid, gid), access) else { return Some(STATUS_INVALID_PARAMETER); };
    if uaccess::put_user_u32(output.as_u64(), handle.raw()).is_err() { let _ = table.close(handle); return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_SUCCESS)
}
