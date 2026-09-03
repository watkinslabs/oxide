//! Native NT process/thread handle acquisition for the current NT process.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_INVALID_CID: u64 = 0xc000_000b;
const STATUS_INVALID_INFO_CLASS: u64 = 0xc000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
pub(crate) const PROCESS_ALL_ACCESS: u32 = 0x001f_0fff;
pub(crate) const THREAD_ALL_ACCESS: u32 = 0x001f_03ff;
pub(crate) const SYNCHRONIZE: u32 = 0x0010_0000;
const PROCESS_QUERY_INFORMATION: u32 = 0x0000_0400;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x0000_1000;
const PROCESS_TERMINATE: u32 = 0x0000_0001;
pub(crate) const PROCESS_CREATE_THREAD: u32 = 0x0000_0002;
pub(crate) const PROCESS_VM_OPERATION: u32 = 0x0000_0008;
pub(crate) const PROCESS_QUERY_INFORMATION_ACCESS: u32 = 0x0000_0400;
const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
const PROCESS_BASIC_INFORMATION_BYTES: usize = 48;
const PROCESS_AFFINITY_MASK_CLASS: u32 = 21;
const PROCESS_WOW64_INFORMATION_CLASS: u32 = 26;
const PROCESS_IMAGE_FILE_NAME_CLASS: u32 = 27;
const PROCESS_IMAGE_FILE_NAME_WIN32_CLASS: u32 = 43;
const PROCESS_POINTER_BYTES: usize = 8;
const CURRENT_PROCESS: u64 = u64::MAX;
const CURRENT_THREAD: u64 = u64::MAX - 1;
const THREAD_QUERY_INFORMATION: u32 = 0x0000_0040;
const THREAD_BASIC_INFORMATION_CLASS: u32 = 0;
const THREAD_BASIC_INFORMATION_BYTES: usize = 48;

/// Open a task identity into the caller's process-local NT handle table.
/// Only identities in the current NT process are admitted until the native
/// process namespace gains a cross-process owner. # C: O(log N)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == syscall::nt::NtService::TerminateProcess {
        let (process, status) = match syscall::nt::decode_terminate(call) {
            Ok(values) => values,
            Err(_) => return Some(STATUS_INVALID_PARAMETER),
        };
        if process == u64::MAX { return None; }
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        let table = cur.thread_group.nt_handles();
        let Some(target) = process_task(process, &table, PROCESS_TERMINATE) else {
            return Some(STATUS_INVALID_HANDLE);
        };
        if target.tgid.load(core::sync::atomic::Ordering::Acquire)
            != cur.tgid.load(core::sync::atomic::Ordering::Acquire) {
            return Some(STATUS_INVALID_HANDLE);
        }
        return Some(crate::s060_exit::sys_exit_group(&syscall::SyscallArgs {
            a0: status as u64, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0,
        }) as u64);
    }
    let object = match syscall::nt::decode_object(call) {
        Ok(object @ (NtObjectCall::OpenProcess { .. } | NtObjectCall::OpenThread { .. })) => object,
        Ok(NtObjectCall::QueryProcess { process, class, info, length, return_length }) => {
            return query_process(process, class, info, length, return_length);
        }
        Ok(NtObjectCall::QueryThread { thread, class, info, length, return_length }) => {
            return query_thread(thread, class, info, length, return_length);
        }
        _ => return None,
    };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    let (handle, desired_access, attributes, client_id, thread) = match object {
        NtObjectCall::OpenProcess { handle, desired_access, attributes, client_id } =>
            (handle, desired_access, attributes, client_id, false),
        NtObjectCall::OpenThread { handle, desired_access, attributes, client_id } =>
            (handle, desired_access, attributes, client_id, true),
        _ => return None,
    };
    if desired_access & !(if thread { THREAD_ALL_ACCESS } else { PROCESS_ALL_ACCESS }) != 0
        || !valid_object_attributes(attributes) { return Some(STATUS_INVALID_PARAMETER); }
    let process_id = match uaccess::get_user_u64(client_id.as_u64()) { Ok(value) => value, Err(_) => return Some(STATUS_INVALID_PARAMETER) };
    let Some(thread_id_address) = client_id.as_u64().checked_add(8) else { return Some(STATUS_INVALID_PARAMETER); };
    let thread_id = match uaccess::get_user_u64(thread_id_address) { Ok(value) => value, Err(_) => return Some(STATUS_INVALID_PARAMETER) };
    if thread {
        if !crate::nt_process_policy::valid_thread_client_id(process_id, thread_id) {
            return Some(STATUS_INVALID_CID);
        }
    } else if !crate::nt_process_policy::valid_process_client_id(process_id, thread_id) {
        return Some(STATUS_INVALID_CID);
    }
    let task = if thread {
        sched::registry::lookup(thread_id as u32)
    } else {
        let Some(candidate) = sched::registry::lookup(process_id as u32) else {
            return Some(STATUS_INVALID_CID);
        };
        let leader_id = candidate.tgid.load(core::sync::atomic::Ordering::Acquire);
        sched::registry::lookup(leader_id).or(Some(candidate))
    };
    let Some(task) = task else { return Some(STATUS_INVALID_CID); };
    if thread && !crate::nt_process_policy::thread_belongs_to_process(
        process_id, task.tgid.load(core::sync::atomic::Ordering::Acquire)) {
        return Some(STATUS_INVALID_CID);
    }
    if !task.is_nt_personality() { return Some(STATUS_INVALID_CID); }
    let object = if thread { table.new_thread(task) } else { table.new_process(task) };
    let access = if thread { desired_access | SYNCHRONIZE } else {
        let Some(access) = crate::nt_process_policy::process_granted_access(desired_access, PROCESS_ALL_ACCESS, SYNCHRONIZE) else {
            return Some(STATUS_INVALID_PARAMETER);
        };
        access
    };
    let Some(native) = table.insert(object, access) else { return Some(STATUS_NO_MEMORY); };
    if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() {
        let _ = table.close(native);
        return Some(STATUS_INVALID_PARAMETER);
    }
    Some(STATUS_SUCCESS)
}

fn query_process(process: u64, class: u32, info: syscall::UserPtr<u8>, length: u32,
    return_length: Option<syscall::UserPtr<u32>>) -> Option<u64> {
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let target_owned = if process == CURRENT_PROCESS {
        None
    } else {
        let table = cur.thread_group.nt_handles();
        if process > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
        let handle = sched::nt_object::NtHandle::from_raw(process as u32);
        let Some(target) = process_task(process, table, PROCESS_QUERY_LIMITED_INFORMATION)
            .or_else(|| process_task(process, table, PROCESS_QUERY_INFORMATION)) else {
            return Some(if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE });
        };
        Some(target)
    };
    let target = target_owned.as_deref().unwrap_or(cur);
    if class == PROCESS_IMAGE_FILE_NAME_CLASS || class == PROCESS_IMAGE_FILE_NAME_WIN32_CLASS {
        return query_process_image_name(target, info, length, return_length, class == PROCESS_IMAGE_FILE_NAME_WIN32_CLASS);
    }
    let required = match class {
        PROCESS_BASIC_INFORMATION_CLASS => PROCESS_BASIC_INFORMATION_BYTES,
        PROCESS_AFFINITY_MASK_CLASS | PROCESS_WOW64_INFORMATION_CLASS => PROCESS_POINTER_BYTES,
        _ => return Some(STATUS_INVALID_INFO_CLASS),
    };
    if (class == PROCESS_BASIC_INFORMATION_CLASS && (length as usize) < required)
        || (class != PROCESS_BASIC_INFORMATION_CLASS && length as usize != required) {
        return Some(STATUS_INFO_LENGTH_MISMATCH);
    }
    if info.as_u64() == 0 { return Some(STATUS_INVALID_PARAMETER); }
    if class == PROCESS_WOW64_INFORMATION_CLASS {
        if uaccess::put_user_u64(info.as_u64(), 0).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        return write_process_return_length(return_length, required);
    }
    if class == PROCESS_AFFINITY_MASK_CLASS {
        let mask = target.cpus_allowed.load(core::sync::atomic::Ordering::Acquire).low_word();
        if uaccess::put_user_u64(info.as_u64(), mask).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        return write_process_return_length(return_length, required);
    }
    let mut out = [0u8; PROCESS_BASIC_INFORMATION_BYTES];
    out[8..16].copy_from_slice(&target.nt_peb().to_ne_bytes());
    out[32..40].copy_from_slice(&(target.tgid.load(core::sync::atomic::Ordering::Acquire) as u64).to_ne_bytes());
    out[40..48].copy_from_slice(&(target.parent_tid.load(core::sync::atomic::Ordering::Acquire) as u64).to_ne_bytes());
    if uaccess::copy_to_user(info.as_u64(), &out).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    write_process_return_length(return_length, required)
}

fn query_process_image_name(target: &sched::Task, info: syscall::UserPtr<u8>, length: u32,
    return_length: Option<syscall::UserPtr<u32>>, win32: bool) -> Option<u64> {
    if info.as_u64() == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let Some(raw_path) = target.exe_path() else { return Some(STATUS_INVALID_PARAMETER); };
    let path = if win32 {
        crate::nt_path::render_windows_path(&raw_path)?
    } else {
        raw_path.strip_prefix("/windows/").map_or(raw_path.as_str(), |value| value).into()
    };
    let mut wide = alloc::vec::Vec::new();
    for value in path.encode_utf16() {
        wide.push(value);
    }
    let bytes = wide.len().checked_mul(2)?;
    if bytes > u16::MAX as usize { return Some(STATUS_INVALID_PARAMETER); }
    let required = 16usize.checked_add(bytes)?;
    if let Some(return_length) = return_length {
        if uaccess::put_user_u32(return_length.as_u64(), required as u32).is_err() {
            return Some(STATUS_INVALID_PARAMETER);
        }
    }
    if (length as usize) < required { return Some(STATUS_INFO_LENGTH_MISMATCH); }
    let mut output = alloc::vec![0u8; required];
    output[0..2].copy_from_slice(&(bytes as u16).to_ne_bytes());
    output[2..4].copy_from_slice(&(bytes as u16).to_ne_bytes());
    let Some(buffer_address) = info.as_u64().checked_add(16) else { return Some(STATUS_INVALID_PARAMETER); };
    output[8..16].copy_from_slice(&buffer_address.to_ne_bytes());
    for (index, value) in wide.iter().enumerate() {
        output[16 + index * 2..18 + index * 2].copy_from_slice(&value.to_ne_bytes());
    }
    if uaccess::copy_to_user(info.as_u64(), &output).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_SUCCESS)
}

fn write_process_return_length(return_length: Option<syscall::UserPtr<u32>>, length: usize) -> Option<u64> {
    if let Some(return_length) = return_length {
        if uaccess::put_user_u32(return_length.as_u64(), length as u32).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    }
    Some(STATUS_SUCCESS)
}

fn query_thread(thread: u64, class: u32, info: syscall::UserPtr<u8>, length: u32,
    return_length: Option<syscall::UserPtr<u32>>) -> Option<u64> {
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || class != THREAD_BASIC_INFORMATION_CLASS {
        return Some(if cur.is_nt_personality() { STATUS_INVALID_INFO_CLASS } else { STATUS_INVALID_PARAMETER });
    }
    if (length as usize) < THREAD_BASIC_INFORMATION_BYTES { return Some(STATUS_INFO_LENGTH_MISMATCH); }
    if info.as_u64() == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let target_owned = if thread == CURRENT_THREAD {
        None
    } else {
        let table = cur.thread_group.nt_handles();
        if thread > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
        let handle = sched::nt_object::NtHandle::from_raw(thread as u32);
        let Some(target) = thread_task(thread, table, THREAD_QUERY_INFORMATION) else {
            return Some(if table.contains(handle) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE });
        };
        Some(target)
    };
    let target = target_owned.as_deref().unwrap_or(cur);
    let mut out = [0u8; THREAD_BASIC_INFORMATION_BYTES];
    out[0..8].copy_from_slice(&(target.exit_status.load(core::sync::atomic::Ordering::Acquire) as i64 as u64).to_ne_bytes());
    out[8..16].copy_from_slice(&target.nt_teb().to_ne_bytes());
    out[16..24].copy_from_slice(&(target.tgid.load(core::sync::atomic::Ordering::Acquire) as u64).to_ne_bytes());
    out[24..32].copy_from_slice(&(target.tid as u64).to_ne_bytes());
    out[32..40].copy_from_slice(&target.cpus_allowed.load(core::sync::atomic::Ordering::Acquire).low_word().to_ne_bytes());
    out[40..44].copy_from_slice(&0i32.to_ne_bytes());
    out[44..48].copy_from_slice(&0i32.to_ne_bytes());
    if uaccess::copy_to_user(info.as_u64(), &out).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    write_process_return_length(return_length, THREAD_BASIC_INFORMATION_BYTES)
}

fn thread_task(raw: u64, table: &sched::nt_object::NtHandleTable, access: u32)
    -> Option<alloc::sync::Arc<sched::Task>> {
    if raw > u32::MAX as u64 { return None; }
    let object = table.get(sched::nt_object::NtHandle::from_raw(raw as u32), access)?;
    (object.kind() == sched::nt_object::NtObjectType::Thread).then(|| object.task()).flatten()
}

fn process_task(raw: u64, table: &sched::nt_object::NtHandleTable, access: u32)
    -> Option<alloc::sync::Arc<sched::Task>> {
    if raw > u32::MAX as u64 { return None; }
    let handle = sched::nt_object::NtHandle::from_raw(raw as u32);
    let object = table.get(handle, access)?;
    if object.kind() != sched::nt_object::NtObjectType::Process { return None; }
    object.task()
}

/// Validate a process pseudo-handle or native handle against one caller's
/// canonical process group. # C: O(1)
pub(crate) fn permits_current_process(raw: u64, cur: &sched::Task, access: u32) -> bool {
    if raw == u64::MAX { return true; }
    let table = cur.thread_group.nt_handles();
    let Some(target) = process_task(raw, table, access) else { return false; };
    target.tgid.load(core::sync::atomic::Ordering::Acquire)
        == cur.tgid.load(core::sync::atomic::Ordering::Acquire)
}

pub(crate) fn valid_object_attributes(attributes: Option<syscall::UserPtr<u8>>) -> bool {
    let Some(attributes) = attributes else { return true; };
    let address = attributes.as_u64();
    let Ok(length) = uaccess::get_user_u32(address) else { return false; };
    length >= 48 && uaccess::get_user_u64(address + 8).ok() == Some(0)
        && uaccess::get_user_u64(address + 16).ok() == Some(0)
}
