//! Process-local Windows DLL-directory state.

#![cfg(target_os = "oxide-kernel")]

use alloc::{vec, vec::Vec};
use core::sync::atomic::Ordering;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const UNICODE_STRING_BYTES: usize = 16;
const BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE: u32 = 0x00001;
const BASE_SEARCH_PATH_DISABLE_SAFE_SEARCHMODE: u32 = 0x10000;
const BASE_SEARCH_PATH_PERMANENT: u32 = 0x08000;
const BASE_SEARCH_PATH_ENABLE_SAFE_PERMANENT: u32 = BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT;
const SEARCH_PATH_MODE_UNSET: u32 = 0;
const SEARCH_PATH_MODE_SAFE: u32 = 1;
const SEARCH_PATH_MODE_PERMANENT: u32 = 2;
const STATUS_DLL_NOT_FOUND: u64 = 0xc000_0135;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const PEB_IMAGE_BASE_OFFSET: u64 = 0x10;
const PEB_LDR_OFFSET: u64 = 0x18;
const TEB_PEB_OFFSET: u64 = 0x60;
const LDR_LOAD_LIST_OFFSET: u64 = 0x10;
const LIST_LINK_OFFSET: u64 = 0;
const MODULE_BASE_OFFSET: u64 = 0x30;
const MODULE_FULL_NAME_OFFSET: u64 = 0x48;
const MODULE_BASE_NAME_OFFSET: u64 = 0x58;
const MAX_MODULE_SCAN: usize = 64;
const LDR_ADDREF_DLL_PIN: u32 = 1;
const LDR_GET_HANDLE_UNCHANGED_REFCOUNT: u32 = 1;
const LDR_GET_HANDLE_PIN: u32 = 2;

pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::RtlAcquirePebLock => Some(acquire_peb_lock()),
        NtService::RtlReleasePebLock => Some(release_peb_lock()),
        NtService::RtlSetSearchPathMode => Some(set_search_path_mode(call.args.a0 as u32)),
        NtService::LdrGetDllDirectory => Some(get(call.args.a0)),
        NtService::LdrSetDllDirectory => Some(set(call.args.a0)),
        NtService::LdrAddDllDirectory => Some(add(call.args.a0, call.args.a1)),
        NtService::LdrRemoveDllDirectory => Some(remove(call.args.a0)),
        NtService::LdrAddRefDll => Some(add_ref(call.args.a0 as u32, call.args.a1)),
        NtService::LdrDisableThreadCalloutsForDll => Some(disable_thread_callouts(call.args.a0)),
        NtService::LdrGetDllHandleEx => Some(get_handle(call.args.a0 as u32, call.args.a3, call.args.a4)),
        NtService::LdrGetDllPath => Some(get_path(call.args.a0, call.args.a2, call.args.a3)),
        NtService::LdrGetDllPath => Some(get_path(call.args.a0, call.args.a2, call.args.a3)),
        NtService::LdrGetDllFullName => Some(full_name(call.args.a0, call.args.a1)),
        NtService::LdrLoadDll => Some(load(call.args.a2, call.args.a3)),
        NtService::LdrQueryImageFileExecutionOptions => Some(query_options(call.args.a0, call.args.a1, call.args.a4, call.args.a5)),
        _ => None,
    }
}

fn add_ref(flags: u32, module: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || module == 0 { return STATUS_INVALID_PARAMETER; }
    let peb = read_u64(cur.nt_teb().saturating_add(TEB_PEB_OFFSET));
    let ldr = read_u64(peb.saturating_add(PEB_LDR_OFFSET));
    if peb == 0 || ldr == 0 { return STATUS_INVALID_PARAMETER; }
    let head = ldr.saturating_add(LDR_LOAD_LIST_OFFSET);
    let mut entry = read_u64(head);
    let mut loaded = false;
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        if read_u64(entry.saturating_add(MODULE_BASE_OFFSET)) == module { loaded = true; break; }
        entry = read_u64(entry.saturating_add(LIST_LINK_OFFSET));
    }
    if !loaded { return STATUS_INVALID_PARAMETER; }
    let mut refs = cur.thread_group.nt_module_refs.lock();
    if flags & !LDR_ADDREF_DLL_PIN != 0 { /* Wine accepts this with a FIXME. */ }
    if let Some((_, count)) = refs.iter_mut().find(|(base, _)| *base == module) {
        if flags & LDR_ADDREF_DLL_PIN != 0 { *count = -1; } else if *count != -1 { *count = count.saturating_add(1); }
    } else {
        refs.push((module, if flags & LDR_ADDREF_DLL_PIN != 0 { -1 } else { 2 }));
    }
    STATUS_SUCCESS
}

fn disable_thread_callouts(module: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || module == 0 { return STATUS_INVALID_PARAMETER; }
    let peb = read_u64(cur.nt_teb().saturating_add(TEB_PEB_OFFSET));
    let ldr = read_u64(peb.saturating_add(PEB_LDR_OFFSET));
    if peb == 0 || ldr == 0 { return STATUS_INVALID_PARAMETER; }
    let head = ldr.saturating_add(LDR_LOAD_LIST_OFFSET);
    let mut entry = read_u64(head);
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        if read_u64(entry.saturating_add(MODULE_BASE_OFFSET)) == module {
            let mut disabled = cur.thread_group.nt_module_no_thread_calls.lock();
            if !disabled.iter().any(|base| *base == module) { disabled.push(module); }
            return STATUS_SUCCESS;
        }
        entry = read_u64(entry.saturating_add(LIST_LINK_OFFSET));
    }
    STATUS_DLL_NOT_FOUND
}

fn get_handle(flags: u32, name_descriptor: u64, module_output: u64) -> u64 {
    let valid = LDR_GET_HANDLE_UNCHANGED_REFCOUNT | LDR_GET_HANDLE_PIN | 4;
    if name_descriptor == 0 || module_output == 0 || flags & !valid != 0 { return STATUS_INVALID_PARAMETER; }
    if flags & (LDR_GET_HANDLE_UNCHANGED_REFCOUNT | LDR_GET_HANDLE_PIN)
        == (LDR_GET_HANDLE_UNCHANGED_REFCOUNT | LDR_GET_HANDLE_PIN) { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Some(wanted) = read_unicode(name_descriptor) else { return STATUS_INVALID_PARAMETER; };
    let peb = read_u64(cur.nt_teb().saturating_add(TEB_PEB_OFFSET));
    let ldr = read_u64(peb.saturating_add(PEB_LDR_OFFSET));
    if peb == 0 || ldr == 0 { return STATUS_INVALID_PARAMETER; }
    let head = ldr.saturating_add(LDR_LOAD_LIST_OFFSET);
    let mut entry = read_u64(head);
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        if module_name_matches(&wanted, entry.saturating_add(MODULE_BASE_NAME_OFFSET)) {
            let module = read_u64(entry.saturating_add(MODULE_BASE_OFFSET));
            if uaccess::put_user_u64(module_output, module).is_err() { return STATUS_INVALID_PARAMETER; }
            if flags & LDR_GET_HANDLE_PIN != 0 { return add_ref(LDR_ADDREF_DLL_PIN, module); }
            if flags & LDR_GET_HANDLE_UNCHANGED_REFCOUNT == 0 { return add_ref(0, module); }
            return STATUS_SUCCESS;
        }
        entry = read_u64(entry.saturating_add(LIST_LINK_OFFSET));
    }
    STATUS_DLL_NOT_FOUND
}

fn get_path(module: u64, path_output: u64, unknown_output: u64) -> u64 {
    if module == 0 || path_output == 0 || unknown_output == 0 { return STATUS_INVALID_PARAMETER; }
    if read_wide_z(module).is_none() { return STATUS_INVALID_PARAMETER; }
    if uaccess::put_user_u64(path_output, 0).is_err() || uaccess::put_user_u64(unknown_output, 0).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn read_wide_z(address: u64) -> Option<Vec<u8>> {
    let mut value = Vec::new();
    for index in 0..1024u64 {
        let offset = address.checked_add(index.checked_mul(2)?)?;
        let mut bytes = [0u8; 2];
        uaccess::copy_from_user(&mut bytes, offset).ok()?;
        if bytes == [0, 0] { return Some(value); }
        value.extend_from_slice(&bytes);
    }
    None
}

fn get_path(module: u64, path_output: u64, unknown_output: u64) -> u64 {
    if module == 0 || path_output == 0 || unknown_output == 0 { return STATUS_INVALID_PARAMETER; }
    if read_wide_z(module).is_none() { return STATUS_INVALID_PARAMETER; }
    if uaccess::put_user_u64(path_output, 0).is_err() || uaccess::put_user_u64(unknown_output, 0).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn read_wide_z(address: u64) -> Option<Vec<u8>> {
    let mut value = Vec::new();
    for index in 0..1024u64 {
        let mut bytes = [0u8; 2];
        uaccess::copy_from_user(&mut bytes, address.checked_add(index.checked_mul(2)?)?).ok()?;
        if bytes == [0, 0] { return Some(value); }
        value.extend_from_slice(&bytes);
    }
    None
}

fn module_name_matches(wanted: &[u8], descriptor: u64) -> bool {
    let current = read_module_name(descriptor);
    if wanted.eq_ignore_ascii_case(&current) { return true; }
    if wanted.len() + 8 == current.len() && current[..wanted.len()].eq_ignore_ascii_case(wanted)
        && current[wanted.len()..].eq_ignore_ascii_case(&[b'.', 0, b'd', 0, b'l', 0, b'l', 0]) { return true; }
    false
}

fn add(descriptor: u64, cookie_output: u64) -> u64 {
    if descriptor == 0 || cookie_output == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Some(path) = read_unicode(descriptor) else { return STATUS_INVALID_PARAMETER; };
    if path.is_empty() || !absolute_path(&path) { return STATUS_INVALID_PARAMETER; }
    let cookie = cur.thread_group.nt_dll_directory_next.fetch_add(1, Ordering::AcqRel).max(1);
    cur.thread_group.nt_dll_directories.lock().push((cookie, path));
    if uaccess::put_user_u64(cookie_output, cookie).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn remove(cookie: u64) -> u64 {
    if cookie == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let mut dirs = cur.thread_group.nt_dll_directories.lock();
    let before = dirs.len();
    dirs.retain(|(known, _)| *known != cookie);
    if dirs.len() == before { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}

fn read_unicode(descriptor: u64) -> Option<Vec<u8>> {
    let mut raw = [0u8; UNICODE_STRING_BYTES];
    uaccess::copy_from_user(&mut raw, descriptor).ok()?;
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let maximum = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    if length == 0 || length > maximum || length & 1 != 0 || length > 32 * 1024 || buffer == 0 { return None; }
    let mut value = vec![0u8; length];
    uaccess::copy_from_user(&mut value, buffer).ok()?;
    Some(value)
}

fn absolute_path(path: &[u8]) -> bool {
    path.len() >= 2 && ((path[0] == b'\\' && path[1] == 0) || (path.len() >= 4 && path[1] == 0 && path[2] == b':' && path[3] == 0))
}

fn query_options(key: u64, value: u64, data_size: u64, result_size: u64) -> u64 {
    if key == 0 || value == 0 || data_size > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let mut raw = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut raw, key).is_err() { return STATUS_INVALID_PARAMETER; }
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if length == 0 || length & 1 != 0 || buffer == 0 || length > 1024 { return STATUS_INVALID_PARAMETER; }
    if result_size != 0 && uaccess::copy_to_user(result_size, &[0, 0, 0, 0]).is_err() { return STATUS_INVALID_PARAMETER; }
    // The Windows registry personality is not mounted in this process yet;
    // absence is therefore the precise result for every unconfigured IFEO key.
    STATUS_OBJECT_NAME_NOT_FOUND
}

fn load(name_descriptor: u64, module_output: u64) -> u64 {
    if name_descriptor == 0 || module_output == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut descriptor, name_descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    let length = u16::from_le_bytes([descriptor[0], descriptor[1]]) as usize;
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    if length & 1 != 0 || length == 0 || buffer == 0 || length > 1024 { return STATUS_INVALID_PARAMETER; }
    let mut wanted = Vec::new(); wanted.resize(length, 0);
    if uaccess::copy_from_user(&mut wanted, buffer).is_err() { return STATUS_INVALID_PARAMETER; }
    let teb = cur.nt_teb();
    let peb = read_u64(teb.saturating_add(TEB_PEB_OFFSET));
    let ldr = read_u64(peb.saturating_add(PEB_LDR_OFFSET));
    if peb == 0 || ldr == 0 { return STATUS_DLL_NOT_FOUND; }
    let head = ldr.saturating_add(LDR_LOAD_LIST_OFFSET);
    let mut entry = read_u64(head);
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        let name = read_module_name(entry.saturating_add(MODULE_BASE_NAME_OFFSET));
        if same_module_name(&wanted, &name) {
            let base = read_u64(entry.saturating_add(MODULE_BASE_OFFSET));
            if uaccess::copy_to_user(module_output, &base.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
            return STATUS_SUCCESS;
        }
        entry = read_u64(entry.saturating_add(LIST_LINK_OFFSET));
    }
    STATUS_DLL_NOT_FOUND
}

fn read_module_name(descriptor: u64) -> Vec<u8> {
    let mut raw = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut raw, descriptor).is_err() { return Vec::new(); }
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if length == 0 || length > 1024 || length & 1 != 0 || buffer == 0 { return Vec::new(); }
    let mut value = Vec::new(); value.resize(length, 0);
    if uaccess::copy_from_user(&mut value, buffer).is_err() { Vec::new() } else { value }
}

fn same_module_name(wanted: &[u8], current: &[u8]) -> bool {
    wanted.eq_ignore_ascii_case(current)
}

fn full_name(module: u64, descriptor: u64) -> u64 {
    if descriptor == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let teb = cur.nt_teb();
    let peb = read_u64(teb.saturating_add(TEB_PEB_OFFSET));
    if peb == 0 { return STATUS_INVALID_PARAMETER; }
    let module = if module == 0 { read_u64(peb.saturating_add(PEB_IMAGE_BASE_OFFSET)) } else { module };
    let ldr = read_u64(peb.saturating_add(PEB_LDR_OFFSET));
    if module == 0 || ldr == 0 { return STATUS_DLL_NOT_FOUND; }
    let head = ldr.saturating_add(LDR_LOAD_LIST_OFFSET);
    let mut entry = read_u64(head);
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        if read_u64(entry.saturating_add(MODULE_BASE_OFFSET)) == module {
            return copy_full_name(entry.saturating_add(MODULE_FULL_NAME_OFFSET), descriptor);
        }
        entry = read_u64(entry.saturating_add(LIST_LINK_OFFSET));
    }
    STATUS_DLL_NOT_FOUND
}

fn copy_full_name(source_descriptor: u64, destination: u64) -> u64 {
    let mut source = [0u8; UNICODE_STRING_BYTES];
    let mut target = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut source, source_descriptor).is_err() || uaccess::copy_from_user(&mut target, destination).is_err() { return STATUS_INVALID_PARAMETER; }
    let source_len = u16::from_le_bytes([source[0], source[1]]) as usize;
    let source_buffer = u64::from_le_bytes(source[8..16].try_into().unwrap());
    let maximum = u16::from_le_bytes([target[2], target[3]]) as usize;
    let target_buffer = u64::from_le_bytes(target[8..16].try_into().unwrap());
    if source_len & 1 != 0 || source_len != 0 && source_buffer == 0 { return STATUS_INVALID_PARAMETER; }
    let copied = core::cmp::min(source_len, maximum);
    if copied != 0 {
        let mut bytes = Vec::new();
        bytes.resize(copied, 0);
        if uaccess::copy_from_user(&mut bytes, source_buffer).is_err() || target_buffer == 0 || uaccess::copy_to_user(target_buffer, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    if copied < maximum && maximum >= copied.saturating_add(2) && target_buffer != 0 && uaccess::copy_to_user(target_buffer.saturating_add(copied as u64), &[0, 0]).is_err() { return STATUS_INVALID_PARAMETER; }
    if uaccess::copy_to_user(destination, &(copied as u16).to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    if maximum < source_len { STATUS_BUFFER_TOO_SMALL } else { STATUS_SUCCESS }
}

fn read_u64(address: u64) -> u64 {
    let mut raw = [0u8; 8];
    if uaccess::copy_from_user(&mut raw, address).is_err() { 0 } else { u64::from_le_bytes(raw) }
}

fn set_search_path_mode(flags: u32) -> u64 {
    let (mode, permanent) = match flags {
        BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE => (SEARCH_PATH_MODE_SAFE, false),
        BASE_SEARCH_PATH_DISABLE_SAFE_SEARCHMODE => (SEARCH_PATH_MODE_UNSET, false),
        BASE_SEARCH_PATH_ENABLE_SAFE_PERMANENT => (SEARCH_PATH_MODE_PERMANENT, true),
        _ => return STATUS_INVALID_PARAMETER,
    };
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    loop {
        let previous = cur.thread_group.nt_search_path_mode.load(Ordering::Acquire);
        if previous == SEARCH_PATH_MODE_PERMANENT {
            return if permanent { STATUS_SUCCESS } else { STATUS_ACCESS_DENIED };
        }
        if cur.thread_group.nt_search_path_mode.compare_exchange(previous, mode, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return STATUS_SUCCESS;
        }
    }
}

fn acquire_peb_lock() -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || cur.tid == 0 { return STATUS_INVALID_PARAMETER; }
    let outcome = unsafe { cur.thread_group.nt_peb_lock.wait(cur.tid as u64, 0, timekeeper::monotonic_ns) };
    if outcome == sched::WaitOutcome::Ready { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER }
}

fn release_peb_lock() -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || cur.tid == 0 { return STATUS_INVALID_PARAMETER; }
    if cur.thread_group.nt_peb_lock.release(cur.tid as u64).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn get(descriptor: u64) -> u64 {
    if descriptor == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let mut raw = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut raw, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    let maximum = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let value = cur.thread_group.nt_dll_directory.lock().clone();
    let required = value.len().saturating_add(2);
    if required > u16::MAX as usize { return STATUS_INVALID_PARAMETER; }
    if uaccess::copy_to_user(descriptor, &(required as u16).to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    if maximum < required {
        if maximum >= 2 && buffer != 0 { let _ = uaccess::copy_to_user(buffer, &[0, 0]); }
        return STATUS_BUFFER_TOO_SMALL;
    }
    if buffer == 0 { return STATUS_INVALID_PARAMETER; }
    let mut output = value;
    output.extend_from_slice(&[0, 0]);
    if uaccess::copy_to_user(buffer, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn set(descriptor: u64) -> u64 {
    if descriptor == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let mut raw = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut raw, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let maximum = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if length > maximum || length & 1 != 0 || length != 0 && buffer == 0 { return STATUS_INVALID_PARAMETER; }
    let mut value = Vec::with_capacity(length);
    if length != 0 {
        value.resize(length, 0);
        if uaccess::copy_from_user(&mut value, buffer).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    *cur.thread_group.nt_dll_directory.lock() = value;
    STATUS_SUCCESS
}
