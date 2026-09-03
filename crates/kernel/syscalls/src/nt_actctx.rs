//! Activation-context section lookup boundary for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use alloc::{sync::Arc, vec::Vec};
use syscall::nt::{NtCall, NtService};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const ACTCTX_FLAGS_ALL: u32 = 0xff;
const ACTCTX_MIN_BYTES: u32 = 16;
const STATUS_SXS_KEY_NOT_FOUND: u64 = 0xc015_0008;
const STATUS_SXS_EARLY_DEACTIVATION: u64 = 0xc015_000f;
const STATUS_SXS_INVALID_DEACTIVATION: u64 = 0xc015_0010;
const FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX: u64 = 1;
const DEACTIVATE_FORCE_EARLY: u64 = 1;
const QUERY_USE_ACTIVE: u64 = 0x0000_0004;
const QUERY_NO_ADDREF: u64 = 0x8000_0000;
const UNICODE_STRING_BYTES: usize = 16;
const ACTCTX_SECTION_KEYED_DATA_ROSTER_OFFSET: u32 = 64;
const TEB_ACTIVATION_CONTEXT_STACK_OFFSET: u64 = 0x2c8;
const TEB_ACTIVATION_CONTEXT_STACK_INLINE: u64 = 0x290;
const WINDOWS_SETTINGS_2005: &[u8] = b"http://schemas.microsoft.com/SMI/2005/WindowsSettings";
const WINDOWS_SETTINGS_2011: &[u8] = b"http://schemas.microsoft.com/SMI/2011/WindowsSettings";
const WINDOWS_SETTINGS_2016: &[u8] = b"http://schemas.microsoft.com/SMI/2016/WindowsSettings";
const WINDOWS_SETTINGS_2017: &[u8] = b"http://schemas.microsoft.com/SMI/2017/WindowsSettings";
const WINDOWS_SETTINGS_2019: &[u8] = b"http://schemas.microsoft.com/SMI/2019/WindowsSettings";
const WINDOWS_SETTINGS_2020: &[u8] = b"http://schemas.microsoft.com/SMI/2020/WindowsSettings";

/// Validate the Wine/Windows string-section query and report no active context.
/// # C: O(1) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlQueryInformationActivationContext {
        return Some(query_information(call));
    }
    if call.service == NtService::RtlQueryActivationContextApplicationSettings {
        return Some(query_application_settings(call));
    }
    if call.service == NtService::RtlGetActiveActivationContext {
        return Some(get_active(call.args.a0));
    }
    if call.service == NtService::RtlFreeActivationContextStack {
        return Some(free_stack(Some(call.args.a0)));
    }
    if call.service == NtService::RtlFreeThreadActivationContextStack {
        return Some(free_stack(None));
    }
    if call.service == NtService::RtlFindActivationContextSectionGuid {
        let flags = call.args.a0;
        if flags & !FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX != 0 || call.args.a1 != 0 || call.args.a3 == 0 || call.args.a4 == 0 {
            return Some(STATUS_INVALID_PARAMETER);
        }
        if call.args.a2 == 0 {
            return Some(STATUS_INVALID_PARAMETER);
        }
        let mut cb_size = [0u8; 4];
        if uaccess::copy_from_user(&mut cb_size, call.args.a4).is_err() ||
            u32::from_le_bytes(cb_size) < ACTCTX_SECTION_KEYED_DATA_ROSTER_OFFSET {
            return Some(STATUS_INVALID_PARAMETER);
        }
        // The stack owner is present, but manifest keyed sections have not
        // been parsed into that object yet.
        return Some(STATUS_SXS_KEY_NOT_FOUND);
    }
    if call.service == NtService::RtlDeactivateActivationContext {
        return Some(deactivate(call.args.a0, call.args.a1));
    }
    if call.service == NtService::RtlReleaseActivationContext {
        if call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let Some(task) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        return Some(release_context(&task, call.args.a0));
    }
    if call.service == NtService::RtlAddRefActivationContext {
        if call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let Some(task) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        let Ok((_, _, context)) = resolve_context(&task, call.args.a0) else { return Some(STATUS_INVALID_PARAMETER); };
        return Some(if context.add_ref() { 0 } else { STATUS_NO_MEMORY });
    }
    if call.service == NtService::RtlCreateActivationContext {
        if call.args.a0 == 0 || call.args.a1 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let mut header = [0u8; 8];
        if uaccess::copy_from_user(&mut header, call.args.a1).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        let size = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let flags = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if size < ACTCTX_MIN_BYTES || flags & !ACTCTX_FLAGS_ALL != 0 { return Some(STATUS_INVALID_PARAMETER); }
        let Some(task) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        let object = task.thread_group.nt_handles().new_activation_context();
        let Some(handle) = task.thread_group.nt_handles().insert(object, 0) else { return Some(STATUS_NO_MEMORY); };
        if uaccess::put_user_u64(call.args.a0, handle.raw() as u64).is_err() {
            let _ = task.thread_group.nt_handles().close(handle);
            return Some(STATUS_INVALID_PARAMETER);
        }
        return Some(0);
    }
    if call.service == NtService::RtlActivateActivationContextEx {
        return Some(activate(call.args.a0, Some(call.args.a1), call.args.a2, call.args.a3));
    }
    if call.service == NtService::RtlActivateActivationContext {
        return Some(activate(call.args.a0, None, call.args.a1, call.args.a2));
    }
    if call.service != NtService::RtlFindActivationContextSectionString { return None; }
    let flags = call.args.a0;
    if flags & !FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX != 0 || call.args.a1 != 0 {
        return Some(STATUS_INVALID_PARAMETER);
    }
    if call.args.a3 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let mut name = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut name, call.args.a3).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    let length = u16::from_le_bytes([name[0], name[1]]);
    let buffer = u64::from_le_bytes(name[8..16].try_into().unwrap());
    if buffer == 0 || length & 1 != 0 { return Some(STATUS_INVALID_PARAMETER); }
    if call.args.a4 != 0 {
        let mut cb_size = [0u8; 4];
        if uaccess::copy_from_user(&mut cb_size, call.args.a4).is_err() {
            return Some(STATUS_INVALID_PARAMETER);
        }
        if u32::from_le_bytes(cb_size) < ACTCTX_SECTION_KEYED_DATA_ROSTER_OFFSET {
            return Some(STATUS_INVALID_PARAMETER);
        }
    }
    // Active-context ownership is separate from manifest keyed-section data.
    Some(STATUS_SXS_KEY_NOT_FOUND)
}

fn resolve_context(task: &sched::Task, raw: u64) -> Result<(sched::nt_object::NtHandle,
    Arc<sched::nt_object::NtObject>, Arc<sched::nt_object::NtActivationContext>), u64> {
    if raw == 0 || raw > u32::MAX as u64 { return Err(STATUS_INVALID_PARAMETER); }
    let handle = sched::nt_object::NtHandle::from_raw(raw as u32);
    let object = task.thread_group.nt_handles().get(handle, 0).ok_or(STATUS_INVALID_HANDLE)?;
    let context = object.activation_context().ok_or(STATUS_INVALID_HANDLE)?;
    Ok((handle, object, context))
}

fn target_for_teb(current: &sched::Task, teb: Option<u64>) -> Option<Arc<sched::Task>> {
    let Some(teb) = teb else { return sched::registry::lookup(current.tid); };
    if teb == 0 { return None; }
    if current.nt_teb() == teb { return sched::registry::lookup(current.tid); }
    sched::registry::snapshot().into_iter().find(|candidate|
        candidate.is_nt_personality() && candidate.nt_teb() == teb
            && Arc::ptr_eq(&candidate.thread_group, &current.thread_group))
}

fn activate(flags: u64, teb: Option<u64>, raw: u64, cookie_out: u64) -> u64 {
    if flags != 0 || raw == 0 || cookie_out == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Some(target) = target_for_teb(current, teb) else { return STATUS_INVALID_PARAMETER; };
    let Ok((handle, object, context)) = resolve_context(current, raw) else { return STATUS_INVALID_HANDLE; };
    if !context.add_ref() { return STATUS_NO_MEMORY; }
    let cookie = {
        let mut stack = target.nt_activation_stack.lock();
        stack.push(handle, object)
    };
    let Some(cookie) = cookie else {
        let _ = context.release();
        return STATUS_NO_MEMORY;
    };
    if uaccess::put_user_u64(cookie_out, cookie).is_ok() { return 0; }
    let removed = target.nt_activation_stack.lock().deactivate(cookie, true).unwrap_or_default();
    sched::nt_activation::release_frames(&target, removed);
    STATUS_INVALID_PARAMETER
}

fn deactivate(flags: u64, cookie: u64) -> u64 {
    if flags & !DEACTIVATE_FORCE_EARLY != 0 || cookie == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let removed = current.nt_activation_stack.lock().deactivate(
        cookie, flags & DEACTIVATE_FORCE_EARLY != 0);
    let removed = match removed {
        Ok(frames) => frames,
        Err(sched::nt_activation::DeactivateError::NotFound) => return STATUS_SXS_INVALID_DEACTIVATION,
        Err(sched::nt_activation::DeactivateError::Early) => return STATUS_SXS_EARLY_DEACTIVATION,
        Err(sched::nt_activation::DeactivateError::NoMemory) => return STATUS_NO_MEMORY,
    };
    sched::nt_activation::release_frames(current, removed);
    0
}

fn get_active(output: u64) -> u64 {
    if output == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let active = current.nt_activation_stack.lock().top();
    let Some(frame) = active else {
        return if uaccess::put_user_u64(output, 0).is_ok() { 0 } else { STATUS_INVALID_PARAMETER };
    };
    let Some(context) = frame.object().activation_context() else { return STATUS_INVALID_HANDLE; };
    if !context.add_ref() { return STATUS_NO_MEMORY; }
    if uaccess::put_user_u64(output, frame.handle().raw() as u64).is_ok() { return 0; }
    let _ = context.release();
    STATUS_INVALID_PARAMETER
}

fn release_context(task: &sched::Task, raw: u64) -> u64 {
    let Ok((handle, _, context)) = resolve_context(task, raw) else { return STATUS_INVALID_HANDLE; };
    match context.release() {
        Some(false) => 0,
        Some(true) => if task.thread_group.nt_handles().close(handle) { 0 } else { STATUS_INVALID_HANDLE },
        None => STATUS_INVALID_HANDLE,
    }
}

fn free_stack(stack_address: Option<u64>) -> u64 {
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || current.nt_teb() == 0 { return STATUS_INVALID_PARAMETER; }
    if let Some(stack_address) = stack_address {
        let Some(pointer_address) = current.nt_teb().checked_add(TEB_ACTIVATION_CONTEXT_STACK_OFFSET) else {
            return STATUS_INVALID_PARAMETER;
        };
        let Some(inline_stack) = current.nt_teb().checked_add(TEB_ACTIVATION_CONTEXT_STACK_INLINE) else {
            return STATUS_INVALID_PARAMETER;
        };
        let Ok(expected) = uaccess::get_user_u64(pointer_address) else { return STATUS_INVALID_PARAMETER; };
        if stack_address == 0 || stack_address != expected || expected != inline_stack {
            return STATUS_INVALID_PARAMETER;
        }
    }
    let removed = current.nt_activation_stack.lock().clear();
    sched::nt_activation::release_frames(current, removed);
    0
}

fn query_information(call: NtCall) -> u64 {
    const ACTIVATION_CONTEXT_BASIC_INFORMATION: u64 = 1;
    const BASIC_INFORMATION_BYTES: u64 = 16;
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() || call.args.a0 & !(QUERY_USE_ACTIVE | QUERY_NO_ADDREF) != 0
        || call.args.a2 != 0 { return STATUS_INVALID_PARAMETER; }
    if call.args.a3 != ACTIVATION_CONTEXT_BASIC_INFORMATION { return STATUS_NOT_IMPLEMENTED; }
    let active: Option<(sched::nt_object::NtHandle, Arc<sched::nt_object::NtObject>)> =
        if call.args.a0 & QUERY_USE_ACTIVE != 0 {
        if call.args.a1 != 0 { return STATUS_INVALID_PARAMETER; }
        current.nt_activation_stack.lock().top().map(|frame| (frame.handle(), frame.object()))
    } else if call.args.a1 == 0 { None } else {
        let Ok((handle, object, _)) = resolve_context(current, call.args.a1) else { return STATUS_INVALID_HANDLE; };
        Some((handle, object))
    };
    let return_length = crate::nt_dispatch::stack_argument(6).unwrap_or(0);
    if return_length != 0 && uaccess::put_user_u64(return_length, BASIC_INFORMATION_BYTES).is_err() {
        return STATUS_INVALID_PARAMETER;
    }
    if call.args.a5 < BASIC_INFORMATION_BYTES || call.args.a4 == 0 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let mut out = [0u8; BASIC_INFORMATION_BYTES as usize];
    let mut acquired = None;
    if let Some((handle, object)) = active {
        let Some(context) = object.activation_context() else { return STATUS_INVALID_HANDLE; };
        if call.args.a0 & QUERY_NO_ADDREF == 0 {
            if !context.add_ref() { return STATUS_NO_MEMORY; }
            acquired = Some(context);
        }
        out[0..8].copy_from_slice(&(handle.raw() as u64).to_le_bytes());
    }
    if uaccess::copy_to_user(call.args.a4, &out).is_err() {
        if let Some(context) = acquired { let _ = context.release(); }
        return STATUS_INVALID_PARAMETER;
    }
    0
}

fn query_application_settings(call: NtCall) -> u64 {
    if call.args.a0 != 0 || call.args.a3 == 0 || call.args.a1 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if read_wide_z(call.args.a3).is_none() { return STATUS_INVALID_PARAMETER; }
    if call.args.a2 != 0 {
        let Some(namespace) = read_wide_z(call.args.a2) else { return STATUS_INVALID_PARAMETER; };
        if ![WINDOWS_SETTINGS_2005, WINDOWS_SETTINGS_2011, WINDOWS_SETTINGS_2016,
            WINDOWS_SETTINGS_2017, WINDOWS_SETTINGS_2019, WINDOWS_SETTINGS_2020]
            .iter().any(|candidate| namespace.len() == candidate.len()
                && namespace.iter().zip(candidate.iter()).all(|(left, right)| *left == *right as u16)) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    // The activation-context manifest parser is not installed yet. Preserve
    // the reference result for a valid query instead of copying settings from
    // a Linux configuration source or claiming a buffer was populated.
    STATUS_SXS_KEY_NOT_FOUND
}

fn read_wide_z(address: u64) -> Option<Vec<u16>> {
    if address == 0 { return None; }
    let mut output = Vec::new();
    for index in 0..0x8000usize {
        let mut bytes = [0u8; 2];
        uaccess::copy_from_user(&mut bytes, address.checked_add((index * 2) as u64)?).ok()?;
        let value = u16::from_le_bytes(bytes);
        if value == 0 { return Some(output); }
        output.push(value);
    }
    None
}
