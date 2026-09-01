//! Activation-context section lookup boundary for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const ACTCTX_FLAGS_ALL: u32 = 0xff;
const ACTCTX_MIN_BYTES: u32 = 16;
const STATUS_SXS_KEY_NOT_FOUND: u64 = 0xc015_0008;
const FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX: u64 = 1;
const UNICODE_STRING_BYTES: usize = 16;
const ACTCTX_SECTION_KEYED_DATA_ROSTER_OFFSET: u32 = 64;
const TEB_ACTIVATION_CONTEXT_STACK_OFFSET: u64 = 0x2c8;
const WINDOWS_SETTINGS_2005: &[u8] = b"http://schemas.microsoft.com/SMI/2005/WindowsSettings";
const WINDOWS_SETTINGS_2011: &[u8] = b"http://schemas.microsoft.com/SMI/2011/WindowsSettings";
const WINDOWS_SETTINGS_2016: &[u8] = b"http://schemas.microsoft.com/SMI/2016/WindowsSettings";
const WINDOWS_SETTINGS_2017: &[u8] = b"http://schemas.microsoft.com/SMI/2017/WindowsSettings";
const WINDOWS_SETTINGS_2019: &[u8] = b"http://schemas.microsoft.com/SMI/2019/WindowsSettings";
const WINDOWS_SETTINGS_2020: &[u8] = b"http://schemas.microsoft.com/SMI/2020/WindowsSettings";

/// Validate the Wine/Windows string-section query and report no active context.
/// # C: O(1) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlQueryActivationContextApplicationSettings {
        return Some(query_application_settings(call));
    }
    if call.service == NtService::RtlGetActiveActivationContext {
        if call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let Some(task) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        let teb = task.nt_teb();
        let Some(pointer) = teb.checked_add(TEB_ACTIVATION_CONTEXT_STACK_OFFSET) else {
            return Some(STATUS_INVALID_PARAMETER);
        };
        let stack = uaccess::get_user_u64(pointer).ok().unwrap_or(0);
        let active = if stack == 0 { 0 } else {
            uaccess::get_user_u64(stack).ok().unwrap_or(0)
        };
        let context = if active == 0 { 0 } else {
            uaccess::get_user_u64(active.saturating_add(8)).ok().unwrap_or(0)
        };
        if context != 0 { return Some(STATUS_NOT_IMPLEMENTED); }
        if uaccess::put_user_u64(call.args.a0, 0).is_err() {
            return Some(STATUS_INVALID_PARAMETER);
        }
        return Some(0);
    }
    if call.service == NtService::RtlFreeActivationContextStack {
        if call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // ACTIVATION_CONTEXT_STACK.ActiveFrame is the first pointer. An
        // empty caller-owned stack needs no release work; populated stacks
        // await the activation-context object/lifetime owner.
        let Ok(active) = uaccess::get_user_u64(call.args.a0) else {
            return Some(STATUS_INVALID_PARAMETER);
        };
        return Some(if active == 0 { 0 } else { STATUS_NOT_IMPLEMENTED });
    }
    if call.service == NtService::RtlFreeThreadActivationContextStack {
        let Some(task) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        let teb = task.nt_teb();
        if teb == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let Some(stack) = teb.checked_add(TEB_ACTIVATION_CONTEXT_STACK_OFFSET) else {
            return Some(STATUS_INVALID_PARAMETER);
        };
        // The current TEB initializes this pointer to NULL.  An allocated
        // frame cannot be safely reclaimed until activation-context object
        // ownership is installed; preserve the honest boundary in that case.
        if uaccess::get_user_u64(stack).ok().unwrap_or(0) != 0 {
            return Some(STATUS_NOT_IMPLEMENTED);
        }
        return Some(0);
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
        // No process/thread activation-context owner is installed yet. The
        // native lookup therefore reaches the same not-found result after
        // checking both scopes.
        return Some(STATUS_SXS_KEY_NOT_FOUND);
    }
    if call.service == NtService::RtlDeactivateActivationContext {
        if call.args.a0 != 0 || call.args.a1 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // Deactivation must pop the caller's activation-context frame and
        // release its context; no kernel-owned frame stack exists yet.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::RtlReleaseActivationContext {
        if call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::RtlCreateActivationContext {
        if call.args.a0 == 0 || call.args.a1 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let mut header = [0u8; 8];
        if uaccess::copy_from_user(&mut header, call.args.a1).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        let size = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let flags = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if size < ACTCTX_MIN_BYTES || flags & !ACTCTX_FLAGS_ALL != 0 { return Some(STATUS_INVALID_PARAMETER); }
        // Manifest parsing, module-resource lookup, and activation-context
        // object lifetime are not owned by the kernel yet.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::RtlActivateActivationContextEx {
        // Native ABI: ULONG flags, TEB*, activation context, ULONG_PTR *cookie.
        if call.args.a0 != 0 || call.args.a1 == 0 || call.args.a2 == 0 || call.args.a3 == 0 {
            return Some(STATUS_INVALID_PARAMETER);
        }
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::RtlActivateActivationContext {
        // Native ABI: ULONG flags, HANDLE/PACTIVATION_CONTEXT context,
        // ULONG_PTR *cookie. The context is opaque to the kernel boundary.
        if call.args.a0 != 0 || call.args.a1 == 0 || call.args.a2 == 0 {
            return Some(STATUS_INVALID_PARAMETER);
        }
        // The per-thread activation-context stack and cookie ownership are
        // not installed yet, so do not report success without an owner.
        return Some(STATUS_NOT_IMPLEMENTED);
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
    // Process/thread activation contexts are not installed yet. This is the
    // same result Wine returns after searching both context scopes.
    Some(STATUS_SXS_KEY_NOT_FOUND)
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
    // The activation-context object/parser is not installed yet. Preserve
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
