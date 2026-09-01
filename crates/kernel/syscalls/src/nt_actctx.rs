//! Activation-context section lookup boundary for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const ACTCTX_FLAGS_ALL: u32 = 0xff;
const ACTCTX_MIN_BYTES: u32 = 16;
const STATUS_SXS_KEY_NOT_FOUND: u64 = 0xc015_0008;
const FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX: u64 = 1;
const UNICODE_STRING_BYTES: usize = 16;
const ACTCTX_SECTION_KEYED_DATA_ROSTER_OFFSET: u32 = 64;

/// Validate the Wine/Windows string-section query and report no active context.
/// # C: O(1) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
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
