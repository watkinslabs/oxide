//! Windows `CONTEXT_EX` xstate component lookup.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const LEGACY_XSTATE_BYTES: u64 = 512;
const XSTATE_HEADER_BYTES: u64 = 64;
const XSTATE_COMPACTION_BIT: u64 = 1 << 63;

/// Locate one standard-format xstate component in a Windows extended context.
/// # C: O(1) plus bounded usercopy
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlLocateExtendedFeature { return None; }
    Some(locate(call.args.a0, call.args.a1 as u32, call.args.a2))
}

fn locate(context_ex: u64, feature: u32, length: u64) -> u64 {
    if context_ex == 0 || feature < 2 || feature >= 64 { return 0; }
    let mut descriptor = [0u8; 8];
    let Some(descriptor_address) = context_ex.checked_add(16) else { return 0; };
    if uaccess::copy_from_user(&mut descriptor, descriptor_address).is_err() { return 0; }
    let offset = u32::from_le_bytes(descriptor[0..4].try_into().unwrap()) as u64;
    let available = u32::from_le_bytes(descriptor[4..8].try_into().unwrap()) as u64;
    let Some(xstate) = context_ex.checked_add(offset) else { return 0; };
    let mut header = [0u8; 16];
    if uaccess::copy_from_user(&mut header, xstate).is_err() { return 0; }
    let enabled = u64::from_le_bytes(header[0..8].try_into().unwrap());
    let compaction = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let Some((component, size)) = hal_x86_64::xstate_component_layout(feature) else { return 0; };
    if length != 0 && uaccess::put_user_u32(length, size as u32).is_err() { return 0; }
    let mask = 1u64 << feature;
    if enabled & mask == 0 || compaction & XSTATE_COMPACTION_BIT != 0 { return 0; }
    let relative = match (component as u64).checked_sub(LEGACY_XSTATE_BYTES) {
        Some(value) => value,
        None => return 0,
    };
    let end = match relative.checked_add(size as u64) { Some(value) => value, None => return 0 };
    if available < XSTATE_HEADER_BYTES || available < end { return 0; }
    xstate.checked_add(relative).unwrap_or(0)
}
