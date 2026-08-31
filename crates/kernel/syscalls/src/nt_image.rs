//! Native PE image-header probes for the Windows personality.
#![cfg(target_os = "oxide-kernel")]
use syscall::nt::{NtCall, NtService};

/// Return the NT header address when a user image has valid PE signatures.
/// # C: O(1) plus three fault-recovering user reads
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlImageNtHeader { return None; }
    let base = call.args.a0;
    if base == 0 { return Some(0); }
    if !matches!(uaccess::get_user_u32(base), Ok(value) if value as u16 == 0x5a4d) { return Some(0); }
    let offset = match uaccess::get_user_u32(base.checked_add(0x3c)?) { Ok(value) => value as u64, Err(_) => return Some(0) };
    let header = base.checked_add(offset)?;
    if !matches!(uaccess::get_user_u32(header), Ok(0x0000_4550)) { return Some(0); }
    Some(header)
}
