//! Native Wine-compatible debug entry points used by the Windows personality.
#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const DEBUG_CLASS_COUNT: u64 = 4;
const DEBUG_INIT_FLAG: u8 = 1 << 7;
const DEFAULT_DEBUG_FLAGS: u8 = (1 << 0) | (1 << 1);

/// Dispatch the debug-header ABI while the per-thread output buffer is added.
/// # C: O(1) plus one user byte read
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::WineDbgHeader { return None; }
    Some(header(call.args.a0, call.args.a1))
}

fn header(class: u64, channel: u64) -> u64 {
    if class >= DEBUG_CLASS_COUNT || channel == 0 { return (-1i64) as u64; }
    let mut channel_flags = [0u8; 1];
    if uaccess::copy_from_user(&mut channel_flags, channel).is_err() { return (-1i64) as u64; }
    let flags = channel_flags[0];
    let flags = if flags & DEBUG_INIT_FLAG != 0 { DEFAULT_DEBUG_FLAGS } else { flags };
    if flags & (1 << class) == 0 { (-1i64) as u64 } else { 0 }
}
