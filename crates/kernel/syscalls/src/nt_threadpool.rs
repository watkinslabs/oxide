//! Native NT thread-pool wait lifecycle boundary.
#![cfg(target_os = "oxide-kernel")]
use syscall::nt::{NtCall, NtService};
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
/// Reject an unregistered wait object without touching Linux scheduler state.
/// # C: O(1)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlDeregisterWait { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    if call.args.a0 == 0 { return Some(STATUS_INVALID_HANDLE); }
    Some(STATUS_INVALID_HANDLE)
}
