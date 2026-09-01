//! Native unhandled-exception filter state for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use syscall::nt::{NtCall, NtService};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;

pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlRaiseException {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 {
            return Some(STATUS_INVALID_PARAMETER);
        }
        // Wine's wrapper captures the current user context and enters
        // NtRaiseException. That requires a Windows SEH dispatcher and a
        // resumable user-register frame; do not execute a user exception
        // record without those ownership guarantees.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service != NtService::RtlSetUnhandledExceptionFilter { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || (call.args.a0 != 0 && hal::UserVirtAddr::new(call.args.a0).is_none()) {
        return Some(STATUS_INVALID_PARAMETER);
    }
    cur.thread_group.nt_unhandled_filter.store(call.args.a0, Ordering::Release);
    Some(0)
}
