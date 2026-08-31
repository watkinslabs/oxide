//! Native Windows high-resolution counter adapters.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const QPC_FREQUENCY: u64 = 10_000_000;
const NT_EPOCH_100NS: u64 = 116_444_736_000_000_000;

/// Implement Wine's `RtlQueryPerformanceCounter` over the canonical
/// monotonic clock. The exported counter uses 100-nanosecond ticks and has a
/// fixed frequency of ten million ticks per second. # C: O(1) plus usercopy
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::QuerySystemTime {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        let value = NT_EPOCH_100NS.saturating_add(timekeeper::realtime_ns() / 100);
        if uaccess::put_user_u64(call.args.a0, value).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        return Some(STATUS_SUCCESS);
    }
    if call.service == NtService::DbgUiGetThreadDebugObject {
        let Some(cur) = sched::live::current() else { return Some(0); };
        if !cur.is_nt_personality() { return Some(0); }
        return Some(0);
    }
    if call.service == NtService::DbgUiIssueRemoteBreakin {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service == NtService::RtlQueryUnbiasedInterruptTime {
        let Some(cur) = sched::live::current() else { return Some(0); };
        if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(0); }
        if uaccess::put_user_u64(call.args.a0, timekeeper::monotonic_ns() / 100).is_err() { return Some(0); }
        return Some(1);
    }
    if !matches!(call.service, NtService::RtlQueryPerformanceCounter | NtService::RtlQueryPerformanceFrequency) { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let value = if call.service == NtService::RtlQueryPerformanceCounter { timekeeper::monotonic_ns() / 100 } else { QPC_FREQUENCY };
    if uaccess::put_user_u64(call.args.a0, value).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    Some(STATUS_SUCCESS)
}
