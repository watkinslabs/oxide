//! Native NT registry-handle boundary.

use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;

/// Create the process-local current-user key handle used by ntdll callers.
/// # C: O(1) plus one NT handle-table insertion
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlOpenCurrentUser { return None; }
    let Some(current) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !current.is_nt_personality() || call.args.a1 == 0 || call.args.a0 > u32::MAX as u64 {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let handles = current.thread_group.nt_handles();
    let Some(handle) = handles.insert(handles.new_key(), call.args.a0 as u32) else {
        return Some(STATUS_NO_MEMORY);
    };
    if uaccess::put_user_u32(call.args.a1, handle.raw()).is_err() {
        let _ = handles.close(handle);
        return Some(STATUS_INVALID_PARAMETER);
    }
    Some(STATUS_SUCCESS)
}
