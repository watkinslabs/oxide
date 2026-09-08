//! Native NT handle duplication over the process-local object table.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::NtCall;

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const DUPLICATE_CLOSE_SOURCE: u32 = 1;
const DUPLICATE_SAME_ACCESS: u32 = 2;
/// The duplicate keeps the source's handle attributes; this table carries
/// none, so the option names the attributes it already copies.
const DUPLICATE_SAME_ATTRIBUTES: u32 = 4;
const CURRENT_PROCESS: u64 = u64::MAX;

/// Duplicate one process-local NT handle from the seven-argument service
/// shape: three handles, the output handle pointer, and three `ULONG`s the
/// caller stored into frame words. Reading them from a record the caller
/// never built refused every duplication.
/// # C: O(1) plus one handle-table insertion
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != syscall::nt::NtService::DuplicateObject { return None; }
    let Some(access) = crate::nt_dispatch::stack_argument(4) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(attributes) = crate::nt_dispatch::stack_argument(5) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(options) = crate::nt_dispatch::stack_argument(6) else { return Some(STATUS_INVALID_PARAMETER); };
    let request = crate::nt_obj_sig::duplicate_object([call.args.a0, call.args.a1, call.args.a2,
        call.args.a3, access, attributes, options]);
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    if request.source_process != CURRENT_PROCESS || request.target_process != CURRENT_PROCESS
        || request.target == 0 || request.attributes != 0
        || request.options & !(DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES) != 0 {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let table = cur.thread_group.nt_handles();
    let source_handle = sched::nt_object::NtHandle::from_raw(request.source);
    let Some(granted) = table.access(source_handle) else { return Some(STATUS_INVALID_HANDLE); };
    let access = if request.options & DUPLICATE_SAME_ACCESS != 0 { granted } else {
        if request.access & !granted != 0 { return Some(STATUS_ACCESS_DENIED); }
        request.access
    };
    let Some(duplicate) = table.duplicate(source_handle, access) else { return Some(STATUS_INVALID_HANDLE); };
    if uaccess::put_user_u64(request.target, u64::from(duplicate.raw())).is_err() {
        let _ = table.close(duplicate);
        return Some(STATUS_INVALID_PARAMETER);
    }
    if request.options & DUPLICATE_CLOSE_SOURCE != 0 {
        // Source consumption is a normal NT close: object-specific owners
        // must observe it, while protected sources remain live.
        let _ = crate::nt_dispatch::close_native_handle(&table, source_handle.raw());
    }
    Some(STATUS_SUCCESS)
}
