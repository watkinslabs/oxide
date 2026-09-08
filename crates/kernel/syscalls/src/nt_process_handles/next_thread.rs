//! Opening a handle to the next thread of one process.
//!
//! The walk is over the process's own threads, taken from the canonical task
//! registry rather than from any list this personality keeps of its own. The
//! order is the registry's, which is total and stable; what the contract fixes
//! is that every thread is reached exactly once and that running off the end
//! is a status of its own rather than a failure.

use super::{PROCESS_QUERY_INFORMATION_ACCESS, STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS, SYNCHRONIZE, THREAD_ALL_ACCESS};
use crate::nt_thread_enum;

/// The walk has passed the last thread of the process.
const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_001a;

/// Identities of one process's threads, in the registry's order. # C: O(N_tasks)
fn thread_order(tgid: u32) -> alloc::vec::Vec<u32> {
    let mut order: alloc::vec::Vec<u32> = sched::registry::thread_group(tgid).iter()
        .filter(|task| !task.reaped.load(core::sync::atomic::Ordering::Acquire)
            && !task.kernel_thread.load(core::sync::atomic::Ordering::Acquire))
        .map(|task| task.tid)
        .collect();
    order.sort_unstable();
    order
}

/// Answer the next-thread service. # C: O(N_tasks)
pub fn dispatch(call: syscall::nt::NtCall) -> u64 {
    let (process, last, access, attributes, flags, out) =
        (call.args.a0, call.args.a1, call.args.a2 as u32, call.args.a3 as u32, call.args.a4 as u32, call.args.a5);
    if !nt_thread_enum::flags_admitted(flags) { return STATUS_INVALID_PARAMETER; }
    if !nt_thread_enum::attributes_admitted(attributes) { return STATUS_INVALID_PARAMETER; }
    if access & !THREAD_ALL_ACCESS != 0 || out == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    // The process must be named by a handle carrying the query right, and the
    // pseudo handle names the caller's own process.
    let tgid = if process == u64::MAX {
        cur.tgid.load(core::sync::atomic::Ordering::Acquire)
    } else {
        let Some(target) = super::process_task(process, table, PROCESS_QUERY_INFORMATION_ACCESS) else {
            return if process <= u32::MAX as u64
                && table.contains(sched::nt_object::NtHandle::from_raw(process as u32)) {
                STATUS_ACCESS_DENIED
            } else { STATUS_INVALID_HANDLE };
        };
        target.tgid.load(core::sync::atomic::Ordering::Acquire)
    };
    // A supplied previous position must name a thread this process can see;
    // its identity, not its position, is what orders the rest of the walk.
    let last = if last == 0 { None } else {
        if last > u32::MAX as u64 { return STATUS_INVALID_HANDLE; }
        let handle = sched::nt_object::NtHandle::from_raw(last as u32);
        let Some(object) = table.get(handle, 0) else { return STATUS_INVALID_HANDLE; };
        if object.kind() != sched::nt_object::NtObjectType::Thread { return STATUS_INVALID_HANDLE; }
        let Some(task) = object.task() else { return STATUS_INVALID_HANDLE; };
        Some(task.tid)
    };
    let order = thread_order(tgid);
    let backwards = nt_thread_enum::walks_backwards(flags);
    let Some(tid) = nt_thread_enum::next_of(&order, last, backwards) else { return STATUS_NO_MORE_ENTRIES; };
    let Some(task) = sched::registry::lookup(tid) else { return STATUS_NO_MORE_ENTRIES; };
    let object = table.new_thread(task);
    let Some(native) = table.insert(object, access | SYNCHRONIZE) else { return STATUS_NO_MEMORY; };
    let flags = nt_thread_enum::handle_flags_from_attributes(attributes);
    if flags != 0 { let _ = table.set_flags(native, flags); }
    if uaccess::put_user_u64(out, u64::from(native.raw())).is_err() {
        let _ = table.close(native);
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}
