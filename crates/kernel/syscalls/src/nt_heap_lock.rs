//! Native process-heap lock ownership for the initial NT heap.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const PROCESS_HEAP: u64 = 1;
const TRUE: u64 = 1;
const FALSE: u64 = 0;

/// Dispatch process-heap lock operations without changing Linux heap state.
/// # C: O(1)
pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::RtlLockHeap => Some(lock(call.args.a0)),
        NtService::RtlUnlockHeap => Some(unlock(call.args.a0)),
        _ => None,
    }
}

fn lock(heap: u64) -> u64 {
    if heap != PROCESS_HEAP { return FALSE; }
    let Some(cur) = sched::live::current() else { return FALSE; };
    if !cur.is_nt_personality() || cur.tid == 0 { return FALSE; }
    let mut owner = cur.thread_group.nt_heap_lock.lock();
    match *owner {
        None => { *owner = Some((cur.tid as u64, 1)); TRUE }
        Some((tid, depth)) if tid == cur.tid as u64 => {
            let Some(next) = depth.checked_add(1) else { return FALSE; };
            *owner = Some((tid, next)); TRUE
        }
        Some(_) => FALSE,
    }
}

fn unlock(heap: u64) -> u64 {
    if heap != PROCESS_HEAP { return FALSE; }
    let Some(cur) = sched::live::current() else { return FALSE; };
    if !cur.is_nt_personality() || cur.tid == 0 { return FALSE; }
    let mut owner = cur.thread_group.nt_heap_lock.lock();
    match *owner {
        Some((tid, 1)) if tid == cur.tid as u64 => { *owner = None; TRUE }
        Some((tid, depth)) if tid == cur.tid as u64 && depth > 1 => {
            *owner = Some((tid, depth - 1)); TRUE
        }
        _ => FALSE,
    }
}
