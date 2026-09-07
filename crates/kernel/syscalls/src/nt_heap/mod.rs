//! Process-heap ABI shim.
//!
//! Module manifest:
//! - `backend` — reservations, commits and body access for one address space
//! - `info`    — heap handles, heap information classes, walk and user records
//!
//! Block policy — sizes, splitting, coalescing, growth — belongs to the
//! allocator crate, which is hosted-tested without an address space.

mod backend;
mod info;

use ntheap::flags::HEAP_GROWABLE;
use syscall::nt::{self, NtCall, NtHeapCall};

/// Windows failure value of `RtlSizeHeap`.
const SIZE_FAILURE: u64 = u64::MAX;
/// Windows failure value of the pointer-returning heap entries.
const POINTER_FAILURE: u64 = 0;
/// `RtlFreeHeap` success.
const FREE_SUCCESS: u64 = 1;
/// `RtlFreeHeap` failure.
const FREE_FAILURE: u64 = 0;

/// Serve the heap subset, returning `None` for every other NT service.
/// # C: O(log N_free) per call
/// # Lk: process heap lock; # Ctx: process; # Sleeps: no
pub fn dispatch(call: NtCall) -> Option<u64> {
    if let Some(result) = info::dispatch_info(call) { return Some(result); }
    if call.service == nt::NtService::RtlFreeUserStack {
        if call.args.a0 == 0 { return Some(0); }
        let free = NtCall { service: nt::NtService::FreeHeap, args: syscall::SyscallArgs { a0: 0, a1: 0, a2: call.args.a0, a3: 0, a4: 0, a5: 0 } };
        let _ = dispatch(free);
        return Some(0);
    }
    let heap_call = nt::decode_heap(call).ok()?;
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return Some(info::STATUS_INVALID_PARAMETER); }
    // SAFETY: `mm_ref` reads the current task's address space while this
    // thread is running on it, and the clone keeps it alive for the call.
    let mm = (unsafe { cur.mm_ref() }).map(|mm| mm.clone())?;
    let mut backend = backend::MmBackend { as_: &mm };
    let mut state = cur.thread_group.nt_heap.lock();
    let heap = state.get_or_insert_with(|| ntheap::Heap::new(HEAP_GROWABLE));
    Some(match heap_call {
        NtHeapCall::Allocate { heap: _, flags, size } => {
            let Ok(size) = usize::try_from(size) else { return Some(POINTER_FAILURE); };
            heap.allocate(&mut backend, flags as u32, size).unwrap_or(POINTER_FAILURE)
        }
        NtHeapCall::Free { heap: _, flags: _, base } => {
            if heap.free(&mut backend, base) { FREE_SUCCESS } else { FREE_FAILURE }
        }
        NtHeapCall::Reallocate { heap: _, flags, base, size } => {
            let Ok(size) = usize::try_from(size) else { return Some(POINTER_FAILURE); };
            heap.reallocate(&mut backend, flags as u32, base, size).unwrap_or(POINTER_FAILURE)
        }
        NtHeapCall::Size { heap: _, flags: _, base } => {
            heap.size(&backend, base).map(|size| size as u64).unwrap_or(SIZE_FAILURE)
        }
    })
}
