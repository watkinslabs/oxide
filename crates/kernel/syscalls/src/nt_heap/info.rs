//! Heap handles, information classes, walk entries and user records.

use syscall::nt::{self, NtCall};

pub const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_INVALID_INFO_CLASS: u64 = 0xc000_0003;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_UNSUCCESSFUL: u64 = 0xc000_0001;
const STATUS_SUCCESS: u64 = 0;
const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_001a;
/// The canonical process heap handle.
const PROCESS_HEAP: u64 = 1;
const HEAP_COMPATIBILITY_INFORMATION: u64 = 0;
/// Standard (non-frontend) heap compatibility mode.
const HEAP_COMPATIBILITY_STANDARD: u32 = 0;
/// Low-fragmentation frontend, the only other value Windows accepts.
const HEAP_COMPATIBILITY_LFH: u32 = 2;
/// `RtlWalkHeap` entry bytes and its flag bits.
const ENTRY_BYTES: usize = 40;
const ENTRY_BUSY: u16 = 0x0001;
const ENTRY_BLOCK: u16 = 0x0010;
const ENTRY_COMMITTED: u16 = 0x4000;

/// Serve the heap services that do not carry a block pointer of their own.
/// # C: O(1) except the walk step
pub fn dispatch_info(call: NtCall) -> Option<u64> {
    match call.service {
        nt::NtService::RtlValidateHeap => Some(validate_heap(call)),
        nt::NtService::RtlWalkHeap => Some(walk_heap(call)),
        nt::NtService::RtlCompactHeap => Some(0),
        nt::NtService::RtlCreateHeap => Some(create_heap(call)),
        nt::NtService::RtlDestroyHeap => Some(destroy_heap(call)),
        nt::NtService::RtlGetProcessHeaps => Some(get_process_heaps(call)),
        nt::NtService::RtlGetUserInfoHeap => Some(get_user_info(call)),
        nt::NtService::RtlSetUserValueHeap => Some(set_user_value(call)),
        nt::NtService::RtlQueryHeapInformation => Some(query_heap_information(call)),
        nt::NtService::RtlSetHeapInformation => Some(set_heap_information(call)),
        _ => None,
    }
}

/// The calling task, once it is running the native personality.
fn nt_current() -> Option<&'static sched::Task> {
    let cur = sched::live::current()?;
    if cur.is_nt_personality() { Some(cur) } else { None }
}

fn walk_heap(call: NtCall) -> u64 {
    if call.args.a0 != PROCESS_HEAP || call.args.a1 == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = nt_current() else { return STATUS_INVALID_PARAMETER; };
    let mut entry = [0u8; ENTRY_BYTES];
    if uaccess::copy_from_user(&mut entry, call.args.a1).is_err() { return STATUS_INVALID_PARAMETER; }
    let cursor = u64::from_le_bytes(entry[0..8].try_into().unwrap());
    // SAFETY: `mm_ref` reads the current task's address space while this
    // thread is running on it, and the clone keeps it alive for the call.
    let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
    let backend = super::backend::MmBackend { as_: &mm };
    let mut state = cur.thread_group.nt_heap.lock();
    let Some(heap) = state.as_mut() else { return STATUS_NO_MORE_ENTRIES; };
    let Some(block) = heap.walk(&backend, cursor) else { return STATUS_NO_MORE_ENTRIES; };
    entry = [0; ENTRY_BYTES];
    entry[0..8].copy_from_slice(&block.data.to_le_bytes());
    entry[8..16].copy_from_slice(&(block.size as u64).to_le_bytes());
    let flags = ENTRY_COMMITTED | if block.busy { ENTRY_BUSY | ENTRY_BLOCK } else { 0 };
    entry[18..20].copy_from_slice(&flags.to_le_bytes());
    if uaccess::copy_to_user(call.args.a1, &entry).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn validate_heap(call: NtCall) -> u64 {
    if call.args.a0 != PROCESS_HEAP { return 0; }
    let Some(cur) = nt_current() else { return 0; };
    if call.args.a2 == 0 { return 1; }
    // SAFETY: `mm_ref` reads the current task's address space while this
    // thread is running on it, and the clone keeps it alive for the call.
    let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return 0; };
    let backend = super::backend::MmBackend { as_: &mm };
    let state = cur.thread_group.nt_heap.lock();
    match state.as_ref() { Some(heap) => heap.validate(&backend, call.args.a2) as u64, None => 0 }
}

fn set_heap_information(call: NtCall) -> u64 {
    if call.args.a0 != PROCESS_HEAP { return STATUS_INVALID_HANDLE; }
    if nt_current().is_none() { return STATUS_INVALID_PARAMETER; }
    if call.args.a1 != HEAP_COMPATIBILITY_INFORMATION { return STATUS_SUCCESS; }
    if call.args.a3 < core::mem::size_of::<u32>() as u64 { return STATUS_BUFFER_TOO_SMALL; }
    if call.args.a2 == 0 { return STATUS_ACCESS_VIOLATION; }
    let mut value = [0u8; 4];
    if uaccess::copy_from_user(&mut value, call.args.a2).is_err() { return STATUS_ACCESS_VIOLATION; }
    let compatibility = u32::from_le_bytes(value);
    if compatibility != HEAP_COMPATIBILITY_STANDARD && compatibility != HEAP_COMPATIBILITY_LFH { return STATUS_UNSUCCESSFUL; }
    STATUS_SUCCESS
}

fn query_heap_information(call: NtCall) -> u64 {
    if call.args.a0 != PROCESS_HEAP { return STATUS_ACCESS_VIOLATION; }
    if nt_current().is_none() { return STATUS_INVALID_PARAMETER; }
    if call.args.a1 != HEAP_COMPATIBILITY_INFORMATION { return STATUS_INVALID_INFO_CLASS; }
    if call.args.a4 != 0 && uaccess::put_user_u64(call.args.a4, core::mem::size_of::<u32>() as u64).is_err() { return STATUS_ACCESS_VIOLATION; }
    if call.args.a3 < core::mem::size_of::<u32>() as u64 { return STATUS_BUFFER_TOO_SMALL; }
    if call.args.a2 == 0 { return STATUS_ACCESS_VIOLATION; }
    // Blocks are served from the heap's own regions with no separate
    // low-fragmentation frontend, which is the standard compatibility mode.
    if uaccess::put_user_u32(call.args.a2, HEAP_COMPATIBILITY_STANDARD).is_err() { return STATUS_ACCESS_VIOLATION; }
    STATUS_SUCCESS
}

fn create_heap(call: NtCall) -> u64 {
    if nt_current().is_none() { return STATUS_INVALID_PARAMETER; }
    let _ = (call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4, call.args.a5);
    PROCESS_HEAP
}

fn destroy_heap(call: NtCall) -> u64 {
    if nt_current().is_none() { return call.args.a0; }
    call.args.a0
}

fn get_process_heaps(call: NtCall) -> u64 {
    if call.args.a0 == 0 { return 1; }
    if call.args.a1 == 0 { return 0; }
    if uaccess::put_user_u64(call.args.a1, PROCESS_HEAP).is_err() { return 0; }
    1
}

fn get_user_info(call: NtCall) -> u64 {
    if call.args.a0 != PROCESS_HEAP || call.args.a2 == 0 || call.args.a3 == 0 || call.args.a4 == 0 { return 0; }
    let Some(cur) = nt_current() else { return 0; };
    let state = cur.thread_group.nt_heap.lock();
    let Some((value, flags)) = state.as_ref().and_then(|heap| heap.user_info(call.args.a2)) else { return 0; };
    if uaccess::put_user_u64(call.args.a3, value).is_err() || uaccess::put_user_u32(call.args.a4, flags).is_err() { return 0; }
    1
}

fn set_user_value(call: NtCall) -> u64 {
    if call.args.a0 != PROCESS_HEAP || call.args.a2 == 0 { return 0; }
    let Some(cur) = nt_current() else { return 0; };
    let mut state = cur.thread_group.nt_heap.lock();
    match state.as_mut() { Some(heap) => heap.set_user_value(call.args.a2, call.args.a3) as u64, None => 0 }
}
