//! Native FLS index table with per-thread values stored through the NT TEB.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use sync::{Spinlock, TaskList as FlsLockClass};
use syscall::{SyscallArgs, nt::{NtCall, NtService}};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const MAX_FLS_DATA_COUNT: u32 = 0xff0;
const TEB_FLS_SLOTS_OFFSET: u64 = 0x17c8;
const FLS_SLOTS_BYTES: u64 = MAX_FLS_DATA_COUNT as u64 * 8;

static INDEXES: Spinlock<Vec<Option<u64>>, FlsLockClass> = Spinlock::new(Vec::new());

/// Dispatch FLS operations; values remain per-thread in the caller's TEB.
/// # C: O(MAX_FLS_DATA_COUNT) allocation, O(1) access
pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::RtlFlsAlloc => Some(fls_alloc(call.args.a0, call.args.a1)),
        NtService::RtlFlsFree => Some(fls_free(call.args.a0 as u32)),
        NtService::RtlFlsGetValue => Some(fls_get(call.args.a0 as u32, call.args.a1)),
        NtService::RtlFlsSetValue => Some(fls_set(call.args.a0 as u32, call.args.a1)),
        NtService::RtlProcessFlsData => Some(process_fls_data(call.args.a0, call.args.a1 as u32)),
        _ => None,
    }
}

fn fls_alloc(callback: u64, output: u64) -> u64 {
    if output == 0 { return STATUS_INVALID_PARAMETER; }
    if ensure_slots().is_err() { return STATUS_NO_MEMORY; }
    let mut indexes = INDEXES.lock();
    if indexes.is_empty() { indexes.push(Some(u64::MAX)); }
    let index = indexes.iter().position(Option::is_none).unwrap_or_else(|| { indexes.push(None); indexes.len() - 1 });
    if index >= MAX_FLS_DATA_COUNT as usize { return STATUS_NO_MEMORY; }
    indexes[index] = Some(callback);
    if uaccess::put_user_u32(output, index as u32).is_err() {
        indexes[index] = None;
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}

fn fls_free(index: u32) -> u64 {
    if !valid_index(index) { return STATUS_INVALID_PARAMETER; }
    let mut indexes = INDEXES.lock();
    if indexes.get(index as usize).and_then(|callback| *callback).is_none() { return STATUS_INVALID_PARAMETER; }
    indexes[index as usize] = None;
    if let Some(slots) = current_slots(false) {
        let _ = uaccess::put_user_u64(slots + index as u64 * 8, 0);
    }
    STATUS_SUCCESS
}

fn fls_get(index: u32, output: u64) -> u64 {
    if !valid_index(index) || output == 0 || !allocated(index) { return STATUS_INVALID_PARAMETER; }
    let Some(slots) = current_slots(false) else { return STATUS_INVALID_PARAMETER; };
    let Some(address) = slots.checked_add(index as u64 * 8) else { return STATUS_INVALID_PARAMETER; };
    let Ok(value) = uaccess::get_user_u64(address) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::put_user_u64(output, value).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn fls_set(index: u32, value: u64) -> u64 {
    if !valid_index(index) || !allocated(index) { return STATUS_INVALID_PARAMETER; }
    let Ok(slots) = ensure_slots() else { return STATUS_NO_MEMORY; };
    if uaccess::put_user_u64(slots + index as u64 * 8, value).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn process_fls_data(data: u64, flags: u32) -> u64 {
    if data == 0 { return STATUS_SUCCESS; }
    let Some(slots) = current_slots(false) else { return STATUS_SUCCESS; };
    if data != slots { return STATUS_SUCCESS; }
    if flags & 1 != 0 {
        for index in 1..MAX_FLS_DATA_COUNT {
            let _ = uaccess::put_user_u64(slots + index as u64 * 8, 0);
        }
    }
    if flags & 2 != 0 {
        let free = NtCall { service: NtService::FreeHeap, args: SyscallArgs { a0: 0, a1: 0, a2: slots, a3: 0, a4: 0, a5: 0 } };
        let _ = crate::nt_heap::dispatch(free);
        if let Some(task) = sched::live::current() {
            let _ = uaccess::put_user_u64(task.nt_teb().saturating_add(TEB_FLS_SLOTS_OFFSET), 0);
        }
    }
    STATUS_SUCCESS
}

fn valid_index(index: u32) -> bool { index != 0 && index < MAX_FLS_DATA_COUNT }

fn allocated(index: u32) -> bool {
    INDEXES.lock().get(index as usize).and_then(|callback| *callback).is_some()
}

fn current_slots(create: bool) -> Option<u64> {
    let task = sched::live::current()?;
    let teb = task.nt_teb();
    if teb == 0 { return None; }
    let address = teb.checked_add(TEB_FLS_SLOTS_OFFSET)?;
    let Ok(slots) = uaccess::get_user_u64(address) else { return None; };
    if slots != 0 || !create { return (slots != 0).then_some(slots); }
    let call = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 1, a1: 0, a2: FLS_SLOTS_BYTES, a3: 0, a4: 0, a5: 0 } };
    let slots = crate::nt_heap::dispatch(call).filter(|value| *value != 0)?;
    uaccess::put_user_u64(address, slots).ok()?;
    Some(slots)
}

fn ensure_slots() -> Result<u64, ()> {
    let Some(task) = sched::live::current() else { return Err(()); };
    if !task.is_nt_personality() { return Err(()); }
    current_slots(true).ok_or(())
}
