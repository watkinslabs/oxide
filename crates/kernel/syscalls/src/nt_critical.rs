//! Native RTL critical-section lifecycle and acquisition adapters.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ALERTED: u64 = 0x0000_0101;

/// Dispatch the 64-bit user-layout critical-section operations.
/// # C: O(1) uncontended; scheduler-dependent when contended
pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::RtlInitializeCriticalSection => Some(initialize(call.args.a0, 0)),
        NtService::RtlInitializeCriticalSectionAndSpinCount => Some(initialize(call.args.a0, call.args.a1 as u32)),
        NtService::RtlInitializeCriticalSectionEx => Some(initialize(call.args.a0, call.args.a1 as u32)),
        NtService::RtlDeleteCriticalSection => Some(delete(call.args.a0)),
        NtService::RtlEnterCriticalSection => Some(enter(call.args.a0)),
        NtService::RtlLeaveCriticalSection => Some(leave(call.args.a0)),
        _ => None,
    }
}

fn initialize(critical: u64, spin: u32) -> u64 {
    if critical == 0 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = [0u8; 40];
    bytes[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    bytes[32..36].copy_from_slice(&spin.to_le_bytes());
    if uaccess::copy_to_user(critical, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn delete(critical: u64) -> u64 {
    if critical == 0 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = [0u8; 40]; bytes[8..12].copy_from_slice(&(-1i32).to_le_bytes());
    if uaccess::copy_to_user(critical, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}

fn enter(critical: u64) -> u64 {
    const LOCK: u64 = 8; const RECURSION: u64 = 12; const OWNER: u64 = 16; const SEMAPHORE: u64 = 24;
    const SYNCHRONIZE: u32 = 0x0010_0000; const MUTANT_ALL: u32 = 0x001f_0001;
    if critical == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || cur.tid == 0 { return STATUS_INVALID_PARAMETER; }
    let lock = match critical.checked_add(LOCK) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let owner_address = match critical.checked_add(OWNER) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let recursion_address = match critical.checked_add(RECURSION) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let seen = match uaccess::cmpxchg_user_u32(lock, u32::MAX, 0) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    if seen == u32::MAX {
        if uaccess::put_user_u64(owner_address, cur.tid as u64).is_err() || uaccess::put_user_u32(recursion_address, 1).is_err() { return STATUS_INVALID_PARAMETER; }
        return STATUS_SUCCESS;
    }
    let owner = match uaccess::get_user_u64(owner_address) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    if owner == cur.tid as u64 {
        let next = seen.checked_add(1).unwrap_or(u32::MAX);
        if next == u32::MAX || uaccess::cmpxchg_user_u32(lock, seen, next).ok() != Some(seen) { return STATUS_INVALID_PARAMETER; }
        let recursion = match uaccess::get_user_u32(recursion_address) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
        if uaccess::put_user_u32(recursion_address, recursion.saturating_add(1)).is_err() { return STATUS_INVALID_PARAMETER; }
        return STATUS_SUCCESS;
    }
    let handle_address = match critical.checked_add(SEMAPHORE) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let mut raw = match uaccess::get_user_u32(handle_address) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    let table = cur.thread_group.nt_handles();
    if raw == 0 {
        let object = table.new_mutant(if owner == 0 { None } else { Some(owner) });
        let Some(native) = table.insert(object, MUTANT_ALL) else { return STATUS_INVALID_PARAMETER; };
        if uaccess::cmpxchg_user_u32(handle_address, 0, native.raw()).ok() == Some(0) { raw = native.raw(); }
        else { let _ = table.close(native); raw = match uaccess::get_user_u32(handle_address) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER }; }
    }
    let native = sched::nt_object::NtHandle::from_raw(raw);
    let Some(object) = table.get(native, SYNCHRONIZE) else { return STATUS_INVALID_PARAMETER; };
    let Some(mutant) = object.mutant() else { return STATUS_INVALID_PARAMETER; };
    let outcome = unsafe { mutant.wait(cur.tid as u64, 0, timekeeper::monotonic_ns) };
    if outcome != sched::WaitOutcome::Ready { return STATUS_ALERTED; }
    if uaccess::put_user_u64(owner_address, cur.tid as u64).is_err() || uaccess::put_user_u32(recursion_address, 1).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn leave(critical: u64) -> u64 {
    const LOCK: u64 = 8; const RECURSION: u64 = 12; const OWNER: u64 = 16; const SEMAPHORE: u64 = 24;
    if critical == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || cur.tid == 0 { return STATUS_INVALID_PARAMETER; }
    let owner_address = match critical.checked_add(OWNER) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let recursion_address = match critical.checked_add(RECURSION) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let lock = match critical.checked_add(LOCK) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let owner = match uaccess::get_user_u64(owner_address) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    let recursion = match uaccess::get_user_u32(recursion_address) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    if owner != cur.tid as u64 || recursion == 0 { return STATUS_INVALID_PARAMETER; }
    let seen = match uaccess::get_user_u32(lock) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    if uaccess::cmpxchg_user_u32(lock, seen, seen.wrapping_sub(1)).ok() != Some(seen) { return STATUS_INVALID_PARAMETER; }
    if recursion > 1 { if uaccess::put_user_u32(recursion_address, recursion - 1).is_err() { return STATUS_INVALID_PARAMETER; } return STATUS_SUCCESS; }
    if uaccess::put_user_u32(recursion_address, 0).is_err() || uaccess::put_user_u64(owner_address, 0).is_err() { return STATUS_INVALID_PARAMETER; }
    let handle_address = match critical.checked_add(SEMAPHORE) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let raw = match uaccess::get_user_u32(handle_address) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    if raw != 0 {
        let table = cur.thread_group.nt_handles(); let native = sched::nt_object::NtHandle::from_raw(raw);
        let Some(object) = table.get(native, 1) else { return STATUS_INVALID_PARAMETER; }; let Some(mutant) = object.mutant() else { return STATUS_INVALID_PARAMETER; };
        if mutant.release(cur.tid as u64).is_err() { return STATUS_INVALID_PARAMETER; } table.wake_waiters();
    }
    STATUS_SUCCESS
}
