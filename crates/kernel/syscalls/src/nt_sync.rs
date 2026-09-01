//! Native semaphore adapters for the NT object boundary.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtObjectCall, NtService};
use ipc::live::futex;

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const SEMAPHORE_ALL_ACCESS: u32 = 0x001f_0003;
const SEMAPHORE_MODIFY_STATE: u32 = 0x0002;
const STATUS_TIMEOUT: u64 = 0x0000_0102;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_NOT_OWNER: u64 = 0xc000_005a;
const SRW_SHARED: u32 = 0x0001;
const SRW_EXCLUSIVE_HELD: u32 = 0x0001;
const SRW_OWNERS_SHIFT: u32 = 16;
const FUTEX_WAIT_CMD: u32 = 0;
const FUTEX_WAKE_CMD: u32 = 1;

/// Dispatch semaphore creation and release; waits share the NT object adapter.
/// # C: O(1)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlSleepConditionVariableCS {
        return Some(sleep_condition_variable_cs(call));
    }
    if call.service == NtService::RtlSleepConditionVariableSRW {
        return Some(sleep_condition_variable_srw(call));
    }
    let object = match syscall::nt::decode_object(call) {
        Ok(object @ (NtObjectCall::CreateSemaphore { .. } | NtObjectCall::ReleaseSemaphore { .. })) => object,
        _ => return None,
    };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    Some(match object {
        NtObjectCall::CreateSemaphore { handle, desired_access, attributes, initial, maximum } => {
            if attributes != 0 || desired_access & !SEMAPHORE_ALL_ACCESS != 0 || initial < 0 || maximum <= 0 || initial > maximum {
                return Some(STATUS_INVALID_PARAMETER);
            }
            let object = table.new_semaphore(initial, maximum);
            let Some(native) = table.insert(object, desired_access) else { return Some(STATUS_NO_MEMORY); };
            if uaccess::put_user_u32(handle.as_u64(), native.raw()).is_err() {
                let _ = table.close(native); STATUS_INVALID_PARAMETER
            } else { STATUS_SUCCESS }
        }
        NtObjectCall::ReleaseSemaphore { handle, count, previous } => {
            let native = sched::nt_object::NtHandle::from_raw(handle);
            let Some(object) = table.get(native, SEMAPHORE_MODIFY_STATE) else {
                return Some(if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE });
            };
            if object.kind() != sched::nt_object::NtObjectType::Semaphore { return Some(STATUS_INVALID_HANDLE); }
            let Some(semaphore) = object.semaphore() else { return Some(STATUS_INVALID_HANDLE); };
            let Some(old) = semaphore.release(count) else { return Some(STATUS_INVALID_PARAMETER); };
            table.wake_waiters();
            if let Some(previous) = previous {
                if uaccess::put_user_u32(previous.as_u64(), old).is_err() { return Some(STATUS_INVALID_PARAMETER); }
            }
            STATUS_SUCCESS
        }
        _ => return None,
    })
}

/// Release a critical section, wait on the condition-variable word, then
/// reacquire the section before returning. The user address is the futex key,
/// so the value check and waiter enqueue retain Linux's lost-wakeup contract.
fn sleep_condition_variable_cs(call: NtCall) -> u64 {
    const FUTEX_WAIT: u32 = 0;
    let variable = call.args.a0;
    let critical = call.args.a1;
    if variable == 0 || critical == 0 || (variable & 3) != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let expected = match uaccess::get_user_u32(variable) {
        Ok(value) => value,
        Err(_) => return STATUS_ACCESS_VIOLATION,
    };
    let timeout = if call.args.a2 == 0 {
        None
    } else {
        match syscall::UserPtr::<i64>::new(call.args.a2) {
            Ok(pointer) => Some(pointer),
            Err(_) => return STATUS_INVALID_PARAMETER,
        }
    };
    let deadline = match crate::nt_dispatch::wait_deadline(timeout) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let leave = NtCall { service: NtService::RtlLeaveCriticalSection, args: syscall::SyscallArgs { a0: critical, ..call.args } };
    if crate::nt_critical::dispatch(leave) != Some(STATUS_SUCCESS) {
        return STATUS_INVALID_PARAMETER;
    }
    let wait = futex::dispatch_timed(
        variable,
        FUTEX_WAIT | futex::FUTEX_PRIVATE_FLAG,
        expected,
        futex::FUTEX_BITSET_MATCH_ANY,
        deadline,
    );
    let enter = NtCall { service: NtService::RtlEnterCriticalSection, args: syscall::SyscallArgs { a0: critical, ..call.args } };
    let reacquire = crate::nt_critical::dispatch(enter).unwrap_or(STATUS_INVALID_PARAMETER);
    if reacquire != STATUS_SUCCESS {
        return reacquire;
    }
    if wait == 0 || wait == -(syscall::errno::Errno::Eagain.as_i32() as i64) {
        STATUS_SUCCESS
    } else if wait == -(syscall::errno::Errno::Etimedout.as_i32() as i64) {
        STATUS_TIMEOUT
    } else {
        STATUS_INVALID_PARAMETER
    }
}

/// Release the compact SRW state, wait on the condition word, then acquire
/// the same shared or exclusive mode. The state word is futex-keyed, giving
/// the release/wait/reacquire path Linux's value-checking wake contract.
fn sleep_condition_variable_srw(call: NtCall) -> u64 {
    let variable = call.args.a0;
    let lock = call.args.a1;
    let flags = call.args.a3 as u32;
    if variable == 0 || lock == 0 || (variable & 3) != 0 || (lock & 3) != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let expected = match uaccess::get_user_u32(variable) {
        Ok(value) => value,
        Err(_) => return STATUS_ACCESS_VIOLATION,
    };
    let timeout = if call.args.a2 == 0 { None } else {
        match syscall::UserPtr::<i64>::new(call.args.a2) {
            Ok(pointer) => Some(pointer), Err(_) => return STATUS_INVALID_PARAMETER,
        }
    };
    let deadline = match crate::nt_dispatch::wait_deadline(timeout) {
        Ok(value) => value, Err(status) => return status,
    };
    let shared = flags & SRW_SHARED != 0;
    if !release_srw(lock, shared) { return STATUS_NOT_OWNER; }
    let wait = futex::dispatch_timed(variable, FUTEX_WAIT_CMD | futex::FUTEX_PRIVATE_FLAG,
        expected, futex::FUTEX_BITSET_MATCH_ANY, deadline);
    if !acquire_srw(lock, shared) { return STATUS_INVALID_PARAMETER; }
    if wait == 0 || wait == -(syscall::errno::Errno::Eagain.as_i32() as i64) {
        STATUS_SUCCESS
    } else if wait == -(syscall::errno::Errno::Etimedout.as_i32() as i64) {
        STATUS_TIMEOUT
    } else {
        STATUS_INVALID_PARAMETER
    }
}

fn release_srw(lock: u64, shared: bool) -> bool {
    loop {
        let Ok(old) = uaccess::get_user_u32(lock) else { return false; };
        let owners = old >> SRW_OWNERS_SHIFT;
        let new = if shared {
            if old & SRW_EXCLUSIVE_HELD != 0 || owners == 0 { return false; }
            old - (1 << SRW_OWNERS_SHIFT)
        } else {
            if old & SRW_EXCLUSIVE_HELD == 0 || owners != 1 { return false; }
            old & !((1 << SRW_OWNERS_SHIFT) - 1 | SRW_EXCLUSIVE_HELD)
        };
        if uaccess::cmpxchg_user_u32(lock, old, new).ok() == Some(old) {
            let _ = futex::dispatch_timed(lock, FUTEX_WAKE_CMD | futex::FUTEX_PRIVATE_FLAG,
                u32::MAX, futex::FUTEX_BITSET_MATCH_ANY, 0);
            return true;
        }
    }
}

fn acquire_srw(lock: u64, shared: bool) -> bool {
    loop {
        let Ok(old) = uaccess::get_user_u32(lock) else { return false; };
        let owners = old >> SRW_OWNERS_SHIFT;
        let can_take = if shared { old & SRW_EXCLUSIVE_HELD == 0 } else { old == 0 };
        if can_take {
            let new = if shared { old + (1 << SRW_OWNERS_SHIFT) }
                else { SRW_EXCLUSIVE_HELD | (1 << SRW_OWNERS_SHIFT) };
            if uaccess::cmpxchg_user_u32(lock, old, new).ok() == Some(old) { return true; }
        } else {
            let wait = futex::dispatch_timed(lock, FUTEX_WAIT_CMD | futex::FUTEX_PRIVATE_FLAG,
                old, futex::FUTEX_BITSET_MATCH_ANY, 0);
            if wait != 0 && wait != -(syscall::errno::Errno::Eagain.as_i32() as i64) { return false; }
        }
        if owners == u32::MAX { return false; }
    }
}
