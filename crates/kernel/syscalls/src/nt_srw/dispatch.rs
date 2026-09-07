//! User boundary for the slim reader/writer lock and the condition-variable
//! wake. Every transition is a compare-and-exchange on the caller's lock word
//! decided by the ungated state module; blocking uses the same futex key the
//! address-wait service uses, so a sleeper parked by either path is reachable
//! from the other.
//!
//! Windows wakes writers and readers through two addresses two bytes apart so
//! a release disturbs only one class. A futex key covers a whole aligned word,
//! so both classes share one key here and every wake releases all sleepers:
//! waking a superset re-runs the loser's loop, while waking one of a shared
//! key could leave the intended sleeper parked.

use ipc::live::futex;
use syscall::nt::{NtCall, NtService};

use super::state::{self, Wake};

const STATUS_SUCCESS: u64 = 0;
const FUTEX_WAIT_CMD: u32 = 0;
const FUTEX_WAKE_CMD: u32 = 1;
/// The exports return void or a boolean; a caller passing an unusable lock
/// address has no status channel to receive, so the routine returns.
const NO_RESULT: u64 = 0;

/// Route the slim reader/writer and condition-variable services.
/// # C: O(contention) plus bounded user word accesses
pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::RtlAcquireSRWLockExclusive => { acquire(call.args.a0, false); Some(NO_RESULT) }
        NtService::RtlAcquireSRWLockShared => { acquire(call.args.a0, true); Some(NO_RESULT) }
        NtService::RtlReleaseSRWLockExclusive => { release(call.args.a0, false); Some(NO_RESULT) }
        NtService::RtlReleaseSRWLockShared => { release(call.args.a0, true); Some(NO_RESULT) }
        NtService::RtlTryAcquireSRWLockExclusive => Some(try_acquire_exclusive(call.args.a0) as u64),
        NtService::RtlWakeConditionVariable => { wake_condition_variable(call.args.a0); Some(STATUS_SUCCESS) }
        _ => None,
    }
}

/// The word this lock's transitions and its futex key both name.
fn word(lock: u64) -> Option<u64> { if lock == 0 || lock & 3 != 0 { None } else { Some(lock) } }

fn load(lock: u64) -> Option<u32> { uaccess::get_user_u32(lock).ok() }

fn install(lock: u64, old: u32, new: u32) -> Option<bool> {
    Some(uaccess::cmpxchg_user_u32(lock, old, new).ok()? == old)
}

/// Release every sleeper on one lock or variable word.
fn wake_all(key: u64) {
    let _ = futex::dispatch_timed(key, FUTEX_WAKE_CMD | futex::FUTEX_PRIVATE_FLAG,
        u32::MAX, futex::FUTEX_BITSET_MATCH_ANY, 0);
}

/// Release a single sleeper on one key.
fn wake_one(key: u64) {
    let _ = futex::dispatch_timed(key, FUTEX_WAKE_CMD | futex::FUTEX_PRIVATE_FLAG,
        1, futex::FUTEX_BITSET_MATCH_ANY, 0);
}

/// Park a waiter of one class until the word leaves `observed`. The class
/// chooses the address Windows parks it on; the key that address falls in is
/// what a wake can reach.
fn park(lock: u64, shared: bool, observed: u32) {
    let key = state::futex_key(state::wait_address(lock, shared));
    let _ = futex::dispatch_timed(key, FUTEX_WAIT_CMD | futex::FUTEX_PRIVATE_FLAG,
        observed, futex::FUTEX_BITSET_MATCH_ANY, 0);
}

/// Take the lock, blocking until it is free. A writer announces itself once
/// before its first attempt so readers stop overtaking it, and every later
/// attempt retires that announcement when it succeeds.
/// # C: O(contention)
pub fn acquire(lock: u64, shared: bool) -> bool {
    let Some(key) = word(lock) else { return false; };
    if !shared && !announce(key) { return false; }
    loop {
        let Some(old) = load(key) else { return false; };
        let taken = if shared { state::take_shared(old) } else { state::take_announced_exclusive(old) };
        match taken {
            Some(new) => match install(key, old, new) {
                Some(true) => return true,
                Some(false) => continue,
                None => return false,
            },
            None => park(key, shared, old),
        }
    }
}

fn announce(key: u64) -> bool {
    loop {
        let Some(old) = load(key) else { return false; };
        match install(key, old, state::announce_exclusive_waiter(old)) {
            Some(true) => return true,
            Some(false) => continue,
            None => return false,
        }
    }
}

/// Take the lock for writing without blocking or announcing a waiter.
/// # C: O(contention)
fn try_acquire_exclusive(lock: u64) -> bool {
    let Some(key) = word(lock) else { return false; };
    loop {
        let Some(old) = load(key) else { return false; };
        let Some(new) = state::try_take_exclusive(old) else { return false; };
        match install(key, old, new) {
            Some(true) => return true,
            Some(false) => continue,
            None => return false,
        }
    }
}

/// Drop one claim and disturb whoever the installed word says must run.
/// # C: O(contention)
pub fn release(lock: u64, shared: bool) -> bool {
    let Some(key) = word(lock) else { return false; };
    loop {
        let Some(old) = load(key) else { return false; };
        let new = if shared { state::drop_shared(old) } else { state::drop_exclusive(old) };
        match install(key, old, new) {
            Some(true) => {
                let wake = if shared { state::wake_after_shared_release(new) }
                    else { state::wake_after_exclusive_release(new) };
                // Waking one writer would need the two classes to sit in
                // different keys; they do not, so a single wake could land on
                // a reader and leave the writer parked. Waking all is the
                // superset that cannot lose one.
                if wake != Wake::None { wake_all(state::futex_key(state::wait_address(key, shared))); }
                return true;
            }
            Some(false) => continue,
            None => return false,
        }
    }
}

/// Advance the variable's sequence word, then release one sleeper. The word
/// must change before the wake so a sleeper that samples it after the change
/// and before the wake refuses to park at all.
fn wake_condition_variable(variable: u64) {
    let Some(key) = word(variable) else { return; };
    loop {
        let Some(old) = load(key) else { return; };
        match install(key, old, old.wrapping_add(1)) {
            Some(true) => break,
            Some(false) => continue,
            None => return,
        }
    }
    wake_one(key);
}
