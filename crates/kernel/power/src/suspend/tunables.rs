// The `/sys/power` boolean tunables and the `mem_sleep` selection (`32a§11`).
//
// Separate from `state.rs` because these are mutable machine state while that
// module is pure decisions over it.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use super::state::SuspendState;

static SYNC_ON_SUSPEND: AtomicBool = AtomicBool::new(true);
static PM_ASYNC: AtomicBool = AtomicBool::new(true);
static PM_DEBUG_MESSAGES: AtomicBool = AtomicBool::new(false);
static MEM_SLEEP_CURRENT: AtomicU8 = AtomicU8::new(SuspendState::ToIdle as u8);

/// Whether step 0 of `32a§5` runs. # C: O(1)
pub fn sync_on_suspend() -> bool { SYNC_ON_SUSPEND.load(Ordering::Acquire) }
/// Set whether step 0 runs. # C: O(1)
pub fn set_sync_on_suspend(v: bool) { SYNC_ON_SUSPEND.store(v, Ordering::Release); }

/// Whether device phases may run asynchronously. # C: O(1)
pub fn pm_async() -> bool { PM_ASYNC.load(Ordering::Acquire) }
/// Set whether device phases may run asynchronously. # C: O(1)
pub fn set_pm_async(v: bool) { PM_ASYNC.store(v, Ordering::Release); }

/// Whether sleep-transition debug logging is on. # C: O(1)
pub fn pm_debug_messages() -> bool { PM_DEBUG_MESSAGES.load(Ordering::Acquire) }
/// Set sleep-transition debug logging. # C: O(1)
pub fn set_pm_debug_messages(v: bool) { PM_DEBUG_MESSAGES.store(v, Ordering::Release); }

/// The mechanism `mem` currently means. # C: O(1)
pub fn mem_sleep_current() -> SuspendState {
    match MEM_SLEEP_CURRENT.load(Ordering::Acquire) {
        x if x == SuspendState::Mem as u8     => SuspendState::Mem,
        x if x == SuspendState::Standby as u8 => SuspendState::Standby,
        _ => SuspendState::ToIdle,
    }
}

/// Select the mechanism `mem` means. # C: O(1)
pub fn set_mem_sleep_current(s: SuspendState) { MEM_SLEEP_CURRENT.store(s as u8, Ordering::Release); }

/// Whether a sleep transition is running. A second one is refused rather than
/// queued: two transitions racing would each unwind the other's steps.
/// # C: O(1)
pub fn transition_in_progress() -> bool { crate::transition::in_progress() }

/// Claim the transition. False when one is already running. # C: O(1)
pub fn try_claim_transition() -> bool {
    crate::transition::try_claim_legacy()
}

/// Release the transition claim. # C: O(1)
pub fn release_transition() { crate::transition::release(); }

/// Parse a `/sys/power` boolean attribute write: a decimal `0` or `1`, with an
/// optional trailing newline. Anything else is rejected.
/// # C: O(n)
pub fn parse_bool(buf: &[u8]) -> Option<bool> {
    let len = super::state::line_len(buf);
    match &buf[..len] { b"0" => Some(false), b"1" => Some(true), _ => None }
}

/// Parse a `/sys/power/wakeup_count` write: an unsigned decimal, with an
/// optional trailing newline. Empty and overlong inputs are rejected.
/// # C: O(n)
pub fn parse_u32(buf: &[u8]) -> Option<u32> {
    let len = super::state::line_len(buf);
    let digits = &buf[..len];
    if digits.is_empty() { return None; }
    let mut v: u32 = 0;
    for b in digits {
        if !b.is_ascii_digit() { return None; }
        v = v.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(v)
}

#[cfg(test)]
#[path = "tunables/tests.rs"]
mod tests;
