// Which platform table a sequence step consults, per `32a§4`/`32a§5`.
//
// Two tables cover eleven step positions and the routing is not uniform: the
// `prepare_late` position calls the s2idle table's `prepare`, the `prepare_noirq`
// position calls the s2idle table's `prepare_late`, and the deep table is
// consulted at neither. Getting a routing wrong silently skips a platform hook,
// so the routing is stated here once, as pure functions over the two tables.

use crate::decide::KResult;
use super::ops::{PlatformS2idleOps, PlatformSuspendOps};
use super::state::SuspendState;

/// The two tables, resolved for one transition.
#[derive(Copy, Clone)]
pub struct Tables<'a> {
    pub suspend: Option<&'a PlatformSuspendOps>,
    pub s2idle: Option<&'a PlatformS2idleOps>,
}

impl<'a> Tables<'a> {
    /// Neither table installed. # C: O(1)
    pub const fn none() -> Self { Tables { suspend: None, s2idle: None } }
}

fn idle(state: SuspendState) -> bool { state == SuspendState::ToIdle }

/// Step 3. Suspend-to-idle prefers its own hook and never falls through to the
/// deep table; every other state uses the deep table.
/// # C: O(1)
pub fn begin(t: Tables, state: SuspendState) -> KResult<()> {
    if idle(state) {
        if let Some(f) = t.s2idle.and_then(|o| o.begin) { return f(); }
        return Ok(());
    }
    match t.suspend.and_then(|o| o.begin) { Some(f) => f(state), None => Ok(()) }
}

/// Step 7. Deep states only. # C: O(1)
pub fn prepare(t: Tables, state: SuspendState) -> KResult<()> {
    if idle(state) { return Ok(()); }
    match t.suspend.and_then(|o| o.prepare) { Some(f) => f(), None => Ok(()) }
}

/// Step 9. Suspend-to-idle only, and it is the s2idle table's `prepare`.
/// # C: O(1)
pub fn prepare_late(t: Tables, state: SuspendState) -> KResult<()> {
    if !idle(state) { return Ok(()); }
    match t.s2idle.and_then(|o| o.prepare) { Some(f) => f(), None => Ok(()) }
}

/// Step 11. The s2idle table's `prepare_late`, or the deep table's.
/// # C: O(1)
pub fn prepare_noirq(t: Tables, state: SuspendState) -> KResult<()> {
    if idle(state) {
        return match t.s2idle.and_then(|o| o.prepare_late) { Some(f) => f(), None => Ok(()) };
    }
    match t.suspend.and_then(|o| o.prepare_late) { Some(f) => f(), None => Ok(()) }
}

/// Step 15. Deep states only; suspend-to-idle has no platform enter, which is
/// the reason it works with no firmware support at all.
/// # C: O(1)
pub fn enter(t: Tables, state: SuspendState) -> KResult<()> {
    if idle(state) { return Ok(()); }
    match t.suspend.and_then(|o| o.enter) { Some(f) => f(state), None => Ok(()) }
}

/// Undo 11. # C: O(1)
pub fn resume_noirq(t: Tables, state: SuspendState) {
    if idle(state) {
        if let Some(f) = t.s2idle.and_then(|o| o.restore_early) { f(); }
        return;
    }
    if let Some(f) = t.suspend.and_then(|o| o.wake) { f(); }
}

/// Undo 9. Suspend-to-idle only. # C: O(1)
pub fn resume_early(t: Tables, state: SuspendState) {
    if !idle(state) { return; }
    if let Some(f) = t.s2idle.and_then(|o| o.restore) { f(); }
}

/// Undo 7. Deep states only. # C: O(1)
pub fn resume_finish(t: Tables, state: SuspendState) {
    if idle(state) { return; }
    if let Some(f) = t.suspend.and_then(|o| o.finish) { f(); }
}

/// Undo 3. # C: O(1)
pub fn resume_end(t: Tables, state: SuspendState) {
    if idle(state) {
        if let Some(f) = t.s2idle.and_then(|o| o.end) { f(); }
        return;
    }
    if let Some(f) = t.suspend.and_then(|o| o.end) { f(); }
}

/// The device-suspend collapse hook. Deep states only. # C: O(1)
pub fn recover(t: Tables, state: SuspendState) {
    if idle(state) { return; }
    if let Some(f) = t.suspend.and_then(|o| o.recover) { f(); }
}

/// Whether the platform wants the enter repeated without waking userspace.
/// # C: O(1)
pub fn suspend_again(t: Tables, state: SuspendState) -> bool {
    if idle(state) { return false; }
    t.suspend.and_then(|o| o.suspend_again).is_some_and(|f| f())
}

/// The installed tables. # C: O(1)
pub fn installed() -> Tables<'static> {
    Tables { suspend: super::ops::suspend_ops(), s2idle: super::ops::s2idle_ops() }
}

#[cfg(test)]
#[path = "platform/tests.rs"]
mod tests;
