// Per-PID-namespace number space: the numbering authority a PID namespace owns
// for the tasks it names. One space per namespace, so a task carries a distinct
// number at every level of the namespace chain it belongs to.

use alloc::collections::BTreeSet;

use crate::identity::NamespaceKind;
use crate::sync::SpinLock;

/// Default ceiling a fresh PID namespace numbers under, matching the value
/// `/proc/sys/kernel/pid_max` reports. Allocated numbers are `1..pid_max`.
pub const PID_MAX_DEFAULT: u32 = 32768;

/// Hard ceiling `pid_max` may be raised to.
pub const PID_MAX_LIMIT: u32 = 4_194_304;

/// Numbers below this are handed out only until the space has cycled once;
/// afterwards allocation wraps back to this floor instead of to 1, so the
/// low numbers a system's long-lived services hold are not recycled under
/// short-lived tasks.
const RESERVED_PIDS: u32 = 300;

/// The number the initial task holds in the initial PID namespace.
const INITIAL_TASK_NR: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PidNumberError {
    /// Namespace is not of PID kind and numbers nothing.
    NotPidNamespace,
    /// Requested number is outside `1..pid_max`.
    OutOfRange,
    /// Requested number is already held by a live identity.
    InUse,
    /// Every number in `1..pid_max` is held.
    Exhausted,
}

struct State {
    cursor: u32,
    max: u32,
    used: BTreeSet<u32>,
}

/// Numbering authority of one PID namespace. Inert for every other kind.
pub struct PidNumberSpace {
    state: SpinLock<Option<State>>,
}

impl PidNumberSpace {
    /// Build the space a namespace of `kind` owns. Only PID namespaces number
    /// anything; the initial one starts with the initial task's number already
    /// held, because that task is stamped by the boot path rather than
    /// allocated. # C: O(1)
    pub(crate) fn for_kind(kind: NamespaceKind, initial: bool) -> Self {
        if kind != NamespaceKind::Pid { return Self { state: SpinLock::new(None) }; }
        let mut used = BTreeSet::new();
        let mut cursor = INITIAL_TASK_NR;
        if initial {
            used.insert(INITIAL_TASK_NR);
            cursor = INITIAL_TASK_NR + 1;
        }
        Self { state: SpinLock::new(Some(State { cursor, max: PID_MAX_DEFAULT, used })) }
    }

    /// Ceiling this namespace numbers under. # C: O(1)
    pub fn max(&self) -> Result<u32, PidNumberError> {
        let guard = self.state.lock();
        guard.as_ref().map(|state| state.max).ok_or(PidNumberError::NotPidNamespace)
    }

    /// Raise or lower the ceiling. Numbers already held above a lowered
    /// ceiling stay held until their identity releases them, exactly as a
    /// lowered `pid_max` does not retroactively unname a running task.
    /// # C: O(1)
    pub fn set_max(&self, max: u32) -> Result<(), PidNumberError> {
        if max == 0 || max > PID_MAX_LIMIT { return Err(PidNumberError::OutOfRange); }
        let mut guard = self.state.lock();
        let state = guard.as_mut().ok_or(PidNumberError::NotPidNamespace)?;
        state.max = max;
        Ok(())
    }

    /// Take the next free number, cycling from the allocation cursor.
    /// # C: O(log N_held) amortised; O(pid_max log N_held) once cycled full
    pub fn alloc(&self) -> Result<u32, PidNumberError> {
        let mut guard = self.state.lock();
        let state = guard.as_mut().ok_or(PidNumberError::NotPidNamespace)?;
        let floor = if state.cursor <= RESERVED_PIDS { 1 } else { RESERVED_PIDS };
        let start = if state.cursor < floor { floor } else { state.cursor };
        let nr = scan(state, start, floor).ok_or(PidNumberError::Exhausted)?;
        state.used.insert(nr);
        state.cursor = if nr + 1 >= state.max { floor } else { nr + 1 };
        Ok(nr)
    }

    /// Take one exact number, for a caller that named the number itself.
    /// # C: O(log N_held)
    pub fn reserve(&self, nr: u32) -> Result<(), PidNumberError> {
        let mut guard = self.state.lock();
        let state = guard.as_mut().ok_or(PidNumberError::NotPidNamespace)?;
        if nr < 1 || nr >= state.max { return Err(PidNumberError::OutOfRange); }
        if !state.used.insert(nr) { return Err(PidNumberError::InUse); }
        Ok(())
    }

    /// Return a number to the space. # C: O(log N_held)
    pub fn free(&self, nr: u32) {
        let mut guard = self.state.lock();
        if let Some(state) = guard.as_mut() { state.used.remove(&nr); }
    }

    /// Whether a number is currently held. # C: O(log N_held)
    pub fn is_held(&self, nr: u32) -> bool {
        let guard = self.state.lock();
        guard.as_ref().is_some_and(|state| state.used.contains(&nr))
    }

    /// Count of numbers currently held. # C: O(1)
    pub fn held(&self) -> usize {
        let guard = self.state.lock();
        guard.as_ref().map_or(0, |state| state.used.len())
    }
}

/// Free number at or after `start`, wrapping once to `floor`. # C: O(pid_max)
fn scan(state: &State, start: u32, floor: u32) -> Option<u32> {
    for nr in start..state.max {
        if !state.used.contains(&nr) { return Some(nr); }
    }
    for nr in floor..start {
        if !state.used.contains(&nr) { return Some(nr); }
    }
    None
}
