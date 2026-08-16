// Sleep-state identity and availability per `32a§3`/`32a§4`.
//
// Two distinct label vocabularies exist and are routinely confused:
// `/sys/power/state` speaks the state labels (`freeze`/`standby`/`mem`) while
// `/sys/power/mem_sleep` speaks the mechanism labels
// (`s2idle`/`shallow`/`deep`). `mem` is not a mechanism — it is a pointer to
// whichever mechanism `mem_sleep` currently selects, which is why `mem` is
// listed even on a machine with no platform sleep support.

use super::ops::PlatformSuspendOps;

/// The system sleep states. Discriminants are the sysfs ordering.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum SuspendState { On = 0, ToIdle = 1, Standby = 2, Mem = 3 }

/// Every enterable state, lowest first. Excludes `On`, which is "awake".
pub const ENTERABLE: [SuspendState; 3] =
    [SuspendState::ToIdle, SuspendState::Standby, SuspendState::Mem];

impl SuspendState {
    /// `/sys/power/state` label. `On` has none. # C: O(1)
    pub fn label(self) -> Option<&'static str> {
        match self {
            SuspendState::On      => None,
            SuspendState::ToIdle  => Some("freeze"),
            SuspendState::Standby => Some("standby"),
            SuspendState::Mem     => Some("mem"),
        }
    }

    /// `/sys/power/mem_sleep` label naming the mechanism. # C: O(1)
    pub fn mem_sleep_label(self) -> Option<&'static str> {
        match self {
            SuspendState::On      => None,
            SuspendState::ToIdle  => Some("s2idle"),
            SuspendState::Standby => Some("shallow"),
            SuspendState::Mem     => Some("deep"),
        }
    }

    /// Bit position in a [`StateSet`]. # C: O(1)
    pub fn bit(self) -> u8 { 1u8 << (self as u8) }
}

/// Set of sleep states, one bit each. Copy so a snapshot can leave the lock.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct StateSet(u8);

impl StateSet {
    /// Empty set. # C: O(1)
    pub const fn empty() -> Self { StateSet(0) }
    /// `self` with `s` added. # C: O(1)
    pub fn with(self, s: SuspendState) -> Self { StateSet(self.0 | s.bit()) }
    /// Whether `s` is a member. # C: O(1)
    pub fn contains(self, s: SuspendState) -> bool { self.0 & s.bit() != 0 }
    /// Raw bits, for a stable rendering order. # C: O(1)
    pub fn bits(self) -> u8 { self.0 }
}

/// Whether the platform admits `state`, per the reference's rule: ops present,
/// `valid` present and admitting, and `enter` present. No `enter` means no
/// state is enterable however permissive `valid` is.
/// # C: O(1)
pub fn valid_state(ops: Option<&PlatformSuspendOps>, state: SuspendState) -> bool {
    match ops {
        None => false,
        Some(o) => o.valid.map_or(false, |f| f(state)) && o.enter.is_some(),
    }
}

/// The set `/sys/power/state` lists.
///
/// `freeze` and `mem` are unconditional: suspend-to-idle needs no platform
/// support, and `mem` means "the selected `mem_sleep` mechanism", which always
/// resolves to at least `s2idle`. `standby` appears only when admitted.
/// # C: O(1)
pub fn pm_states(ops: Option<&PlatformSuspendOps>) -> StateSet {
    let set = StateSet::empty().with(SuspendState::ToIdle).with(SuspendState::Mem);
    if valid_state(ops, SuspendState::Standby) { set.with(SuspendState::Standby) } else { set }
}

/// The set `/sys/power/mem_sleep` lists: the mechanisms that exist.
/// Unlike [`pm_states`], `deep` appears only when the platform admits it.
/// # C: O(1)
pub fn mem_sleep_states(ops: Option<&PlatformSuspendOps>) -> StateSet {
    let mut set = StateSet::empty().with(SuspendState::ToIdle);
    if valid_state(ops, SuspendState::Standby) { set = set.with(SuspendState::Standby); }
    if valid_state(ops, SuspendState::Mem) { set = set.with(SuspendState::Mem); }
    set
}

/// Default `mem_sleep` selection: the deepest mechanism the platform admits.
/// A machine with no platform ops selects `s2idle`, which is what makes `mem`
/// enterable there at all.
/// # C: O(1)
pub fn default_mem_sleep(ops: Option<&PlatformSuspendOps>) -> SuspendState {
    if valid_state(ops, SuspendState::Mem) { return SuspendState::Mem; }
    if valid_state(ops, SuspendState::Standby) { return SuspendState::Standby; }
    SuspendState::ToIdle
}

/// Length of `buf` up to the first newline — a sysfs write's payload.
/// # C: O(n)
pub fn line_len(buf: &[u8]) -> usize {
    buf.iter().position(|b| *b == b'\n').unwrap_or(buf.len())
}

/// Decode a `/sys/power/state` write. Returns `On` for an unknown label, which
/// the caller reports as EINVAL. Only labels present in `set` decode, so a
/// write naming an unavailable state is rejected rather than attempted.
/// # C: O(1)
pub fn decode_state(set: StateSet, buf: &[u8]) -> SuspendState {
    decode_with(set, buf, SuspendState::label)
}

/// Decode a `/sys/power/mem_sleep` write, against the mechanism labels.
/// # C: O(1)
pub fn decode_mem_sleep(set: StateSet, buf: &[u8]) -> SuspendState {
    decode_with(set, buf, SuspendState::mem_sleep_label)
}

fn decode_with(set: StateSet, buf: &[u8],
               label: fn(SuspendState) -> Option<&'static str>) -> SuspendState {
    let len = line_len(buf);
    for s in ENTERABLE {
        if !set.contains(s) { continue; }
        if let Some(l) = label(s) {
            if l.len() == len && l.as_bytes() == &buf[..len] { return s; }
        }
    }
    SuspendState::On
}

/// Resolve what a `/sys/power/state` write enters: `mem` is an indirection to
/// the current `mem_sleep` selection, every other label is itself.
/// # C: O(1)
pub fn resolve_target(written: SuspendState, mem_sleep_current: SuspendState) -> SuspendState {
    if written == SuspendState::Mem { mem_sleep_current } else { written }
}

#[cfg(test)]
#[path = "state/tests.rs"]
mod tests;
