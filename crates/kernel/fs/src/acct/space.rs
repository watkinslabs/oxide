// `check_free_space`: the suspend/resume hysteresis that stops the accounting
// file from finishing off a nearly full disk, plus the interval that keeps the
// exit path from calling `statfs` once per record.
//
// Pure over (state, clock, statfs result), so every branch — the not-yet-due
// fast path, the suspend edge, the resume edge, the two percentages being
// different numbers, and a backend that cannot answer — is a hosted test.

use super::parm::AcctParm;

/// Per-file free-space state. `active` is the current verdict; `needcheck_ns`
/// is the monotonic time the next `statfs` becomes due.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SpaceState {
    pub active:       bool,
    pub needcheck_ns: u64,
}

impl SpaceState {
    /// A freshly enabled file: active, and due for its first check at once —
    /// so the very first record already sees a real free-space verdict.
    /// # C: O(1)
    pub const fn new(now_ns: u64) -> Self { Self { active: true, needcheck_ns: now_ns } }
}

/// What the record writer must do before writing, decided from the clock alone.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SpaceCheck {
    /// The interval has not elapsed: the last verdict stands, no `statfs`.
    /// The payload is that standing verdict — `false` means the record is not
    /// even assembled, which is why the interval is worth having.
    Standing(bool),
    /// The interval elapsed: `statfs` the file's filesystem and feed the answer
    /// back through [`apply_statfs`] (or [`statfs_failed`] if it could not
    /// answer).
    Due,
}

/// Nanoseconds per second, for the seconds-denominated timeout tunable.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Is a fresh free-space check due? # C: O(1)
pub fn check_due(st: &SpaceState, now_ns: u64) -> SpaceCheck {
    if now_ns < st.needcheck_ns { SpaceCheck::Standing(st.active) } else { SpaceCheck::Due }
}

/// Fold a successful `statfs` into the state and answer whether to write.
/// Suspends at or below `suspend_pct` of total blocks free, resumes at or above
/// `resume_pct`; the gap between the two is the hysteresis that stops the
/// verdict oscillating while a disk hovers at the threshold. A backend that
/// reports no blocks at all has no notion of fullness, so the verdict is left
/// where it stands. The next check is scheduled whether or not the verdict
/// moved. # C: O(1)
pub fn apply_statfs(st: &mut SpaceState, now_ns: u64, p: AcctParm, f_blocks: u64, f_bavail: u64)
    -> SpaceTransition
{
    st.needcheck_ns = now_ns.saturating_add(
        (p.timeout_secs.max(0) as u64).saturating_mul(NS_PER_SEC));
    if f_blocks == 0 { return SpaceTransition::Unchanged(st.active); }
    if st.active {
        let suspend = f_blocks.saturating_mul(p.suspend_pct.max(0) as u64) / 100;
        if f_bavail <= suspend { st.active = false; return SpaceTransition::Paused; }
    } else {
        let resume = f_blocks.saturating_mul(p.resume_pct.max(0) as u64) / 100;
        if f_bavail >= resume { st.active = true; return SpaceTransition::Resumed; }
    }
    SpaceTransition::Unchanged(st.active)
}

/// `statfs` could not answer: the verdict stands and — as Linux returns before
/// scheduling — the check stays due, so the next record retries rather than
/// waiting out a whole interval on a stale answer. # C: O(1)
pub fn statfs_failed(st: &SpaceState) -> bool { st.active }

/// The edge a check produced, so the caller logs exactly the two messages
/// Linux logs and only on the transition.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SpaceTransition {
    /// Crossed below the suspend threshold; do not write this record.
    Paused,
    /// Crossed back above the resume threshold; write this record.
    Resumed,
    /// No edge. The payload is the standing verdict.
    Unchanged(bool),
}

impl SpaceTransition {
    /// Whether the record may be written. # C: O(1)
    pub fn may_write(self) -> bool {
        match self { Self::Paused => false, Self::Resumed => true, Self::Unchanged(a) => a }
    }
}
