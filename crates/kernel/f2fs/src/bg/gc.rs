//! The cleaner thread's policy: when it wakes, how long it sleeps, and which
//! kind of cleaning one wake does.
//!
//! Nothing here touches a volume. The thread body is a loop around these
//! functions, so the part that decides whether the cleaner makes progress —
//! and the part that decides whether it burns the machine doing nothing — is
//! checkable without a medium, a device or a scheduler behind it.
//!
//! The sleep is ADAPTIVE and that is the whole design. A cleaner on a fixed
//! interval is either too slow to keep a busy volume out of the wall or busy
//! enough to cost a quiet one its idle. So the interval walks: down by one
//! step when there is work worth doing, up by one step when there is not, and
//! straight to a long sleep when a pass found no victim at all. Coming back
//! from that long sleep is a jump, not a walk — a volume that has just been
//! given work should not spend five more minutes finding out.
//!
//! Urgency is a separate axis from the walk. A caller that has asked for
//! urgent cleaning gets the urgent interval regardless of where the walk had
//! got to, and it skips the idle test: the point of asking is that the caller
//! does not care that the device is busy.

use crate::opts::BackgroundGc;

/// The interval an urgent request runs at, in milliseconds.
pub const DEF_GC_THREAD_URGENT_SLEEP_TIME: u32 = 500;
/// The shortest ordinary interval, and the size of one step of the walk.
pub const DEF_GC_THREAD_MIN_SLEEP_TIME: u32 = 30_000;
/// The longest ordinary interval.
pub const DEF_GC_THREAD_MAX_SLEEP_TIME: u32 = 60_000;
/// The interval after a pass that found nothing worth cleaning.
pub const DEF_GC_THREAD_NOGC_SLEEP_TIME: u32 = 300_000;
/// Linux's one-time-GC live-block ratio ceiling.
pub const DEF_GC_VALID_THRESH_RATIO: u32 = 80;

/// Share of the volume that must be dead before background cleaning is worth
/// the writes it costs.
pub const LIMIT_INVALID_BLOCK: u64 = 40;
/// Share of that dead space below which free space counts as short.
pub const LIMIT_FREE_BLOCK: u64 = 40;

/// What the cleaner has been told to do, beyond its ordinary walk.
///
/// The three urgent modes differ in what they override: `UrgentHigh` treats
/// the device as idle whatever it is doing, `UrgentMid` runs at the urgent
/// interval but still yields to a busy device for discard, and `UrgentLow`
/// only claims idleness for the two background consumers of it.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum GcMode {
    #[default]
    Normal,
    IdleCb,
    IdleGreedy,
    IdleAt,
    UrgentHigh,
    UrgentLow,
    UrgentMid,
}

impl GcMode {
    /// The number this mode is written and read as. # C: O(1)
    pub fn as_u32(self) -> u32 {
        match self {
            GcMode::Normal => 0,
            GcMode::IdleCb => 1,
            GcMode::IdleGreedy => 2,
            GcMode::IdleAt => 3,
            GcMode::UrgentHigh => 4,
            GcMode::UrgentLow => 5,
            GcMode::UrgentMid => 6,
        }
    }

    /// The mode a stored number names, or `None` for one that names none.
    /// # C: O(1)
    pub fn from_u32(v: u32) -> Option<GcMode> {
        Some(match v {
            0 => GcMode::Normal,
            1 => GcMode::IdleCb,
            2 => GcMode::IdleGreedy,
            3 => GcMode::IdleAt,
            4 => GcMode::UrgentHigh,
            5 => GcMode::UrgentLow,
            6 => GcMode::UrgentMid,
            _ => return None,
        })
    }

    /// Whether the mode runs at the urgent interval and skips the idle test.
    /// # C: O(1)
    pub fn is_urgent(self) -> bool {
        matches!(self, GcMode::UrgentHigh | GcMode::UrgentMid)
    }

    /// Whether the mode makes a caller treat the device as idle for work of
    /// `kind`. # C: O(1)
    pub fn claims_idle(self, kind: IdleKind) -> bool {
        match self {
            GcMode::UrgentHigh => true,
            GcMode::UrgentMid => true,
            GcMode::UrgentLow => matches!(kind, IdleKind::Gc | IdleKind::Discard),
            _ => false,
        }
    }

    /// Which victim cost an idle-mode request asks for, or `None` when the
    /// mode names no preference and the caller's own choice stands.
    /// # C: O(1)
    pub fn idle_policy(self) -> Option<crate::volume::gc::Policy> {
        match self {
            GcMode::IdleCb | GcMode::IdleAt => Some(crate::volume::gc::Policy::CostBenefit),
            GcMode::IdleGreedy => Some(crate::volume::gc::Policy::Greedy),
            _ => None,
        }
    }
}

/// What a caller is asking the idle question about.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IdleKind {
    Gc,
    Discard,
    Request,
}

/// The cleaner thread's own state: its four intervals, where the walk has got
/// to, and what it has been asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GcKthread {
    pub urgent_sleep_time: u32,
    pub min_sleep_time: u32,
    pub max_sleep_time: u32,
    pub no_gc_sleep_time: u32,
    /// Set by a caller that wants the current sleep cut short.
    pub gc_wake: bool,
    pub mode: GcMode,
    /// Passes an urgent mode has left before it lapses back to normal. Zero
    /// means the mode was not asked for with a limit and does not lapse.
    pub remaining_trials: u32,
    /// Where the walk has got to: the interval the next sleep will use.
    pub wait_ms: u32,
    /// Sections an ahead-of-demand pass costs before it settles for the best it
    /// has seen. A caller that needs space NOW is not bounded by it — a bound
    /// there would fail an allocation while a good victim sat past the cut-off.
    pub max_victim_search: u32,
    /// Free-section percentage above which background GC is skipped on a
    /// zoned volume. Linux's `no_zoned_gc_percent`.
    pub no_zoned_gc_percent: u32,
}

impl Default for GcKthread {
    fn default() -> Self { Self::new() }
}

impl GcKthread {
    /// The state a freshly started cleaner runs with. # C: O(1)
    pub fn new() -> Self {
        Self {
            urgent_sleep_time: DEF_GC_THREAD_URGENT_SLEEP_TIME,
            min_sleep_time: DEF_GC_THREAD_MIN_SLEEP_TIME,
            max_sleep_time: DEF_GC_THREAD_MAX_SLEEP_TIME,
            no_gc_sleep_time: DEF_GC_THREAD_NOGC_SLEEP_TIME,
            gc_wake: false,
            mode: GcMode::Normal,
            remaining_trials: 0,
            wait_ms: DEF_GC_THREAD_MIN_SLEEP_TIME,
            max_victim_search: crate::volume::gc::victim::DEF_MAX_VICTIM_SEARCH,
            no_zoned_gc_percent: 0,
        }
    }

    /// One step up the walk.
    ///
    /// The long no-work interval is not part of the walk and is left alone:
    /// stepping up from it would carry the walk past its own ceiling.
    /// # C: O(1)
    pub fn increase_sleep_time(&self, wait: u32) -> u32 {
        if wait == self.no_gc_sleep_time { return wait; }
        if u64::from(wait) + u64::from(self.min_sleep_time) > u64::from(self.max_sleep_time) {
            self.max_sleep_time
        } else {
            wait + self.min_sleep_time
        }
    }

    /// One step down the walk.
    ///
    /// Coming back from the long no-work interval lands at the ceiling rather
    /// than one step below it — the walk is re-entered from the top, and the
    /// steps after this one bring it down.
    /// # C: O(1)
    pub fn decrease_sleep_time(&self, wait: u32) -> u32 {
        let wait = if wait == self.no_gc_sleep_time { self.max_sleep_time } else { wait };
        if i64::from(wait) - i64::from(self.min_sleep_time) < i64::from(self.min_sleep_time) {
            self.min_sleep_time
        } else {
            wait - self.min_sleep_time
        }
    }

    /// Spend one of an urgent mode's passes, dropping back to normal when the
    /// last is gone. # C: O(1)
    pub fn expire_trial(&mut self) {
        if self.mode == GcMode::Normal || self.remaining_trials == 0 { return; }
        self.remaining_trials -= 1;
        if self.remaining_trials == 0 { self.mode = GcMode::Normal; }
    }
}

/// What one wake of the cleaner does.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum GcStep {
    /// Nothing at all, and the interval is left where it was: the mount
    /// cannot be written, so neither cleaning nor a walk step means anything.
    Skip,
    /// No cleaning this pass. The interval has already been adjusted.
    Sleep,
    /// Clean. `sync` picks the greedy, space-first cost over the age-first
    /// one; `foreground` says a caller is blocked waiting for the result.
    Gc { sync: bool, foreground: bool },
}

/// What the volume and the device look like to the cleaner at one wake.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Conditions {
    pub readonly: bool,
    /// Writers are held off for a snapshot; cleaning would be one.
    pub frozen: bool,
    /// A caller is blocked in the balance path waiting for this pass.
    pub foreground: bool,
    /// Whether the device is quiet enough to spend on background work.
    pub idle: bool,
    /// Whether there is enough dead space, and little enough free space, to
    /// make cleaning worth its writes.
    pub boost: bool,
    /// Whether the cleaner's own re-entry guard is clear.
    pub can_lock: bool,
    /// A zoned volume has enough free sections for Linux's no-GC gate.
    pub zoned_free_enough: bool,
}

/// Linux uses a strict greater-than comparison for this zoned GC gate. # C: O(1)
pub fn enough_free_sections(free: u32, total: u32, limit: u32) -> bool {
    u64::from(free) > u64::from(total).saturating_mul(u64::from(limit)) / 100
}

/// Decide one wake, and move the walk. # C: O(1)
pub fn gc_round(th: &mut GcKthread, c: Conditions, bggc: BackgroundGc) -> GcStep {
    // A caller that asked for a pass gets one attempt, whether or not the
    // sleep it interrupted had run out.
    th.gc_wake = false;
    if c.readonly { return GcStep::Skip; }
    if c.frozen {
        th.wait_ms = th.increase_sleep_time(th.wait_ms);
        return GcStep::Sleep;
    }
    if c.zoned_free_enough && !c.foreground && !th.mode.is_urgent() {
        th.wait_ms = th.no_gc_sleep_time;
        return GcStep::Sleep;
    }
    if th.mode.is_urgent() {
        th.wait_ms = th.urgent_sleep_time;
        return do_gc(th, c, bggc);
    }
    if c.foreground { return do_gc(th, c, bggc); }
    // Held means another pass is already cleaning; a second one would clean
    // inside the first and find its half-emptied victim.
    if !c.can_lock { return GcStep::Sleep; }
    if !c.idle {
        th.wait_ms = th.increase_sleep_time(th.wait_ms);
        return GcStep::Sleep;
    }
    th.wait_ms = if c.boost { th.decrease_sleep_time(th.wait_ms) }
                 else { th.increase_sleep_time(th.wait_ms) };
    do_gc(th, c, bggc)
}

/// Which cleaning a pass that has decided to clean does. # C: O(1)
fn do_gc(_th: &GcKthread, c: Conditions, bggc: BackgroundGc) -> GcStep {
    // A blocked caller wants space at the least cost in blocks moved, and it
    // wants it now: the age-weighted cost is for a cleaner with time.
    let sync = if c.foreground { false } else { bggc == BackgroundGc::Sync };
    GcStep::Gc { sync, foreground: c.foreground }
}

/// Move the walk by what the pass found.
///
/// A pass that found no victim sleeps long, because nothing about the volume
/// will have changed by the next ordinary interval. A pass that did clean
/// re-enters the walk at its floor if it had been sleeping long, so a volume
/// that has just become worth cleaning is looked at again soon.
/// # C: O(1)
pub fn after_gc(th: &mut GcKthread, victim_found: bool, foreground: bool) {
    if !victim_found {
        if !foreground { th.wait_ms = th.no_gc_sleep_time; }
    } else if th.wait_ms == th.no_gc_sleep_time {
        th.wait_ms = th.min_sleep_time;
    }
}

/// Seconds a mount must go untouched before background work may spend the
/// device on itself.
pub const IDLE_INTERVAL_SECS: u64 = 5;
/// Linux's default zoned-volume free-space gate for background GC.
pub const DEF_NO_ZONED_GC_PERCENT: u32 = 60;

/// Whether the volume is quiet enough for background work of `kind`.
///
/// An urgent mode answers yes whatever the volume is doing — that is what
/// asking for it means — and the ordinary answer is how long it has been
/// since the mount last did anything for anybody.
/// # C: O(1)
pub fn is_idle(mode: GcMode, kind: IdleKind, now: u64, last_op: u64) -> bool {
    if mode.claims_idle(kind) { return true; }
    now.saturating_sub(last_op) > IDLE_INTERVAL_SECS
}

/// Whether there is enough dead space, and little enough free space, for
/// background cleaning to be worth the writes it costs.
///
/// Both halves are needed. Dead space alone is not a reason: a volume that is
/// mostly free has somewhere to write without cleaning anything, and the
/// blocks the cleaner would move may be invalidated by the next write anyway.
/// # C: O(1)
pub fn has_enough_invalid_blocks(user_blocks: u64, written_blocks: u64, free_blocks: u64,
                                 ovp_blocks: u64) -> bool {
    let invalid = user_blocks.saturating_sub(written_blocks);
    let free_user = free_blocks.saturating_sub(ovp_blocks);
    invalid > user_blocks * LIMIT_INVALID_BLOCK / 100
        && free_user < invalid * LIMIT_FREE_BLOCK / 100
}

#[cfg(test)]
#[path = "../tests/bg/gc.rs"]
mod tests;
