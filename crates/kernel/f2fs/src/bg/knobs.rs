//! The controls a user turns, and what each will accept.
//!
//! Every knob here drives machinery that exists, and that is the whole
//! criterion for one being here: a writable attribute whose value nothing
//! reads is worse than an absent one, because a tool that sets it believes it
//! has changed something.
//!
//! Bounds are refusals, not clamps. A tool that asks for a granularity of
//! twice the longest list has misunderstood the unit, and silently giving it
//! the largest legal value hides that from it forever.

use syscall::errno::Errno;

use super::discard::{IoAware, MAX_PLIST_NUM, MIN_DISCARD_GRANULARITY};
use super::gc::GcMode;
use super::state::Bg;

/// One writable control.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Knob {
    GcUrgentSleepTime,
    GcMinSleepTime,
    GcMaxSleepTime,
    GcNoGcSleepTime,
    /// The urgent cleaning modes, by the numbers upstream writes here: 0 off,
    /// 1 high, 2 low, 3 mid.
    GcUrgent,
    /// The idle-cleaning cost, by the mode's own number.
    GcIdle,
    /// Passes an urgent mode lasts before it lapses.
    GcRemainingTrials,
    /// Sections an ahead-of-demand pass costs before it settles for the best it
    /// has seen. A caller that needs space NOW is deliberately not bounded by
    /// it, so this only ever widens or narrows the BACKGROUND pass.
    MaxVictimSearch,
    DiscardGranularity,
    MaxOrderedDiscard,
    DiscardIoAwareGran,
    DiscardIoAware,
    DiscardUrgentUtil,
    MaxDiscardRequest,
    MinDiscardIssueTime,
    MidDiscardIssueTime,
    MaxDiscardIssueTime,
}

/// The name the control is published under. # C: O(1)
pub fn name(k: Knob) -> &'static str {
    match k {
        Knob::GcUrgentSleepTime => "gc_urgent_sleep_time",
        Knob::GcMinSleepTime => "gc_min_sleep_time",
        Knob::GcMaxSleepTime => "gc_max_sleep_time",
        Knob::GcNoGcSleepTime => "gc_no_gc_sleep_time",
        Knob::GcUrgent => "gc_urgent",
        Knob::GcIdle => "gc_idle",
        Knob::GcRemainingTrials => "gc_remaining_trials",
        Knob::MaxVictimSearch => "max_victim_search",
        Knob::DiscardGranularity => "discard_granularity",
        Knob::MaxOrderedDiscard => "max_ordered_discard",
        Knob::DiscardIoAwareGran => "discard_io_aware_gran",
        Knob::DiscardIoAware => "discard_io_aware",
        Knob::DiscardUrgentUtil => "discard_urgent_util",
        Knob::MaxDiscardRequest => "max_discard_request",
        Knob::MinDiscardIssueTime => "min_discard_issue_time",
        Knob::MidDiscardIssueTime => "mid_discard_issue_time",
        Knob::MaxDiscardIssueTime => "max_discard_issue_time",
    }
}

/// Every control, in the order they are published. # C: O(1)
pub const ALL: &[Knob] = &[
    Knob::GcUrgentSleepTime, Knob::GcMinSleepTime, Knob::GcMaxSleepTime,
    Knob::GcNoGcSleepTime, Knob::GcUrgent, Knob::GcIdle, Knob::GcRemainingTrials,
    Knob::MaxVictimSearch,
    Knob::DiscardGranularity, Knob::MaxOrderedDiscard, Knob::DiscardIoAwareGran,
    Knob::DiscardIoAware, Knob::DiscardUrgentUtil, Knob::MaxDiscardRequest,
    Knob::MinDiscardIssueTime, Knob::MidDiscardIssueTime, Knob::MaxDiscardIssueTime,
];

/// The number a control reads back as. # C: O(1)
pub fn show(bg: &Bg, k: Knob) -> u64 {
    match k {
        Knob::GcUrgentSleepTime => u64::from(bg.gc.lock().urgent_sleep_time),
        Knob::GcMinSleepTime => u64::from(bg.gc.lock().min_sleep_time),
        Knob::GcMaxSleepTime => u64::from(bg.gc.lock().max_sleep_time),
        Knob::GcNoGcSleepTime => u64::from(bg.gc.lock().no_gc_sleep_time),
        Knob::GcUrgent => u64::from(urgent_of(bg.gc.lock().mode)),
        Knob::GcIdle => u64::from(bg.gc.lock().mode.as_u32()),
        Knob::GcRemainingTrials => u64::from(bg.gc.lock().remaining_trials),
        Knob::MaxVictimSearch => u64::from(bg.gc.lock().max_victim_search),
        Knob::DiscardGranularity => u64::from(bg.dcc.lock().granularity),
        Knob::MaxOrderedDiscard => u64::from(bg.dcc.lock().max_ordered_discard),
        Knob::DiscardIoAwareGran => u64::from(bg.dcc.lock().io_aware_gran),
        Knob::DiscardIoAware => u64::from(bg.dcc.lock().io_aware.as_u32()),
        Knob::DiscardUrgentUtil => u64::from(bg.dcc.lock().urgent_util),
        Knob::MaxDiscardRequest => u64::from(bg.dcc.lock().max_discard_request),
        Knob::MinDiscardIssueTime => u64::from(bg.dcc.lock().min_issue_time),
        Knob::MidDiscardIssueTime => u64::from(bg.dcc.lock().mid_issue_time),
        Knob::MaxDiscardIssueTime => u64::from(bg.dcc.lock().max_issue_time),
    }
}

/// Which urgency number a mode reads back as.
///
/// Only the three the control can set have one; every other mode was set
/// through a different control and reads as off here.
/// # C: O(1)
fn urgent_of(mode: GcMode) -> u32 {
    match mode {
        GcMode::UrgentHigh => 1,
        GcMode::UrgentLow => 2,
        GcMode::UrgentMid => 3,
        _ => 0,
    }
}

/// Whether a value is one the control will take. # C: O(1)
pub fn accepts(k: Knob, v: u64, atgc: bool) -> Result<(), Errno> {
    let plist = MAX_PLIST_NUM as u64;
    let ok = match k {
        Knob::DiscardGranularity | Knob::MaxOrderedDiscard => v != 0 && v <= plist,
        Knob::DiscardIoAwareGran => v <= plist,
        Knob::DiscardIoAware => v < 2,
        Knob::DiscardUrgentUtil => v <= 100,
        Knob::GcUrgent => v <= 3,
        // The age-weighted-with-ageing cost needs the volume to have been
        // mounted with the ageing table; without it the mode has no data.
        Knob::GcIdle => v != u64::from(GcMode::IdleAt.as_u32()) || atgc,
        // An interval of zero is a thread that never sleeps, which is a
        // filesystem that spends a core on housekeeping.
        Knob::GcUrgentSleepTime | Knob::GcMinSleepTime | Knob::GcMaxSleepTime
        | Knob::GcNoGcSleepTime | Knob::MinDiscardIssueTime | Knob::MidDiscardIssueTime
        | Knob::MaxDiscardIssueTime | Knob::MaxDiscardRequest =>
            v != 0 && v <= u64::from(u32::MAX),
        Knob::GcRemainingTrials => v <= u64::from(u32::MAX),
        // Zero would cost nothing and settle for nothing, so an ahead-of-demand
        // pass with it set would never find a victim at all.
        Knob::MaxVictimSearch => v != 0 && v <= u64::from(u32::MAX),
    };
    if ok { Ok(()) } else { Err(Errno::Einval) }
}

/// Turn one control, refusing a value it will not take.
///
/// A refused write changes nothing at all — not the knob it named and not the
/// mode it would have implied.
/// # C: O(1)
pub fn store(bg: &Bg, k: Knob, v: u64, atgc: bool) -> Result<(), Errno> {
    accepts(k, v, atgc)?;
    let n = v as u32;
    match k {
        Knob::GcUrgentSleepTime => bg.gc.lock().urgent_sleep_time = n,
        Knob::GcMinSleepTime => bg.gc.lock().min_sleep_time = n,
        Knob::GcMaxSleepTime => bg.gc.lock().max_sleep_time = n,
        Knob::GcNoGcSleepTime => bg.gc.lock().no_gc_sleep_time = n,
        Knob::GcUrgent => bg.set_gc_mode(urgent_mode(n)),
        Knob::GcIdle => bg.set_gc_mode(GcMode::from_u32(n).unwrap_or(GcMode::Normal)),
        Knob::GcRemainingTrials => bg.gc.lock().remaining_trials = n,
        Knob::MaxVictimSearch => bg.gc.lock().max_victim_search = n,
        Knob::DiscardGranularity => bg.dcc.lock().granularity = n,
        Knob::MaxOrderedDiscard => bg.dcc.lock().max_ordered_discard = n,
        Knob::DiscardIoAwareGran => bg.dcc.lock().io_aware_gran = n,
        Knob::DiscardIoAware => {
            bg.dcc.lock().io_aware = IoAware::from_u32(n).ok_or(Errno::Einval)?;
        }
        Knob::DiscardUrgentUtil => bg.dcc.lock().urgent_util = n,
        Knob::MaxDiscardRequest => bg.dcc.lock().max_discard_request = n,
        Knob::MinDiscardIssueTime => bg.dcc.lock().min_issue_time = n,
        Knob::MidDiscardIssueTime => bg.dcc.lock().mid_issue_time = n,
        Knob::MaxDiscardIssueTime => bg.dcc.lock().max_issue_time = n,
    }
    Ok(())
}

/// The mode the urgency control's number names. # C: O(1)
fn urgent_mode(v: u32) -> GcMode {
    match v {
        1 => GcMode::UrgentHigh,
        2 => GcMode::UrgentLow,
        3 => GcMode::UrgentMid,
        _ => GcMode::Normal,
    }
}

/// The smallest granularity a control will take, for a caller stating the
/// bound rather than the value. # C: O(1)
pub const fn min_granularity() -> u32 { MIN_DISCARD_GRANULARITY }

/// Read the decimal a sysfs write carries.
///
/// Leading blanks are skipped and a trailing newline is not an error, because
/// `echo` writes one and every tool that turns these knobs is `echo`.
/// # C: O(len)
pub fn parse_value(bytes: &[u8]) -> Result<u64, Errno> {
    let text = core::str::from_utf8(bytes).map_err(|_| Errno::Einval)?;
    let text = text.trim();
    if text.is_empty() { return Err(Errno::Einval); }
    text.parse::<u64>().map_err(|_| Errno::Einval)
}

#[cfg(test)]
#[path = "../tests/bg/knobs.rs"]
mod tests;
