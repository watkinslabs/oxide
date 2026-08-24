//! The discard thread's policy, and the pending runs it issues from.
//!
//! A discard is cheap to record and expensive to issue: the device stalls
//! other work while it erases, and a run of one block is nearly all overhead.
//! So runs are not handed over as they are found. They are parked in a list
//! per LENGTH, and the thread issues from the longest first — the runs whose
//! erase the controller can actually use — stopping at a granularity below
//! which a run is not worth announcing at all.
//!
//! Two axes decide how hard it pushes:
//!
//! - **The policy.** Background yields to a busy device and issues in address
//!   order, which is what a device with an internal map wants. Forced does
//!   neither, because something is waiting. Unmount ignores granularity
//!   entirely — the checkpoint about to be written says the volume is trimmed,
//!   and that claim has to be true of every run, not the long ones.
//! - **The utilisation.** A nearly full volume needs the space back more than
//!   it needs the device quiet, so past a threshold the granularity drops to
//!   one block and the longest interval collapses to the shortest.
//!
//! The interval between rounds is itself the feedback: short after a round
//! that issued something, long after one that found nothing, and a middle
//! value when the device was too busy to take what was offered.

use alloc::vec;
use alloc::vec::Vec;

use crate::opts::DiscardUnit;
use crate::uapi::BLKS_PER_SEG;
use crate::volume::discard::Range;

/// Lists of pending runs, one per length. The last holds everything at least
/// that long, so a very long run is not given a list of its own.
pub const MAX_PLIST_NUM: usize = 512;
/// The smallest granularity there is: announce every run.
pub const MIN_DISCARD_GRANULARITY: u32 = 1;
/// What the thread announces at by default.
pub const DEFAULT_DISCARD_GRANULARITY: u32 = 16;
/// Up to this length, runs are issued in address order rather than by length.
pub const DEFAULT_MAX_ORDERED_DISCARD_GRANULARITY: u32 = 16;
/// Runs issued in one round before the thread yields.
pub const DEF_MAX_DISCARD_REQUEST: u32 = 8;
/// The interval after a round that issued something, in milliseconds.
pub const DEF_MIN_DISCARD_ISSUE_TIME: u32 = 50;
/// The interval after a round the device was too busy to take.
pub const DEF_MID_DISCARD_ISSUE_TIME: u32 = 500;
/// The interval after a round that found nothing.
pub const DEF_MAX_DISCARD_ISSUE_TIME: u32 = 60_000;
/// Utilisation past which space matters more than keeping the device quiet.
pub const DEF_DISCARD_URGENT_UTIL: u32 = 80;

/// The list a run of `len` blocks waits in. # C: O(1)
pub fn plist_idx(len: u32) -> usize {
    if len as usize >= MAX_PLIST_NUM { MAX_PLIST_NUM - 1 } else { (len.max(1) - 1) as usize }
}

/// Why a round is being issued, which is what decides how hard it pushes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DiscardType {
    /// The thread's ordinary round.
    Bg,
    /// Something is waiting: no yielding, no ordering.
    Force,
    /// A `FITRIM` call, which named the range itself.
    Fstrim,
    /// The last round before the volume goes away.
    Umount,
}

/// Whether the thread yields to a busy device at all.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IoAware {
    Disable,
    Enable,
}

impl IoAware {
    /// The stored number this is written and read as. # C: O(1)
    pub fn as_u32(self) -> u32 {
        match self { IoAware::Disable => 0, IoAware::Enable => 1 }
    }

    /// The setting a stored number names. # C: O(1)
    pub fn from_u32(v: u32) -> Option<IoAware> {
        Some(match v { 0 => IoAware::Disable, 1 => IoAware::Enable, _ => return None })
    }
}

/// One round's rules, derived from the control block and the volume's state.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct DiscardPolicy {
    pub kind: DiscardType,
    /// Interval after a round that issued something.
    pub min_interval: u32,
    /// Interval after a round the device was too busy for.
    pub mid_interval: u32,
    /// Interval after a round that found nothing.
    pub max_interval: u32,
    /// Runs issued before the round ends.
    pub max_requests: u32,
    /// Length at or above which a run is issued whatever the device is doing.
    pub io_aware_gran: u32,
    pub io_aware: bool,
    pub ordered: bool,
    /// Whether the round must finish, however long it takes.
    pub timeout: bool,
    /// Shortest run worth announcing.
    pub granularity: u32,
}

/// Everything the discard thread issues from, and the knobs that shape it.
#[derive(Clone, Debug)]
pub struct DiscardControl {
    /// Maximum number of discard blocks staged before another checkpoint may
    /// add more. Linux calls this `max_small_discards`; it is separate from
    /// the per-round request count below.
    pub max_discards: u64,
    pub granularity: u32,
    pub max_ordered_discard: u32,
    pub io_aware_gran: u32,
    pub io_aware: IoAware,
    pub max_discard_request: u32,
    pub min_issue_time: u32,
    pub mid_issue_time: u32,
    pub max_issue_time: u32,
    pub urgent_util: u32,
    /// Where the address-ordered pass resumes, so it sweeps rather than
    /// re-issuing the lowest addresses every round.
    pub next_pos: u32,
    /// Runs waiting, by length.
    pub pend: Vec<Vec<Range>>,
    /// Runs handed to the device since the mount, for the report.
    pub issued: u64,
    /// Runs a round has handed to the device and whose erase has not come back.
    ///
    /// Raised where a run leaves the parked lists and lowered when the device
    /// has answered for it, so the two counts are disjoint: a run is parked, or
    /// it is in flight, never both. Separate from `issued`, which only ever
    /// rises and is a report of work done.
    pub queued: usize,
    /// Set by a caller that wants the current sleep cut short.
    pub wake: bool,
}

impl DiscardControl {
    /// The control block a mount starts with.
    ///
    /// A mount that announces only whole segments or sections starts at that
    /// granularity rather than the default: a shorter run can never be
    /// announced under that unit, so parking one in a short list is work the
    /// thread would redo every round.
    /// # C: O(MAX_PLIST_NUM)
    pub fn new(unit: DiscardUnit, segs_per_sec: u32) -> Self {
        let granularity = match unit {
            DiscardUnit::Block => DEFAULT_DISCARD_GRANULARITY,
            DiscardUnit::Segment => BLKS_PER_SEG,
            DiscardUnit::Section => BLKS_PER_SEG.saturating_mul(segs_per_sec.max(1)),
        };
        Self {
            max_discards: u64::MAX,
            granularity,
            max_ordered_discard: DEFAULT_MAX_ORDERED_DISCARD_GRANULARITY,
            io_aware_gran: MAX_PLIST_NUM as u32,
            io_aware: IoAware::Enable,
            max_discard_request: DEF_MAX_DISCARD_REQUEST,
            min_issue_time: DEF_MIN_DISCARD_ISSUE_TIME,
            mid_issue_time: DEF_MID_DISCARD_ISSUE_TIME,
            max_issue_time: DEF_MAX_DISCARD_ISSUE_TIME,
            urgent_util: DEF_DISCARD_URGENT_UTIL,
            next_pos: 0,
            pend: vec![Vec::new(); MAX_PLIST_NUM],
            issued: 0,
            queued: 0,
            wake: false,
        }
    }

    /// Set Linux's discard-block accumulation ceiling. # C: O(1)
    pub fn set_max_discards(&mut self, value: u64) { self.max_discards = value; }

    /// Park a run until a round issues it. # C: O(1)
    pub fn add(&mut self, run: Range) {
        if run.1 == 0 { return; }
        let i = plist_idx(run.1);
        self.pend[i].push(run);
    }

    /// Park every run of a checkpoint's worth. # C: O(runs)
    pub fn extend(&mut self, runs: impl IntoIterator<Item = Range>) {
        for r in runs { self.add(r); }
    }

    /// Runs waiting. # C: O(MAX_PLIST_NUM)
    pub fn cmd_count(&self) -> usize { self.pend.iter().map(|l| l.len()).sum() }

    /// Runs handed to a device and not yet answered for. # C: O(1)
    pub fn queued_count(&self) -> u64 { self.queued as u64 }

    /// Note that the device has answered for `n` runs a round handed it.
    /// # C: O(1)
    pub fn completed(&mut self, n: usize) { self.queued = self.queued.saturating_sub(n); }

    /// Blocks waiting, which is what the report calls undiscarded.
    /// # C: O(runs)
    pub fn undiscard_blks(&self) -> u64 {
        self.pend.iter().flatten().map(|&(_, len)| u64::from(len)).sum()
    }

    /// The rules for one round.
    ///
    /// `utilization` is the share of the volume in use, as a percentage.
    /// # C: O(1)
    pub fn init_policy(&self, kind: DiscardType, granularity: u32, utilization: u32)
        -> DiscardPolicy {
        let mut p = DiscardPolicy {
            kind,
            min_interval: self.min_issue_time,
            mid_interval: self.mid_issue_time,
            max_interval: self.max_issue_time,
            max_requests: self.max_discard_request,
            io_aware_gran: self.io_aware_gran,
            io_aware: false,
            ordered: false,
            timeout: false,
            granularity,
        };
        match kind {
            DiscardType::Bg => {
                p.io_aware = self.io_aware == IoAware::Enable;
                p.ordered = true;
                // A volume this full needs its space back more than it needs
                // the device left alone, so every run goes and the longest
                // interval collapses onto the shortest.
                if utilization > self.urgent_util {
                    p.granularity = MIN_DISCARD_GRANULARITY;
                    if self.cmd_count() > 0 { p.max_interval = self.min_issue_time; }
                }
            }
            DiscardType::Force => { p.io_aware = false; }
            DiscardType::Fstrim => { p.io_aware = false; }
            DiscardType::Umount => {
                // The checkpoint about to be written claims the volume is
                // trimmed. That is only true if every run went, not the long
                // ones.
                p.io_aware = false;
                p.granularity = MIN_DISCARD_GRANULARITY;
                p.timeout = true;
            }
        }
        p
    }
}

/// What one round produced: the runs to hand the device, and how the interval
/// should move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round {
    pub runs: Vec<Range>,
    /// True when the round stopped because the device was busy and nothing
    /// had been issued yet — a different outcome from finding nothing.
    pub io_interrupted: bool,
}

impl Round {
    /// Whether the round handed the device anything. # C: O(1)
    pub fn issued(&self) -> usize { self.runs.len() }
}

impl DiscardControl {
    /// Take up to a round's worth of runs, longest list first.
    ///
    /// `idle` is what the device says about itself; a round that is allowed to
    /// yield stops at the first short run when the device is busy, and reports
    /// that separately so the interval can be a middle one rather than the
    /// long one a round with nothing to do earns.
    /// # C: O(MAX_PLIST_NUM + runs issued)
    pub fn issue_round(&mut self, p: &DiscardPolicy, idle: bool) -> Round {
        if p.ordered && p.granularity < self.max_ordered_discard {
            return self.issue_ordered(p, idle);
        }
        let mut out: Vec<Range> = Vec::new();
        let mut io_interrupted = false;
        for i in (0..MAX_PLIST_NUM).rev() {
            if (i as u32) + 1 < p.granularity { break; }

            while let Some(&run) = self.pend[i].first() {
                if p.io_aware && (i as u32) < p.io_aware_gran && !idle {
                    io_interrupted = true;
                    break;
                }
                self.pend[i].remove(0);
                out.push(run);
                self.issued += 1;
                if out.len() as u32 >= p.max_requests { break; }
            }
            if out.len() as u32 >= p.max_requests || io_interrupted { break; }
        }
        let empty = out.is_empty();
        self.queued += out.len();
        Round { runs: out, io_interrupted: io_interrupted && empty }
    }

    /// Take a round's worth in address order, resuming where the last stopped.
    ///
    /// A device with an internal map handles a rising sweep far better than
    /// scattered erases, and short runs are exactly the ones that benefit —
    /// which is why the ordered pass is the one used below the ordered
    /// granularity and the length-first pass is used above it.
    /// # C: O(runs waiting log runs waiting)
    fn issue_ordered(&mut self, p: &DiscardPolicy, idle: bool) -> Round {
        let mut all: Vec<Range> = self.pend.iter().flatten().copied().collect();
        all.sort_unstable();
        let mut out: Vec<Range> = Vec::new();
        let mut io_interrupted = false;
        let mut ran_off_the_end = true;
        let from = self.next_pos;
        for run in all.iter().copied().filter(|r| r.0 >= from) {
            if p.io_aware && !idle { io_interrupted = true; ran_off_the_end = false; break; }
            self.next_pos = run.0 + run.1;
            self.take(run);
            out.push(run);
            self.issued += 1;
            if out.len() as u32 >= p.max_requests { ran_off_the_end = false; break; }
        }
        // A sweep that reached the end starts over, or the runs below where it
        // stopped would never be reached again.
        if ran_off_the_end { self.next_pos = 0; }
        let empty = out.is_empty();
        self.queued += out.len();
        Round { runs: out, io_interrupted: io_interrupted && empty }
    }

    /// Remove one parked run. # C: O(runs in its list)
    fn take(&mut self, run: Range) {
        let list = &mut self.pend[plist_idx(run.1)];
        if let Some(at) = list.iter().position(|&r| r == run) { list.remove(at); }
    }

    /// How long to sleep after a round. # C: O(MAX_PLIST_NUM)
    pub fn next_wait(&self, p: &DiscardPolicy, round: &Round) -> u32 {
        let wait = if round.io_interrupted { p.mid_interval }
                   else if round.issued() > 0 { p.min_interval }
                   else { p.max_interval };
        // Nothing left is the long interval whatever the round did: the next
        // round has nothing to find until a checkpoint parks more.
        if self.cmd_count() == 0 { p.max_interval } else { wait }
    }
}

#[cfg(test)]
#[path = "../tests/bg/discard.rs"]
mod tests;
