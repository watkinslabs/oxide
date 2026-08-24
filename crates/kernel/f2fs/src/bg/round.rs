//! One pass of each background thread, over a real mount.
//!
//! The thread bodies are a park and a call into here. Nothing in this file
//! needs a scheduler, so a pass can be driven straight from a test against an
//! image in memory — which is the only way the interesting cases are reachable
//! at all: a volume short of sections, an urgent mode, a device the policy
//! says is too busy.

use alloc::sync::Arc;

use crate::mount::F2fs;
use crate::opts::BackgroundGc;
use crate::volume::gc::Policy;

use super::discard::{DiscardType, Round, MIN_DISCARD_GRANULARITY};
use super::gc::{self, Conditions, GcMode, GcStep, IdleKind};

/// What one wake of the cleaner did, for the thread's own interval and for a
/// test to assert on.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct GcPass {
    pub step: GcStep,
    /// Whether the pass found a victim and cleaned it.
    pub cleaned: bool,
    /// The interval the thread should sleep before the next pass.
    pub wait_ms: u32,
}

/// Run one pass of the cleaner. # C: O(main segments + blocks per section)
pub fn gc_pass(fs: &Arc<F2fs>) -> GcPass {
    let bg = fs.bg();
    let bggc = *bg.bggc.lock();
    let opts = fs.volume.lock().options().clone();
    // Off means off. The thread stays alive so a remount can turn it back on
    // without a mount cycle, but it does no work while the answer is off —
    // except for a caller blocked in the balance path, which asked for this
    // pass by name.
    let merged = opts.gc_merge && bg.foreground_waiting();
    if bggc == BackgroundGc::Off && !merged {
        let th = bg.gc.lock();
        return GcPass { step: GcStep::Skip, cleaned: false, wait_ms: th.no_gc_sleep_time };
    }
    let (step, wait_before) = {
        let mut th = bg.gc.lock();
        let c = conditions(fs, merged, th.mode, th.no_zoned_gc_percent,
                           th.boost_zoned_gc_percent, th.boost_gc_greedy);
        (gc::gc_round(&mut th, c, bggc), th.wait_ms)
    };
    let GcStep::Gc { sync, foreground, boosted } = step else {
        return GcPass { step, cleaned: false, wait_ms: wait_before };
    };
    let (mode, boost_multiple) = {
        let th = bg.gc.lock();
        (th.mode, th.boost_gc_multiple)
    };
    let cleaned = clean(fs, sync, foreground, boosted, boost_multiple, mode);
    {
        let mut th = bg.gc.lock();
        gc::after_gc(&mut th, cleaned, foreground);
        th.expire_trial();
    }
    // Every pass releases blocked callers, not only one that ran as their
    // foreground. A caller enrols and asks in that order, so a pass already
    // under way when it asked is the pass it is waiting for; releasing only on
    // the foreground flag would leave it waiting out its whole timeout for a
    // pass that had done exactly the work it wanted.
    bg.finish_foreground();
    // The cleaner is also where the periodic checkpoint comes from: a volume
    // written to and then left alone has nobody else to take one, and every
    // segment the cleaner just emptied stays unusable until one lands.
    let recent_io = !gc::is_idle(mode, IdleKind::Request, fs.volume.lock().now_secs(),
                                 bg.last_activity(), bg.idle_interval(IdleKind::Request));
    let _ = fs.volume_now().balance_fs_bg(true, recent_io);
    GcPass { step, cleaned, wait_ms: bg.gc.lock().wait_ms }
}

/// What the volume and the mount look like to the cleaner right now.
/// # C: O(main segments)
fn conditions(fs: &Arc<F2fs>, foreground: bool, mode: GcMode,
              no_zoned_gc_percent: u32, boost_zoned_gc_percent: u32,
              boost_gc_greedy: u32) -> Conditions {
    let bg = fs.bg();
    // The plain lock, not the one that stamps the clock. A background pass is
    // not an operation on anyone's behalf, and stamping the mount's clock here
    // would make the volume look freshly used to the very idle test about to
    // read it.
    let mut v = fs.volume.lock();
    let now = v.now_secs();
    let idle = gc::is_idle(mode, IdleKind::Gc, now, bg.last_activity(),
                           bg.idle_interval(IdleKind::Gc));
    let readonly = !v.writable();
    let can_lock = !v.gc_is_running();
    let loaded = v.load_segments().is_ok();
    let total = v.super_block().segment_count_main
        .div_ceil(v.super_block().segs_per_sec.max(1));
    let zoned_free_enough = crate::features::has_blkzoned(v.super_block().feature)
        && no_zoned_gc_percent != 0
        && crate::bg::gc::enough_free_sections(v.free_section_count(), total,
                                               no_zoned_gc_percent);
    let boosted = loaded && crate::features::has_blkzoned(v.super_block().feature)
        && boost_zoned_gc_percent != 0
        && !crate::bg::gc::enough_free_sections(v.free_section_count(), total,
                                                boost_zoned_gc_percent);
    let boost = loaded && if boosted { true } else { v.worth_cleaning() };
    Conditions { readonly, frozen: false, foreground, idle, boost, boosted,
                 boost_greedy: boost_gc_greedy != 0,
                 can_lock, zoned_free_enough }
}

/// Do the cleaning the pass decided on.
///
/// The mode reaches the volume for two reasons and both matter. It says which
/// COST to look for — an idle mode names one, and without this the knob that
/// selects the cost was a knob nothing read — and it says which policy the
/// segments this pass empties are charged to, which is the only way the
/// reclaimed figures can ever be anything but one row.
/// # C: O(blocks per section)
fn clean(fs: &Arc<F2fs>, sync: bool, foreground: bool, boosted: bool,
         boost_multiple: u32, mode: GcMode) -> bool {
    let mut v = fs.volume_now();
    let slot = mode.as_u32() as usize;
    if foreground {
        // A blocked caller needs a section it can allocate out of, so the
        // target is stated in segments and the pass runs until it is met or
        // nothing is left worth cleaning.
        let target = v.free_segment_count() + v.super_block().segs_per_sec.max(1);
        let policy = mode.idle_policy().unwrap_or(Policy::Greedy);
        return v.collect_as(policy, target, slot).map(|n| n > 0).unwrap_or(false);
    }
    if sync {
        // The volume was mounted asking for background cleaning to move
        // blocks the way the foreground does: cheapest section first.
        let policy = mode.idle_policy().unwrap_or(Policy::Greedy);
        return v.gc_one_segment_as(policy, slot).map(|s| s.is_some()).unwrap_or(false);
    }
    // Ahead of demand is where the age policy belongs: it is the pass that has
    // time to move blocks nothing is waiting for, and the one whose choice of
    // victim decides how many writes the volume spends over its life. A caller
    // that is blocked wants the cheapest section, not the oldest.
    if v.atgc_enabled() && matches!(mode, GcMode::Normal | GcMode::IdleAt) {
        return v.gc_background_age_boosted(slot, if boosted { boost_multiple } else { 1 })
            .map(|s| s.is_some()).unwrap_or(false);
    }
    let policy = mode.idle_policy().unwrap_or(Policy::CostBenefit);
    v.gc_background_as_boosted(policy, slot, if boosted { boost_multiple } else { 1 })
        .map(|s| s.is_some()).unwrap_or(false)
}

/// What one wake of the discard thread did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscardPass {
    pub round: Round,
    pub wait_ms: u32,
}

/// Run one pass of the discard thread, handing the device what it produced.
/// # C: O(MAX_PLIST_NUM + runs issued)
pub fn discard_pass(fs: &Arc<F2fs>) -> DiscardPass {
    let bg = fs.bg();
    let (utilization, now, writable) = {
        let v = fs.volume.lock();
        (v.utilization(), v.now_secs(), v.writable())
    };
    let mode = bg.gc_mode();
    let idle = gc::is_idle(mode, IdleKind::Discard, now, bg.last_activity(),
                           bg.idle_interval(IdleKind::Discard));
    let (round, wait_ms) = {
        let mut dcc = bg.dcc.lock();
        dcc.wake = false;
        // Urgent cleaning wants the device's own map cleared as fast as the
        // segments are: a run held back for politeness is space the device
        // still thinks is used.
        let p = if mode == GcMode::UrgentHigh {
            dcc.init_policy(DiscardType::Force, MIN_DISCARD_GRANULARITY, utilization)
        } else {
            dcc.init_policy(DiscardType::Bg, dcc.granularity, utilization)
        };
        if !writable {
            let wait = p.max_interval;
            (Round { runs: alloc::vec::Vec::new(), io_interrupted: false }, wait)
        } else {
            let round = dcc.issue_round(&p, idle);
            let wait = dcc.next_wait(&p, &round);
            (round, wait)
        }
    };
    fs.announce_free(&round.runs);
    // The device has answered, so the runs are no longer in flight. Lowered
    // here rather than inside the round, because the round is what SUBMITS
    // them: a count lowered at submission would never be non-zero and the
    // report would say nothing was ever outstanding.
    bg.dcc.lock().completed(round.runs.len());
    DiscardPass { round, wait_ms }
}

/// Serve every caller enrolled for a checkpoint, with ONE write.
///
/// The whole queue is taken before the write and the callers are released after
/// it, so a caller that arrives while the write is in progress is enrolled for
/// the next one — its own changes may not have been in the state this write
/// captured.
/// # C: O(a checkpoint)
pub fn ckpt_pass(fs: &Arc<F2fs>) -> u32 {
    let bg = fs.bg();
    let count = bg.cprc.lock().take();
    if count == 0 { return 0; }
    let outcome = fs.checkpoint_now_background();
    bg.cprc.lock().served(count, outcome);
    bg.waits.wake_ckpt();
    count
}

/// Issue everything still parked, whatever its length.
///
/// The unmount path, and the only one that ignores granularity: the checkpoint
/// written after it says the volume is trimmed, and that claim has to be true
/// of every run rather than of the long ones.
/// # C: O(runs waiting)
pub fn drain_discards(fs: &F2fs) {
    let bg = fs.bg();
    let utilization = fs.volume.lock().utilization();
    loop {
        let runs = {
            let mut dcc = bg.dcc.lock();
            let p = dcc.init_policy(DiscardType::Umount, MIN_DISCARD_GRANULARITY, utilization);
            dcc.issue_round(&p, true).runs
        };
        if runs.is_empty() { return; }
        fs.announce_free(&runs);
        bg.dcc.lock().completed(runs.len());
    }
}

#[cfg(test)]
#[path = "../tests/bg/round.rs"]
mod tests;
