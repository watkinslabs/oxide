// Constant Bandwidth Server: the runtime/deadline state machine that turns the
// static reservation in `params.rs` into an enforceable budget.
//
// Every rule here is a pure function over (`DlParams`, `DlSched`, `now`) so the
// throttle and replenish EDGES — the parts that decide whether a deadline task
// is a real-time guarantee or just a priority label — are reachable from
// `cargo test`. The live wiring in `deadline/live.rs` only snapshots, applies
// and stores back.

use super::params::{DlParams, BW_SHIFT, DL_SCALE};

/// Wrap-safe strict "a is before b" over the monotonic clock domain. Every
/// deadline comparison in the class goes through this, so equal deadlines
/// never win anything: a tie does not preempt, and a tie does not reorder.
/// # C: O(1)
pub fn dl_time_before(a: u64, b: u64) -> bool { (a.wrapping_sub(b) as i64) < 0 }

/// Dynamic state of one deadline instance.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DlSched {
    /// Budget remaining in the current instance, ns. SIGNED: an instance that
    /// runs past its grant goes negative, and the replenish loop pays that
    /// debt back one period at a time. Clamping it at zero would let a task
    /// that overran by three periods keep its original deadline.
    pub runtime: i64,
    /// ABSOLUTE deadline of the current instance, in the same clock domain as
    /// the `now` passed to these functions.
    pub deadline: u64,
    /// Budget exhausted; the entity is off the ready tree until its
    /// replenishment instant.
    pub throttled: bool,
    /// The task gave the rest of this instance's budget away.
    pub yielded: bool,
    /// An overrun happened and a `SIGXCPU` is owed. Consumed by the delivery
    /// site, so repeated overruns before delivery coalesce into one signal.
    pub overrun: bool,
}

/// Start of the next instance: the current absolute deadline, rewound by the
/// relative deadline to recover the activation instant, then advanced by one
/// period. For an implicit-deadline entity this is simply the deadline.
/// # C: O(1)
pub fn dl_next_period(p: &DlParams, s: &DlSched) -> u64 {
    s.deadline.wrapping_sub(p.deadline).wrapping_add(p.period)
}

/// Budget exhausted. Zero counts as exhausted — a task with no runtime left
/// cannot be allowed to enter the CPU and consume the next tick's worth first.
/// # C: O(1)
pub fn runtime_exceeded(s: &DlSched) -> bool { s.runtime <= 0 }

/// Fresh instance starting now: deadline one relative-deadline out, full grant.
/// # C: O(1)
pub fn replenish_new_period(p: &DlParams, s: &mut DlSched, now: u64) {
    s.deadline = now.wrapping_add(p.deadline);
    s.runtime = p.runtime as i64;
}

/// Would keeping the current deadline hand the entity more bandwidth than its
/// reservation allows? True iff `runtime / (deadline - now) > dl_runtime /
/// dl_deadline`, evaluated with both sides truncated by [`DL_SCALE`] bits so
/// the products stay inside 64 bits.
///
/// This is the test that stops a task from banking budget across a long sleep:
/// waking with most of its old grant intact against a deadline that is nearly
/// here would let it run at a density far above what was admitted.
/// # C: O(1)
pub fn dl_entity_overflow(p: &DlParams, s: &DlSched, now: u64) -> bool {
    let left = (p.deadline >> DL_SCALE).wrapping_mul((s.runtime >> DL_SCALE) as u64);
    let laxity = s.deadline.wrapping_sub(now);
    let right = (laxity >> DL_SCALE).wrapping_mul(p.runtime >> DL_SCALE);
    dl_time_before(right, left)
}

/// Replenishment at the start of a new instance.
///
/// The postponement loop is the CBS rule proper: each period added to the
/// deadline buys exactly one runtime added to the budget, so an entity that
/// overran by N budgets pays for it with N postponed deadlines rather than
/// with a single free reset. A yielded instance donates whatever is left
/// first, which makes one yield cost exactly one period.
/// # C: O(overrun / dl_runtime)
pub fn replenish(p: &DlParams, s: &mut DlSched, now: u64) {
    if p.runtime == 0 { return; }
    // A degenerate entity (no relative deadline) has no instance to postpone.
    if p.deadline == 0 { replenish_new_period(p, s, now); }

    if s.yielded && s.runtime > 0 { s.runtime = 0; }

    while s.runtime <= 0 {
        s.deadline = s.deadline.wrapping_add(p.period);
        s.runtime = s.runtime.saturating_add(p.runtime as i64);
    }

    // The loop above walks forward from the stored deadline; if the entity was
    // parked for far longer than one period that deadline can still be behind
    // `now`, and honouring it would give the task an instantly-expired instance
    // that outranks everyone. Restart the period instead.
    if dl_time_before(s.deadline, now) { replenish_new_period(p, s, now); }

    s.yielded = false;
    s.throttled = false;
}

/// Wakeup rule: decide whether the entity may resume its current instance or
/// must start a new one.
///
/// Three outcomes:
///   * deadline still ahead and density still respected — keep everything,
///   * constrained-deadline entity whose deadline has not yet passed — keep the
///     deadline but shrink the budget to what its density permits over the
///     remaining laxity,
///   * otherwise — a brand new instance starting now.
/// # C: O(1)
pub fn update_dl_entity(p: &DlParams, s: &mut DlSched, now: u64) {
    let past = dl_time_before(s.deadline, now);
    if !past && !dl_entity_overflow(p, s, now) { return; }
    if !p.is_implicit() && !past {
        let laxity = s.deadline.wrapping_sub(now) as u128;
        s.runtime = ((p.density as u128 * laxity) >> BW_SHIFT) as i64;
        return;
    }
    replenish_new_period(p, s, now);
}

/// A constrained-deadline entity re-entering the ready set between its expired
/// deadline and the start of its next period must wait rather than run: its
/// budget for this instance is spent by definition. Returns `true` when the
/// caller should throttle it until [`dl_next_period`].
/// # C: O(1)
pub fn check_constrained(p: &DlParams, s: &mut DlSched, now: u64) -> bool {
    if p.is_implicit() { return false; }
    if !(dl_time_before(s.deadline, now) && dl_time_before(now, dl_next_period(p, s))) {
        return false;
    }
    s.throttled = true;
    if s.runtime > 0 { s.runtime = 0; }
    true
}

/// Entity placed on a runqueue with a deadline already in the past — no
/// instance to resume, so start one now.
/// # C: O(1)
pub fn setup_new_entity(p: &DlParams, s: &mut DlSched, now: u64) {
    if s.throttled { return; }
    replenish_new_period(p, s, now);
}

/// What the charging step decided.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Charged {
    /// Budget remains; the entity keeps running.
    Running,
    /// Budget spent (or donated by a yield): the entity must leave the ready
    /// tree and wait for its replenishment instant.
    Throttle,
}

/// Charge `delta_ns` of execution against the current instance and report
/// whether the entity must now be throttled.
///
/// A yield throttles regardless of remaining budget, and regardless of whether
/// any time elapsed at all — that is what makes `sched_yield` on a deadline
/// task give up the *instance* rather than merely the CPU. The overrun latch is
/// raised only by a genuine budget exhaustion, never by a yield.
/// # C: O(1)
pub fn charge(p: &DlParams, s: &mut DlSched, delta_ns: u64) -> Charged {
    if p.is_special() { return Charged::Running; }
    if delta_ns > 0 { s.runtime = s.runtime.saturating_sub(delta_ns as i64); }
    let exceeded = runtime_exceeded(s);
    if !exceeded && !s.yielded { return Charged::Running; }
    s.throttled = true;
    if exceeded && p.wants_overrun_signal() { s.overrun = true; }
    Charged::Throttle
}

/// Budget consumed per nanosecond of wall time under `SCHED_FLAG_RECLAIM`
/// (GRUB). The reclaimable share is whatever the runqueue's admitted deadline
/// bandwidth leaves idle, floored at the entity's own reservation so a
/// reclaiming task is never charged MORE than a non-reclaiming one.
///
/// `this_bw` is the utilization assigned to this runqueue, `running_bw` the
/// part currently contending, `max_bw` the global per-CPU deadline cap.
/// # C: O(1)
pub fn grub_reclaim(delta_ns: u64, p: &DlParams, this_bw: u64, running_bw: u64,
                    max_bw: u64, extra_bw: u64, bw_ratio: u64) -> u64 {
    let u_inact = this_bw.saturating_sub(running_bw);
    let u_act = if u_inact.saturating_add(extra_bw) > max_bw.saturating_sub(p.bw) {
        p.bw
    } else {
        max_bw - u_inact - extra_bw
    };
    let u_act = (u_act as u128 * bw_ratio as u128) >> RATIO;
    ((delta_ns as u128 * u_act) >> BW_SHIFT) as u64
}

const RATIO: u32 = super::params::RATIO_SHIFT;

#[cfg(test)]
#[path = "tests/cbs.rs"] mod tests;
