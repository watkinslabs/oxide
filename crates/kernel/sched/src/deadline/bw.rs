// Deadline admission control: the running sum of admitted bandwidth and the
// overflow test that refuses a reservation the machine cannot honour.
//
// Ungated. Admission is the difference between a deadline class and a
// priority label — a scheduler that accepts every request has made no
// guarantee at all — and the arithmetic is a fixed-point sum whose shifts are
// exactly the kind of thing that regresses silently.

use core::sync::atomic::{AtomicU64, Ordering};

use super::params::{to_ratio, BW_UNIT};

/// Capacity of one CPU, in the same scale the capacity sum uses.
pub const CAPACITY_SCALE: u64 = 1024;
/// Shift matching [`CAPACITY_SCALE`].
pub const CAPACITY_SHIFT: u32 = 10;

/// The bandwidth cap sentinel meaning "admission control disabled".
pub const BW_DISABLED: u64 = u64::MAX;

/// Default global real-time period, ns.
pub const GLOBAL_RT_PERIOD_NS: u64 = 1_000_000_000;
/// Default global real-time runtime, ns. Equal to the period: the whole of a
/// CPU may be reserved by deadline tasks.
pub const GLOBAL_RT_RUNTIME_NS: u64 = 1_000_000_000;

/// Scale a per-CPU bandwidth cap by an aggregate capacity.
/// # C: O(1)
pub fn cap_scale(bw: u64, cap: u64) -> u64 { ((bw as u128 * cap as u128) >> CAPACITY_SHIFT) as u64 }

/// Aggregate capacity of `n` CPUs, all at full capacity.
/// # C: O(1)
pub fn capacity_of(n: u64) -> u64 { n << CAPACITY_SHIFT }

/// Would replacing `old_bw` with `new_bw` push the admitted total past what
/// `cap` worth of CPU can serve?
///
/// The comparison is strict, so a task set that exactly fills the cap is
/// admissible; only a request that would exceed it is refused. `total_bw` is
/// an UNDIVIDED sum, and the limit is the per-CPU cap scaled by the aggregate
/// capacity — mixing the two conventions is what makes an N-CPU machine admit
/// either N times too much or N times too little.
/// # C: O(1)
pub fn dl_overflow(bw: u64, cap: u64, total_bw: u64, old_bw: u64, new_bw: u64) -> bool {
    if bw == BW_DISABLED { return false; }
    cap_scale(bw, cap) < total_bw.saturating_sub(old_bw).saturating_add(new_bw)
}

/// The transition an admission request represents.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BwChange {
    /// Nothing to account (the request keeps the exact bandwidth it had, or
    /// the entity is a governor entity outside the accounting).
    None,
    /// Add `new` to the admitted total.
    Add { new: u64 },
    /// Replace `old` with `new` in the admitted total.
    Replace { old: u64, new: u64 },
    /// The entity is leaving the deadline class. Its bandwidth is NOT released
    /// here: the reservation stays booked until the entity's contribution
    /// genuinely stops, so a request that leaves and immediately re-enters the
    /// class cannot double-book.
    Leaving,
}

/// Decide the accounting effect of a policy request, or report that it does
/// not fit.
///
/// `cur_bw` is the entity's currently-admitted bandwidth and `is_dl` whether
/// it currently holds the deadline policy. `Err(())` is the caller's `EBUSY`.
/// # C: O(1)
pub fn plan(bw: u64, cap: u64, total_bw: u64, want_dl: bool, is_dl: bool,
            cur_bw: u64, new_bw: u64, special: bool) -> Result<BwChange, ()> {
    if special { return Ok(BwChange::None); }
    if want_dl && is_dl && new_bw == cur_bw { return Ok(BwChange::None); }
    if want_dl && !is_dl {
        if dl_overflow(bw, cap, total_bw, 0, new_bw) { return Err(()); }
        return Ok(BwChange::Add { new: new_bw });
    }
    if want_dl && is_dl {
        if dl_overflow(bw, cap, total_bw, cur_bw, new_bw) { return Err(()); }
        return Ok(BwChange::Replace { old: cur_bw, new: new_bw });
    }
    if is_dl { return Ok(BwChange::Leaving); }
    Ok(BwChange::None)
}

/// Global admitted-bandwidth accounting for the deadline class.
pub struct DlBw {
    /// Per-CPU cap in `BW_SHIFT` fixed point, or [`BW_DISABLED`].
    bw: AtomicU64,
    /// Sum of every admitted entity's `dl_bw`, undivided.
    total_bw: AtomicU64,
}

impl DlBw {
    /// # C: O(1)
    pub const fn new() -> DlBw {
        DlBw { bw: AtomicU64::new(0), total_bw: AtomicU64::new(0) }
    }

    /// Seed the per-CPU cap from the global real-time period/runtime pair. A
    /// runtime equal to the period admits a full CPU's worth.
    ///
    /// No CPU count is stored: the online set is the single truth for capacity
    /// and is read at each decision, so a CPU coming up or going down changes
    /// what is admissible without a second number to keep in step.
    /// # C: O(1)
    pub fn init(&self, period_ns: u64, runtime_ns: u64) {
        let bw = if runtime_ns == u64::MAX { BW_DISABLED } else { to_ratio(period_ns, runtime_ns) };
        self.bw.store(bw, Ordering::Release);
    }

    /// # C: O(1)
    pub fn bw(&self) -> u64 { self.bw.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn total_bw(&self) -> u64 { self.total_bw.load(Ordering::Acquire) }

    /// Aggregate capacity of the CPUs the class currently schedules over.
    /// # C: O(1)
    pub fn capacity(&self) -> u64 { capacity_of(super::span().count_ones() as u64) }

    /// Apply an admission plan. Separate from [`plan`] so the decision stays a
    /// pure function and only the commit touches shared state.
    /// # C: O(1)
    pub fn apply(&self, change: BwChange) {
        match change {
            BwChange::None | BwChange::Leaving => {}
            BwChange::Add { new } => { self.total_bw.fetch_add(new, Ordering::AcqRel); }
            BwChange::Replace { old, new } => {
                self.total_bw.fetch_sub(old, Ordering::AcqRel);
                self.total_bw.fetch_add(new, Ordering::AcqRel);
            }
        }
    }

    /// Release a reservation whose owner has genuinely stopped contending —
    /// left the deadline class, or exited.
    /// # C: O(1)
    pub fn release(&self, bw: u64) {
        let _ = self.total_bw.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |t| Some(t.saturating_sub(bw)));
    }

    /// Would the admitted total still be servable by `cap` worth of CPU?
    ///
    /// The question a shrinking CPU set must answer — a CPU going away, or a
    /// cpuset narrowing the span. `remaining_cpus == 0` is never servable while
    /// anything at all is booked: the last CPU carrying a reservation cannot
    /// leave.
    /// # C: O(1)
    pub fn fits(&self, cap: u64, remaining_cpus: u64) -> bool {
        let total = self.total_bw();
        if total == 0 { return true; }
        if remaining_cpus == 0 { return false; }
        !dl_overflow(self.bw(), cap, total, 0, 0)
    }
}

impl Default for DlBw {
    fn default() -> Self { Self::new() }
}

/// The one admitted-bandwidth ledger. Single root domain: every CPU serves
/// every deadline task, so there is exactly one sum and one cap.
pub static DL_BW: DlBw = DlBw::new();

/// Seed [`DL_BW`] at the default global real-time period/runtime.
/// # C: O(1)
pub fn init_default() {
    DL_BW.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
    debug_assert_eq!(to_ratio(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS), BW_UNIT);
}

#[cfg(test)]
#[path = "tests/bw.rs"] mod tests;
