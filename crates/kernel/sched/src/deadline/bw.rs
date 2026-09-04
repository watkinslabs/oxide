// Deadline admission control: the running sum of admitted bandwidth and the
// overflow test that refuses a reservation the machine cannot honour.
//
// Ungated. Admission is the difference between a deadline class and a
// priority label — a scheduler that accepts every request has made no
// guarantee at all — and the arithmetic is a fixed-point sum whose shifts are
// exactly the kind of thing that regresses silently.

use super::params::{to_ratio, BW_UNIT};
use super::entity::InactiveReservation;

/// Root-domain deadline-bandwidth serialization. Nested inside the owning
/// runqueue lock; never nested with the replenishment queue.
struct DlBandwidth;
const DL_BW_LOCK_RANK: u16 = 112;
impl sync::LockClass for DlBandwidth {
    fn rank() -> u16 { DL_BW_LOCK_RANK }
    fn name() -> &'static str { "DlBandwidth" }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type DlBwIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type DlBwIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
type DlBwIrq = sync::NoopIrq;

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
/// [`GLOBAL_RT_RUNTIME_NS`] over [`GLOBAL_RT_PERIOD_NS`] in `BW_SHIFT` fixed
/// point — one whole CPU. A `const` because the ledger is a static with no
/// initialiser to run (`to_ratio` is not const-callable here); the equality is
/// asserted by [`init_default`].
const DEFAULT_BW: u64 = BW_UNIT;

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
    let prospective = total_bw.checked_sub(old_bw)
        .and_then(|base| base.checked_add(new_bw))
        .expect("deadline bandwidth prospective total overflow");
    cap_scale(bw, cap) < prospective
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

/// Proof that the ledger already serialized and committed an admission.
pub struct Admission {
    pending: PendingUse,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum PendingUse { None, Reused, Expired }

impl Admission {
    pub(super) fn pending_use(&self) -> PendingUse { self.pending }
}

/// Decide the accounting effect of a policy request, or report that it does
/// not fit.
///
/// `cur_bw` is the entity's currently-admitted bandwidth and `is_dl` whether
/// it currently holds the deadline policy. `Err(())` is the caller's `EBUSY`.
/// # C: O(1)
pub fn plan(bw: u64, cap: u64, total_bw: u64, want_dl: bool, is_dl: bool,
            cur_bw: u64, new_bw: u64, special: bool) -> Result<BwChange, ()> {
    plan_transition(bw, cap, total_bw, want_dl, is_dl, cur_bw, new_bw,
                    special, special)
}

/// Plan a transition where the current and requested entities can differ in
/// whether they are outside ordinary admission accounting. # C: O(1)
pub fn plan_transition(bw: u64, cap: u64, total_bw: u64, want_dl: bool, is_dl: bool,
            cur_bw: u64, new_bw: u64, cur_special: bool,
            new_special: bool) -> Result<BwChange, ()> {
    let has_booking = is_dl && !cur_special;
    let wants_booking = want_dl && !new_special;
    if wants_booking && has_booking && new_bw == cur_bw { return Ok(BwChange::None); }
    if wants_booking && !has_booking {
        if dl_overflow(bw, cap, total_bw, 0, new_bw) { return Err(()); }
        return Ok(BwChange::Add { new: new_bw });
    }
    if wants_booking && has_booking {
        if dl_overflow(bw, cap, total_bw, cur_bw, new_bw) { return Err(()); }
        return Ok(BwChange::Replace { old: cur_bw, new: new_bw });
    }
    if has_booking { return Ok(BwChange::Leaving); }
    Ok(BwChange::None)
}

/// Global admitted-bandwidth accounting for the deadline class.
pub struct DlBw {
    state: sync::Spinlock<DlBwState, DlBandwidth>,
    topology: Option<TopologyOps>,
}

#[derive(Copy, Clone)]
struct TopologyOps {
    online_cpus: fn() -> u64,
    cpu_online: fn(u32) -> bool,
    mark_offline: unsafe fn(u32) -> bool,
}

struct DlBwState {
    /// Per-CPU cap in `BW_SHIFT` fixed point, or [`BW_DISABLED`].
    bw: u64,
    /// Sum of every admitted entity's `dl_bw`, undivided.
    total_bw: u64,
}

impl DlBw {
    /// The cap starts at the default global real-time share rather than at
    /// zero, so the ledger needs no boot-time seeding step and cannot be asked
    /// a question before one has run. A zero cap would refuse every reservation
    /// while looking like a capacity answer.
    /// # C: O(1)
    pub const fn new() -> DlBw {
        DlBw {
            state: sync::Spinlock::new(DlBwState { bw: DEFAULT_BW, total_bw: 0 }),
            topology: None,
        }
    }

    const fn with_topology(online_cpus: fn() -> u64, cpu_online: fn(u32) -> bool,
                           mark_offline: unsafe fn(u32) -> bool) -> DlBw {
        DlBw {
            state: sync::Spinlock::new(DlBwState { bw: DEFAULT_BW, total_bw: 0 }),
            topology: Some(TopologyOps { online_cpus, cpu_online, mark_offline }),
        }
    }

    /// Re-seed the per-CPU cap from a global real-time period/runtime pair.
    ///
    /// No CPU count is stored: the online set is the single truth for capacity
    /// and is read at each decision, so a CPU coming up or going down changes
    /// what is admissible without a second number to keep in step.
    /// # C: O(1)
    pub fn init(&self, period_ns: u64, runtime_ns: u64) {
        let bw = if runtime_ns == u64::MAX { BW_DISABLED } else { to_ratio(period_ns, runtime_ns) };
        self.state.lock_irqsave::<DlBwIrq>().bw = bw;
    }

    /// # C: O(1)
    pub fn bw(&self) -> u64 { self.state.lock_irqsave::<DlBwIrq>().bw }
    /// # C: O(1)
    pub fn total_bw(&self) -> u64 { self.state.lock_irqsave::<DlBwIrq>().total_bw }

    /// Aggregate capacity of the CPUs the class currently schedules over.
    /// # C: O(1)
    pub fn capacity(&self) -> u64 {
        capacity_of(self.topology.map_or_else(
            || super::span().count_ones() as u64,
            |ops| (ops.online_cpus)()))
    }

    /// Check and commit one reservation while holding the root-domain ledger.
    /// The returned change describes the already-committed transition. Keeping
    /// the pure [`plan`] helper separate preserves deterministic arithmetic tests
    /// without exposing a split production check/commit API.
    /// # C: O(1)
    pub fn admit(&self, cap: u64, want_dl: bool, is_dl: bool, cur_bw: u64,
                 new_bw: u64, special: bool) -> Result<Admission, ()> {
        self.admit_pending(cap, want_dl, is_dl, cur_bw, new_bw,
                           special, special, None)
    }

    /// Check and commit a policy transition that may carry an ordinary
    /// booking retained from an earlier deadline policy. The pending token is
    /// claimed under this same ledger lock, so expiry and re-entry cannot both
    /// subtract it or charge the replacement as an additional reservation.
    /// # C: O(1)
    pub(super) fn admit_pending(&self, cap: u64, want_dl: bool, is_dl: bool,
                 cur_bw: u64, new_bw: u64, cur_special: bool,
                 new_special: bool, pending: Option<&InactiveReservation>)
        -> Result<Admission, ()> {
        let mut state = self.state.lock_irqsave::<DlBwIrq>();
        let cap = self.topology.map_or(cap, |ops| capacity_of((ops.online_cpus)()));
        let pending_active = pending.is_some_and(InactiveReservation::active);
        let (has_dl, old_bw, old_special) = if pending_active {
            (true, pending.expect("active pending reservation").bw(), false)
        } else {
            (is_dl, cur_bw, cur_special)
        };
        let change = plan_transition(state.bw, cap, state.total_bw, want_dl, has_dl,
                          old_bw, new_bw, old_special, new_special)?;
        state.total_bw = changed_total(state.total_bw, change);
        let pending = if let Some(held) = pending {
            if pending_active && want_dl && !new_special {
                debug_assert!(held.claim());
                PendingUse::Reused
            } else if pending_active && want_dl && new_special {
                // The inactive callback takes this same lock before claiming.
                // Publish preservation before it can release the old booking.
                held.preserve_current();
                PendingUse::None
            } else if !pending_active { PendingUse::Expired }
            else { PendingUse::None }
        } else { PendingUse::None };
        Ok(Admission { pending })
    }

    /// Remove one online CPU only when the remaining active capacity can
    /// serve every live reservation. Capacity validation and online-set
    /// publication share this ledger lock with [`DlBw::admit`].
    /// # SAFETY: caller owns `cpu`'s hotplug transition and has stopped new
    /// scheduler placement on it.
    /// # C: O(1)
    pub unsafe fn try_mark_offline(&self, cpu: u32) -> bool {
        let ops = match self.topology { Some(ops) => ops, None => return false };
        let state = self.state.lock_irqsave::<DlBwIrq>();
        if !(ops.cpu_online)(cpu) { return false; }
        let online = (ops.online_cpus)();
        if online == 0 { return false; }
        let remaining = online - 1;
        if state.total_bw != 0 && (remaining == 0
            || dl_overflow(state.bw, capacity_of(remaining), state.total_bw, 0, 0))
        { return false; }
        // SAFETY: caller owns the target hotplug transition; invoking the
        // configured topology publisher while the bandwidth lock is held is
        // what makes capacity loss atomic against admission.
        unsafe { (ops.mark_offline)(cpu) }
    }

    /// Release a reservation whose owner has genuinely stopped contending —
    /// left the deadline class, or exited.
    /// # C: O(1)
    pub fn release(&self, bw: u64) {
        let mut state = self.state.lock_irqsave::<DlBwIrq>();
        hal::kassert!(state.total_bw >= bw, "deadline bandwidth double release");
        state.total_bw -= bw;
    }

    /// Timer-owned release of one zero-lag booking. Claim and subtraction are
    /// serialized with admission, so a re-entry that reused the token wins
    /// wholly or the timer wins wholly. # C: O(1)
    pub(super) fn release_inactive(&self, held: &InactiveReservation) -> bool {
        let mut state = self.state.lock_irqsave::<DlBwIrq>();
        if !held.claim() { return false; }
        hal::kassert!(state.total_bw >= held.bw(), "inactive bandwidth double release");
        state.total_bw -= held.bw();
        true
    }

    /// Would the admitted total still be servable by `cap` worth of CPU?
    ///
    /// The question a shrinking CPU set must answer — a CPU going away, or a
    /// cpuset narrowing the span. `remaining_cpus == 0` is never servable while
    /// anything at all is booked: the last CPU carrying a reservation cannot
    /// leave.
    /// # C: O(1)
    pub fn fits(&self, cap: u64, remaining_cpus: u64) -> bool {
        let state = self.state.lock_irqsave::<DlBwIrq>();
        if state.total_bw == 0 { return true; }
        if remaining_cpus == 0 { return false; }
        !dl_overflow(state.bw, cap, state.total_bw, 0, 0)
    }
}

fn changed_total(total: u64, change: BwChange) -> u64 {
    match change {
        BwChange::None | BwChange::Leaving => total,
        BwChange::Add { new } => total.checked_add(new)
            .expect("deadline bandwidth addition overflow"),
        BwChange::Replace { old, new } => total.checked_sub(old)
            .and_then(|base| base.checked_add(new))
            .expect("deadline bandwidth replacement overflow"),
    }
}

impl Default for DlBw {
    fn default() -> Self { Self::new() }
}

/// The one admitted-bandwidth ledger. Single root domain: every CPU serves
/// every deadline task, so there is exactly one sum and one cap.
#[cfg(target_os = "oxide-kernel")]
fn online_cpu_count() -> u64 { cpu::smp::capacity_cpumask().count_ones() as u64 }
#[cfg(target_os = "oxide-kernel")]
fn cpu_is_online(cpu: u32) -> bool { cpu::smp::capacity_cpumask().contains(cpu as usize) }

#[cfg(target_os = "oxide-kernel")]
unsafe fn mark_cpu_offline(cpu: u32) -> bool {
    // SAFETY: forwarded from `try_mark_cpu_offline`, whose caller owns the
    // target CPU's scheduler-quiesced hotplug transition.
    unsafe { cpu::smp::mark_offline(cpu) }
}

#[cfg(target_os = "oxide-kernel")]
pub static DL_BW: DlBw = DlBw::with_topology(online_cpu_count, cpu_is_online, mark_cpu_offline);
#[cfg(not(target_os = "oxide-kernel"))]
pub static DL_BW: DlBw = DlBw::new();

/// Atomically validate deadline capacity and remove one scheduler-quiesced
/// CPU from the online set.
/// # SAFETY: caller owns `cpu`'s hotplug transition and has stopped new
/// scheduler placement on it.
/// # C: O(1)
pub unsafe fn try_mark_cpu_offline(cpu: u32) -> bool {
    // SAFETY: the caller supplies the ownership required by the ledger's
    // topology transition contract.
    unsafe { DL_BW.try_mark_offline(cpu) }
}

/// Reset [`DL_BW`] to the default global real-time period/runtime. The boot
/// path does NOT call this — [`DlBw::new`] already carries the default — so it
/// exists for a runtime change of the global share.
/// # C: O(1)
pub fn init_default() {
    debug_assert_eq!(to_ratio(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS), DEFAULT_BW);
    DL_BW.init(GLOBAL_RT_PERIOD_NS, GLOBAL_RT_RUNTIME_NS);
}

#[cfg(test)]
#[path = "tests/bw.rs"] mod tests;
