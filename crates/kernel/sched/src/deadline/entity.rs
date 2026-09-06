// Per-task deadline entity: the atomic home of the static reservation and the
// live instance state, plus the snapshot/store pair the pure CBS rules in
// `cbs.rs` operate on.
//
// Snapshot-apply-store rather than atomics-in-the-algorithm: an instance's
// runtime and deadline move together (the replenish loop trades one for the
// other), so a reader that caught them mid-update would see a budget that was
// never granted against a deadline that was never set.

use alloc::sync::{Arc, Weak};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering};

use super::cbs::DlSched;
use super::params::DlParams;

const BIT_THROTTLED: u8 = 1;
const BIT_YIELDED: u8 = 2;
const BIT_OVERRUN: u8 = 4;

const INACTIVE_EMPTY: u64 = 0;
const INACTIVE_ARMED: u64 = 1;
const INACTIVE_CLAIMED: u64 = 2;
const INACTIVE_STATE_BITS: u32 = 2;
const REPLENISH_EMPTY: u64 = 0;
const REPLENISH_ARMED: u64 = 1;
const REPLENISH_CLAIMED: u64 = 2;
const REPLENISH_STATE_BITS: u32 = 2;

/// "Never stamped" for `exec_start`. NOT zero: zero is a legitimate monotonic
/// timestamp early in boot, and using it as the sentinel silently charges the
/// first stint on every deadline task as if no time had passed.
const NO_EXEC_START: u64 = u64::MAX;

/// Shared storage for a task's `SCHED_DEADLINE` state. A policy leave may keep
/// its ordinary reservation attached until the inactive timer reaches zero lag.
pub(super) struct DlEntityState {
    /// Even when quiescent, odd while the static/live tuple is changing.
    seq: AtomicU64,
    dl_runtime: AtomicU64,
    dl_deadline: AtomicU64,
    dl_period: AtomicU64,
    dl_bw: AtomicU64,
    dl_density: AtomicU64,
    dl_flags: AtomicU64,
    /// Remaining budget of the current instance, ns. Signed — see [`DlSched`].
    runtime: AtomicI64,
    /// Absolute deadline of the current instance.
    deadline: AtomicU64,
    bits: AtomicU8,
    /// Monotonic timestamp the current stint on-CPU started at. The charging
    /// step's delta is measured from here, so a task that runs between two
    /// ticks is charged for the time it actually ran rather than for a whole
    /// tick.
    exec_start: AtomicU64,
    /// Monotonic instant this entity's budget is replenished at while it is
    /// throttled. Zero when not throttled.
    replenish_at: AtomicU64,
    /// Generation plus armed/claimed state; prevents popped timer ABA.
    replenish_word: AtomicU64,
    /// Embedded replenishment timer. The global queue owns a strong reference
    /// to this state while armed; the task back-link is weak.
    replenish_owner: sync::Spinlock<Option<Weak<crate::Task>>, sync::DlReplenish>,
    replenish_next: UnsafeCell<Option<Arc<DlEntityState>>>,
    /// Embedded allocation-free EDF ready-tree node, protected by its queue.
    ready_node: UnsafeCell<crate::task::TreeRunNode>,
    /// Embedded inactive timer, generation-stamped against timer/admission ABA.
    inactive_word: AtomicU64,
    inactive_at: AtomicU64,
    inactive_bw: AtomicU64,
    inactive_clear: AtomicBool,
    inactive_next: UnsafeCell<Option<Arc<DlEntityState>>>,
    resume_inactive: AtomicBool,
}

// SAFETY: `replenish_next` is written only under the replenishment QUEUE lock;
// `inactive_next` only under the inactive QUEUE lock. `ready_node` is written
// only by the identity-claiming `DlRunqueue` under exclusive `&mut` access and
// is cleared before that claim is released. `replenish_owner` has its own
// spinlock, and every remaining field is atomic.
unsafe impl Sync for DlEntityState {}

/// One ordinary reservation retained after policy leave until zero lag.
#[derive(Clone)]
pub struct InactiveReservation {
    entity: Arc<DlEntityState>,
    generation: u64,
}

impl InactiveReservation {
    pub(super) fn from_state(entity: Arc<DlEntityState>, generation: u64) -> Self {
        Self { entity, generation }
    }
    fn word(&self, state: u64) -> u64 {
        (self.generation << INACTIVE_STATE_BITS) | state
    }
    /// # C: O(1)
    pub(super) fn at(&self) -> u64 { self.entity.inactive_at.load(Ordering::Acquire) }
    /// # C: O(1)
    pub(super) fn bw(&self) -> u64 { self.entity.inactive_bw.load(Ordering::Acquire) }
    /// # C: O(1)
    pub(super) fn active(&self) -> bool {
        self.entity.inactive_word.load(Ordering::Acquire) == self.word(INACTIVE_ARMED)
    }
    /// Claim this booking while the deadline-bandwidth lock is held. # C: O(1)
    pub(super) fn claim(&self) -> bool {
        self.entity.inactive_word.compare_exchange(self.word(INACTIVE_ARMED),
            self.word(INACTIVE_CLAIMED), Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Keep a new special generation when this old booking expires. # C: O(1)
    pub(super) fn preserve_current(&self) {
        if self.active() { self.entity.inactive_clear.store(false, Ordering::Release); }
    }

    pub(super) fn owner(&self) -> Option<Weak<crate::Task>> {
        self.entity.replenish_owner.lock().clone()
    }

    /// Complete a timer-owned claim and clear the old entity generation. # C: O(1)
    pub(super) fn finish_expiry(&self) {
        if self.entity.inactive_word.compare_exchange(self.word(INACTIVE_CLAIMED),
            INACTIVE_EMPTY, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
        if self.entity.inactive_clear.load(Ordering::Acquire) {
            self.entity.clear_current();
        }
    }

    pub(super) fn entity(&self) -> &Arc<DlEntityState> { &self.entity }
    pub(super) fn same_entity(&self, entity: &Arc<DlEntityState>) -> bool {
        Arc::ptr_eq(&self.entity, entity)
    }
}

/// A task's `SCHED_DEADLINE` state. Present on every task; inert until a
/// deadline policy is committed, and reset to inert after inactive expiry.
pub struct DlEntity {
    inner: Arc<DlEntityState>,
}

impl DlEntity {
    /// # C: O(1)
    pub fn new() -> DlEntity {
        DlEntity { inner: Arc::new(DlEntityState {
            seq: AtomicU64::new(0),
            dl_runtime: AtomicU64::new(0), dl_deadline: AtomicU64::new(0),
            dl_period: AtomicU64::new(0), dl_bw: AtomicU64::new(0),
            dl_density: AtomicU64::new(0), dl_flags: AtomicU64::new(0),
            runtime: AtomicI64::new(0), deadline: AtomicU64::new(0),
            bits: AtomicU8::new(0), exec_start: AtomicU64::new(NO_EXEC_START),
            replenish_at: AtomicU64::new(0),
            replenish_word: AtomicU64::new(REPLENISH_EMPTY),
            replenish_owner: sync::Spinlock::new(None),
            replenish_next: UnsafeCell::new(None),
            ready_node: UnsafeCell::new(crate::task::TreeRunNode::new()),
            inactive_word: AtomicU64::new(INACTIVE_EMPTY),
            inactive_at: AtomicU64::new(0), inactive_bw: AtomicU64::new(0),
            inactive_clear: AtomicBool::new(false), inactive_next: UnsafeCell::new(None),
            resume_inactive: AtomicBool::new(false),
        }) }
    }

    /// # C: O(1)
    pub(crate) fn params(&self) -> DlParams { self.snapshot().0 }

    /// One coherent static/live entity generation. # C: O(1) expected
    pub(crate) fn snapshot(&self) -> (DlParams, DlSched) {
        #[cfg(test)]
        publication_test::check_reader(self);
        loop {
            let seq = self.inner.seq.load(Ordering::Acquire);
            if seq & 1 != 0 { core::hint::spin_loop(); continue; }
            let params = DlParams {
                runtime: self.inner.dl_runtime.load(Ordering::Relaxed),
                deadline: self.inner.dl_deadline.load(Ordering::Relaxed),
                period: self.inner.dl_period.load(Ordering::Relaxed),
                bw: self.inner.dl_bw.load(Ordering::Relaxed),
                density: self.inner.dl_density.load(Ordering::Relaxed),
                flags: self.inner.dl_flags.load(Ordering::Relaxed),
            };
            let b = self.inner.bits.load(Ordering::Relaxed);
            let sched = DlSched {
                runtime: self.inner.runtime.load(Ordering::Relaxed),
                deadline: self.inner.deadline.load(Ordering::Relaxed),
                throttled: b & BIT_THROTTLED != 0,
                yielded: b & BIT_YIELDED != 0,
                overrun: b & BIT_OVERRUN != 0,
            };
            if self.inner.seq.load(Ordering::Acquire) == seq { return (params, sched); }
        }
    }

    /// Install a validated reservation. Only the static half is written — the
    /// instance state belongs to the CBS rules and survives a parameter change
    /// so a task cannot mint fresh budget by re-issuing its own parameters.
    /// # C: O(1)
    pub(crate) fn set_params(&self, p: &DlParams) {
        let _publication = self.inner.write_begin();
        self.inner.dl_runtime.store(p.runtime, Ordering::Release);
        self.inner.dl_deadline.store(p.deadline, Ordering::Release);
        self.inner.dl_period.store(p.period, Ordering::Release);
        self.inner.dl_bw.store(p.bw, Ordering::Release);
        self.inner.dl_density.store(p.density, Ordering::Release);
        self.inner.dl_flags.store(p.flags, Ordering::Release);
    }

    pub(crate) fn store_entity(&self, p: &DlParams, s: &DlSched) {
        let _publication = self.inner.write_begin();
        self.inner.dl_runtime.store(p.runtime, Ordering::Relaxed);
        self.inner.dl_deadline.store(p.deadline, Ordering::Relaxed);
        self.inner.dl_period.store(p.period, Ordering::Relaxed);
        self.inner.dl_bw.store(p.bw, Ordering::Relaxed);
        self.inner.dl_density.store(p.density, Ordering::Relaxed);
        self.inner.dl_flags.store(p.flags, Ordering::Relaxed);
        self.inner.runtime.store(s.runtime, Ordering::Relaxed);
        self.inner.deadline.store(s.deadline, Ordering::Relaxed);
        let bits = (s.throttled as u8) * BIT_THROTTLED
            | (s.yielded as u8) * BIT_YIELDED | (s.overrun as u8) * BIT_OVERRUN;
        self.inner.bits.store(bits, Ordering::Relaxed);
    }

    /// Drop the reservation and every instance latch. Run after inactive
    /// expiry (or immediately for an unbooked/special entity) and at fork, so
    /// no stale budget or deadline can be resumed by a later promotion.
    /// # C: O(1)
    pub(crate) fn clear(&self) {
        self.inner.clear_current();
    }

    /// # C: O(1)
    pub(crate) fn sched(&self) -> DlSched { self.snapshot().1 }

    /// # C: O(1)
    pub(crate) fn store_sched(&self, s: &DlSched) {
        let _publication = self.inner.write_begin();
        self.inner.runtime.store(s.runtime, Ordering::Release);
        self.inner.deadline.store(s.deadline, Ordering::Release);
        let b = (s.throttled as u8) * BIT_THROTTLED
            | (s.yielded as u8) * BIT_YIELDED
            | (s.overrun as u8) * BIT_OVERRUN;
        self.inner.bits.store(b, Ordering::Release);
    }

    /// Absolute deadline, read alone. The EDF ordering key.
    /// # C: O(1)
    pub(crate) fn abs_deadline(&self) -> u64 { self.sched().deadline }

    /// Admitted bandwidth of this entity, in `BW_SHIFT` fixed point.
    /// # C: O(1)
    pub(crate) fn bw(&self) -> u64 { self.params().bw }

    /// Claim booked bandwidth on an immediate-release path. Delayed releases
    /// are claimed by their inactive reservation under the bandwidth lock.
    /// # C: O(1)
    pub(crate) fn take_bw(&self) -> u64 {
        let _publication = self.inner.write_begin();
        let bw = self.inner.dl_bw.swap(0, Ordering::AcqRel);
        bw
    }

    /// # C: O(1)
    pub(crate) fn is_throttled(&self) -> bool { self.sched().throttled }

    /// Mark the entity as having given its instance away. Consumed by the next
    /// charge, which throttles it regardless of remaining budget.
    /// # C: O(1)
    pub(crate) fn set_yielded(&self) {
        let _publication = self.inner.write_begin();
        self.inner.bits.fetch_or(BIT_YIELDED, Ordering::AcqRel);
    }

    /// Take the pending overrun latch, if any. One signal per latch.
    /// # C: O(1)
    pub(crate) fn take_overrun(&self) -> bool {
        let _publication = self.inner.write_begin();
        let overrun = self.inner.bits.fetch_and(!BIT_OVERRUN, Ordering::AcqRel) & BIT_OVERRUN != 0;
        overrun
    }

    /// # C: O(1)
    pub(crate) fn set_exec_start(&self, now: u64) { self.inner.exec_start.store(now, Ordering::Release); }

    /// Elapsed nanoseconds since the current stint started, advancing the
    /// stamp so the same interval is never charged twice. Returns zero when the
    /// stamp is unset or the clock did not advance.
    /// # C: O(1)
    pub(crate) fn take_delta(&self, now: u64) -> u64 {
        let start = self.inner.exec_start.swap(now, Ordering::AcqRel);
        if start == NO_EXEC_START || !super::cbs::dl_time_before(start, now) { return 0; }
        now.wrapping_sub(start)
    }

    /// # C: O(1)
    pub(crate) fn replenish_at(&self) -> u64 { self.inner.replenish_at.load(Ordering::Acquire) }
    /// # C: O(1)
    pub(crate) fn set_replenish_at(&self, at: u64) { self.inner.replenish_at.store(at, Ordering::Release); }

    pub(super) fn arm_replenish(&self, generation: u64, at: u64) {
        self.inner.replenish_at.store(at, Ordering::Relaxed);
        self.inner.replenish_word.store(
            (generation << REPLENISH_STATE_BITS) | REPLENISH_ARMED,
            Ordering::Release);
    }

    pub(super) fn cancel_replenish(&self) {
        self.inner.replenish_word.store(REPLENISH_EMPTY, Ordering::Release);
        self.inner.replenish_at.store(0, Ordering::Release);
    }

    /// Install one zero-lag hold unless this entity already has one. # C: O(1)
    pub(super) fn state_ref(&self) -> Arc<DlEntityState> { Arc::clone(&self.inner) }

    /// Bind timer callbacks to the stable task allocation. # C: O(1)
    pub(crate) fn bind_owner(&self, task: &Arc<crate::Task>) {
        self.inner.set_replenish_owner(Arc::downgrade(task));
    }

    /// # SAFETY: caller owns the claiming `DlRunqueue`; `on_class_rq` excludes
    /// every other class queue until this link has been cleared.
    pub(crate) unsafe fn ready_node_mut(&self) -> &mut crate::task::TreeRunNode {
        // SAFETY: the queue identity claim and `&mut DlRunqueue` are exclusive.
        unsafe { &mut *self.inner.ready_node.get() }
    }

    /// # SAFETY: caller owns the claiming `DlRunqueue` against tree mutation.
    pub(crate) unsafe fn ready_node(&self) -> &crate::task::TreeRunNode {
        unsafe { &*self.inner.ready_node.get() }
    }

    /// Arm the embedded inactive timer unless an older generation owns it. # C: O(1)
    pub(super) fn arm_inactive(&self, generation: u64, at: u64, bw: u64,
                               clear_on_expire: bool) -> Option<InactiveReservation> {
        if self.inner.inactive_word.load(Ordering::Acquire) != INACTIVE_EMPTY { return None; }
        self.inner.inactive_at.store(at, Ordering::Relaxed);
        self.inner.inactive_bw.store(bw, Ordering::Relaxed);
        self.inner.inactive_clear.store(clear_on_expire, Ordering::Relaxed);
        let word = (generation << INACTIVE_STATE_BITS) | INACTIVE_ARMED;
        self.inner.inactive_word.compare_exchange(INACTIVE_EMPTY, word,
            Ordering::Release, Ordering::Acquire).ok()?;
        Some(InactiveReservation { entity: self.state_ref(), generation })
    }

    /// Snapshot a pending zero-lag booking for atomic admission. # C: O(1)
    pub(super) fn inactive(&self) -> Option<InactiveReservation> {
        let word = self.inner.inactive_word.load(Ordering::Acquire);
        if word == INACTIVE_EMPTY { return None; }
        Some(InactiveReservation { entity: self.state_ref(),
            generation: word >> INACTIVE_STATE_BITS })
    }

    /// Detach a booking claimed by admission and remember whether to resume
    /// its current runtime/deadline instance. # C: O(1)
    pub(super) fn consume_inactive(&self, held: &InactiveReservation, resume: bool) {
        if !held.same_entity(&self.inner) { return; }
        self.inner.resume_inactive.store(resume, Ordering::Release);
        let _ = self.inner.inactive_word.compare_exchange(held.word(INACTIVE_CLAIMED),
            INACTIVE_EMPTY, Ordering::AcqRel, Ordering::Acquire);
    }

    /// Consume the resume decision prepared with admission. # C: O(1)
    pub(super) fn take_resume_inactive(&self) -> bool {
        self.inner.resume_inactive.swap(false, Ordering::AcqRel)
    }

    /// Pending zero-lag instant, or zero. # C: O(1)
    #[cfg(any(test, feature = "hosted"))]
    pub(crate) fn inactive_at(&self) -> u64 {
        self.inactive().filter(InactiveReservation::active).map_or(0, |held| held.at())
    }

    /// Whether a timer or admission transition still owns an inactive token. # C: O(1)
    pub(super) fn has_inactive(&self) -> bool {
        self.inner.inactive_word.load(Ordering::Acquire) != INACTIVE_EMPTY
    }
}

impl DlEntityState {
    fn write_begin(&self) -> super::publication::Publication<'_> {
        super::publication::Publication::begin(&self.seq)
    }
    pub(super) fn replenish_at(&self) -> u64 { self.replenish_at.load(Ordering::Acquire) }
    pub(super) fn set_replenish_at(&self, at: u64) { self.replenish_at.store(at, Ordering::Release); }
    pub(super) fn set_replenish_owner(&self, owner: Weak<crate::Task>) {
        *self.replenish_owner.lock() = Some(owner);
    }
    pub(super) fn replenish_owner(&self) -> Option<Weak<crate::Task>> {
        self.replenish_owner.lock().clone()
    }
    pub(super) fn claim_replenish(self: &Arc<Self>) -> Option<ReplenishmentClaim> {
        let word = self.replenish_word.load(Ordering::Acquire);
        if word & ((1 << REPLENISH_STATE_BITS) - 1) != REPLENISH_ARMED { return None; }
        self.replenish_word.compare_exchange(word,
            (word & !((1 << REPLENISH_STATE_BITS) - 1)) | REPLENISH_CLAIMED,
            Ordering::AcqRel, Ordering::Acquire).ok()?;
        Some(ReplenishmentClaim { entity: Arc::clone(self),
            generation: word >> REPLENISH_STATE_BITS,
            at: self.replenish_at.load(Ordering::Acquire) })
    }
    pub(super) fn inactive_timer(self: &Arc<Self>) -> Option<InactiveReservation> {
        let word = self.inactive_word.load(Ordering::Acquire);
        if word == INACTIVE_EMPTY { return None; }
        Some(InactiveReservation::from_state(Arc::clone(self),
            word >> INACTIVE_STATE_BITS))
    }

    /// # SAFETY: caller holds the inactive queue lock and this node is linked once.
    pub(super) unsafe fn inactive_next_mut(&self) -> &mut Option<Arc<DlEntityState>> {
        // SAFETY: the queue lock gives exclusive access to this intrusive link.
        unsafe { &mut *self.inactive_next.get() }
    }

    /// # SAFETY: caller holds the replenishment queue lock and this node is linked once.
    pub(super) unsafe fn replenish_next_mut(&self) -> &mut Option<Arc<DlEntityState>> {
        // SAFETY: the queue lock gives exclusive access to this intrusive link.
        unsafe { &mut *self.replenish_next.get() }
    }

    fn clear_current(&self) {
        let _publication = self.write_begin();
        self.dl_runtime.store(0, Ordering::Release);
        self.dl_deadline.store(0, Ordering::Release);
        self.dl_period.store(0, Ordering::Release);
        self.dl_bw.store(0, Ordering::Release);
        self.dl_density.store(0, Ordering::Release);
        self.dl_flags.store(0, Ordering::Release);
        self.runtime.store(0, Ordering::Release);
        self.deadline.store(0, Ordering::Release);
        self.bits.store(0, Ordering::Release);
        self.exec_start.store(NO_EXEC_START, Ordering::Release);
        self.replenish_at.store(0, Ordering::Release);
        self.replenish_word.store(REPLENISH_EMPTY, Ordering::Release);
        self.resume_inactive.store(false, Ordering::Release);
    }
}

/// One popped replenishment generation claimed by the timer.
pub(super) struct ReplenishmentClaim {
    entity: Arc<DlEntityState>,
    generation: u64,
    at: u64,
}

impl ReplenishmentClaim {
    fn word(&self) -> u64 {
        (self.generation << REPLENISH_STATE_BITS) | REPLENISH_CLAIMED
    }
    pub(super) fn at(&self) -> u64 { self.at }
    pub(super) fn current(&self) -> bool {
        self.entity.replenish_word.load(Ordering::Acquire) == self.word()
    }
    pub(super) fn finish(&self) -> bool {
        if self.entity.replenish_word.compare_exchange(self.word(), REPLENISH_EMPTY,
            Ordering::AcqRel, Ordering::Acquire).is_err() { return false; }
        self.entity.replenish_at.store(0, Ordering::Release);
        true
    }
}

impl Default for DlEntity {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
#[path = "tests/publication.rs"]
mod publication_test;
