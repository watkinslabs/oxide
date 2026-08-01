// Per-task deadline entity: the atomic home of the static reservation and the
// live instance state, plus the snapshot/store pair the pure CBS rules in
// `cbs.rs` operate on.
//
// Snapshot-apply-store rather than atomics-in-the-algorithm: an instance's
// runtime and deadline move together (the replenish loop trades one for the
// other), so a reader that caught them mid-update would see a budget that was
// never granted against a deadline that was never set.

use core::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};

use super::cbs::DlSched;
use super::params::DlParams;

const BIT_THROTTLED: u8 = 1;
const BIT_YIELDED: u8 = 2;
const BIT_OVERRUN: u8 = 4;

/// "Never stamped" for `exec_start`. NOT zero: zero is a legitimate monotonic
/// timestamp early in boot, and using it as the sentinel silently charges the
/// first stint on every deadline task as if no time had passed.
const NO_EXEC_START: u64 = u64::MAX;

/// A task's `SCHED_DEADLINE` state. Present on every task; inert until a
/// deadline policy is committed, and reset to inert when one is left.
pub struct DlEntity {
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
}

impl DlEntity {
    /// # C: O(1)
    pub const fn new() -> DlEntity {
        DlEntity {
            dl_runtime: AtomicU64::new(0), dl_deadline: AtomicU64::new(0),
            dl_period: AtomicU64::new(0), dl_bw: AtomicU64::new(0),
            dl_density: AtomicU64::new(0), dl_flags: AtomicU64::new(0),
            runtime: AtomicI64::new(0), deadline: AtomicU64::new(0),
            bits: AtomicU8::new(0), exec_start: AtomicU64::new(NO_EXEC_START),
            replenish_at: AtomicU64::new(0),
        }
    }

    /// # C: O(1)
    pub fn params(&self) -> DlParams {
        DlParams {
            runtime: self.dl_runtime.load(Ordering::Acquire),
            deadline: self.dl_deadline.load(Ordering::Acquire),
            period: self.dl_period.load(Ordering::Acquire),
            bw: self.dl_bw.load(Ordering::Acquire),
            density: self.dl_density.load(Ordering::Acquire),
            flags: self.dl_flags.load(Ordering::Acquire),
        }
    }

    /// Install a validated reservation. Only the static half is written — the
    /// instance state belongs to the CBS rules and survives a parameter change
    /// so a task cannot mint fresh budget by re-issuing its own parameters.
    /// # C: O(1)
    pub fn set_params(&self, p: &DlParams) {
        self.dl_runtime.store(p.runtime, Ordering::Release);
        self.dl_deadline.store(p.deadline, Ordering::Release);
        self.dl_period.store(p.period, Ordering::Release);
        self.dl_bw.store(p.bw, Ordering::Release);
        self.dl_density.store(p.density, Ordering::Release);
        self.dl_flags.store(p.flags, Ordering::Release);
    }

    /// Drop the reservation and every instance latch. Run when a task leaves
    /// the deadline class or is reset at fork, so no stale budget or deadline
    /// can be resumed by a later promotion.
    /// # C: O(1)
    pub fn clear(&self) {
        self.set_params(&DlParams::default());
        self.store_sched(&DlSched::default());
        self.exec_start.store(NO_EXEC_START, Ordering::Release);
        self.replenish_at.store(0, Ordering::Release);
    }

    /// # C: O(1)
    pub fn sched(&self) -> DlSched {
        let b = self.bits.load(Ordering::Acquire);
        DlSched {
            runtime: self.runtime.load(Ordering::Acquire),
            deadline: self.deadline.load(Ordering::Acquire),
            throttled: b & BIT_THROTTLED != 0,
            yielded: b & BIT_YIELDED != 0,
            overrun: b & BIT_OVERRUN != 0,
        }
    }

    /// # C: O(1)
    pub fn store_sched(&self, s: &DlSched) {
        self.runtime.store(s.runtime, Ordering::Release);
        self.deadline.store(s.deadline, Ordering::Release);
        let b = (s.throttled as u8) * BIT_THROTTLED
            | (s.yielded as u8) * BIT_YIELDED
            | (s.overrun as u8) * BIT_OVERRUN;
        self.bits.store(b, Ordering::Release);
    }

    /// Absolute deadline, read alone. The EDF ordering key.
    /// # C: O(1)
    pub fn abs_deadline(&self) -> u64 { self.deadline.load(Ordering::Acquire) }

    /// Admitted bandwidth of this entity, in `BW_SHIFT` fixed point.
    /// # C: O(1)
    pub fn bw(&self) -> u64 { self.dl_bw.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn is_throttled(&self) -> bool { self.bits.load(Ordering::Acquire) & BIT_THROTTLED != 0 }

    /// Mark the entity as having given its instance away. Consumed by the next
    /// charge, which throttles it regardless of remaining budget.
    /// # C: O(1)
    pub fn set_yielded(&self) { self.bits.fetch_or(BIT_YIELDED, Ordering::AcqRel); }

    /// Take the pending overrun latch, if any. One signal per latch.
    /// # C: O(1)
    pub fn take_overrun(&self) -> bool {
        self.bits.fetch_and(!BIT_OVERRUN, Ordering::AcqRel) & BIT_OVERRUN != 0
    }

    /// # C: O(1)
    pub fn set_exec_start(&self, now: u64) { self.exec_start.store(now, Ordering::Release); }

    /// Elapsed nanoseconds since the current stint started, advancing the
    /// stamp so the same interval is never charged twice. Returns zero when the
    /// stamp is unset or the clock did not advance.
    /// # C: O(1)
    pub fn take_delta(&self, now: u64) -> u64 {
        let start = self.exec_start.swap(now, Ordering::AcqRel);
        if start == NO_EXEC_START || now <= start { return 0; }
        now - start
    }

    /// # C: O(1)
    pub fn replenish_at(&self) -> u64 { self.replenish_at.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_replenish_at(&self, at: u64) { self.replenish_at.store(at, Ordering::Release); }
}

impl Default for DlEntity {
    fn default() -> Self { Self::new() }
}
