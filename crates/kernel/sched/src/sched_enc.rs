// Scheduling policy constants and compatibility descriptors. Task storage lives
// only in `task::TaskSched`; the packed descriptor remains for hosted PI mocks.

use crate::task::{SchedClass, SchedPolicy};

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type TaskPiIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type TaskPiIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
type TaskPiIrq = sync::NoopIrq;

/// Linux `SCHED_CAPACITY_SCALE` — the utilization-clamp upper bound and the
/// default `uclamp_req[UCLAMP_MAX]` value every task starts with
/// (`uclamp_none(UCLAMP_MAX)`).
pub const UCLAMP_CAPACITY_SCALE: u32 = 1024;

impl SchedPolicy {
    /// Stable wire code for the atomic class encoding.
    /// # C: O(1)
    pub fn code(self) -> u8 {
        match self { SchedPolicy::Normal => 0, SchedPolicy::Fifo => 1, SchedPolicy::Rr => 2, SchedPolicy::Idle => 3 }
    }
    /// # C: O(1)
    pub fn from_code(c: u8) -> SchedPolicy {
        match c { 1 => SchedPolicy::Fifo, 2 => SchedPolicy::Rr, 3 => SchedPolicy::Idle, _ => SchedPolicy::Normal }
    }
}

impl SchedClass {
    /// Pack into a u64 (low byte = tag: 0 Idle, 1 Normal, 2 Rt).
    /// # C: O(1)
    pub fn encode(self) -> u64 {
        match self {
            SchedClass::Idle              => 0,
            SchedClass::Normal { weight } => 1 | ((weight as u64) << 8),
            SchedClass::Rt { prio, policy } => 2 | ((prio as u64) << 8) | ((policy.code() as u64) << 16),
            SchedClass::Deadline          => 3,
        }
    }
    /// # C: O(1)
    pub fn decode(v: u64) -> SchedClass {
        match v & 0xff {
            1 => SchedClass::Normal { weight: (v >> 8) as u32 },
            2 => SchedClass::Rt { prio: (v >> 8) as u8, policy: SchedPolicy::from_code((v >> 16) as u8) },
            3 => SchedClass::Deadline,
            _ => SchedClass::Idle,
        }
    }
}

/// Initial Linux `p->policy` code implied by a construction-time `SchedClass`.
/// Only used to seed `Task::policy`; afterwards `p->policy` is authoritative
/// and is set by `sched_setscheduler`/`sched_setattr` (several policies share
/// one class, so the mapping is one-way).
/// # C: O(1)
pub fn policy_code_for(class: SchedClass) -> u32 {
    match class {
        SchedClass::Rt { policy: SchedPolicy::Fifo, .. } => 1,
        SchedClass::Rt { policy: SchedPolicy::Rr, .. }   => 2,
        SchedClass::Deadline                            => SCHED_DEADLINE,
        // The per-CPU idle task is not `SCHED_IDLE`; Linux runs it in the
        // stop/idle class and still reports policy 0.
        _ => 0,
    }
}

impl crate::task::Task {
    /// Current effective scheduling class from canonical task state.
    /// # C: O(1)
    pub fn sched_class(&self) -> SchedClass {
        self.sched.effective_class()
    }

    /// Store effective class state under the task PI lock. Queued changes route
    /// through `live::runqueue::set_class` so the owning class tree is updated.
    /// # C: O(1)
    pub fn set_sched_class(&self, c: SchedClass) {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        self.sched.store_effective_class(c);
    }

    /// Scheduling class with PI donation removed. # C: O(1)
    pub fn normal_sched_class(&self) -> SchedClass {
        self.sched.normal_class()
    }

    /// Configured Linux nice from canonical static priority. # C: O(1)
    pub fn nice_value(&self) -> i8 { self.sched.nice() }

    /// Change latent static priority under the task PI lock. # C: O(1)
    pub fn set_nice_value(&self, nice: i8) {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        self.sched.store_nice(nice);
    }

    /// Replace the configured class without overwriting stronger donated priority. # C: O(1)
    pub fn set_normal_sched_class(&self, class: SchedClass) {
        self.set_normal_sched_class_policy(class, policy_code_for(class));
    }

    /// Replace configured policy and class in one published transaction. # C: O(1)
    pub fn set_normal_sched_class_policy(&self, class: SchedClass, policy: u32) {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        self.sched.store_normal_class(class, policy);
    }

    /// Whether a PI donor remains attached, even if normal currently outranks it. # C: O(1)
    pub fn sched_is_boosted(&self) -> bool { self.sched.is_boosted() }

    /// Clear a retained donor once the PI wait relation is gone. # C: O(1)
    pub fn restore_normal_sched_class(&self) {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        self.sched.restore_normal();
    }

    /// Coherent configured/normal/effective priority view. # C: O(1)
    pub fn priority_snapshot(&self) -> crate::task::PrioritySnapshot {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        self.sched.priority_snapshot()
    }

    /// One generation of the scheduler fields copied by `sched_fork`.
    /// # C: O(1)
    pub(crate) fn sched_fork_snapshot(&self) ->
        (crate::task::PrioritySnapshot, crate::task::SchedUclamp, crate::task::SchedEntity) {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        (self.sched.priority_snapshot(), self.sched.uclamp_snapshot(), self.sched.se.snapshot())
    }

    /// Current validated Linux scheduler policy code. # C: O(1)
    pub fn sched_policy_code(&self) -> u32 { self.sched.priority_snapshot().policy.code() }

    /// Publish the one-shot reset-on-fork setting under the PI lock. # C: O(1)
    pub fn set_sched_reset_on_fork(&self, reset: bool) {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        self.sched.store_reset_on_fork(reset);
    }

    /// Runtime fair-entity counters for procfs and accounting consumers. # C: O(1)
    pub fn sched_entity_snapshot(&self) -> crate::task::SchedEntity { self.sched.se.snapshot() }

    /// Runtime RT-entity counters for policy and watchdog consumers. # C: O(1)
    pub fn sched_rt_entity_snapshot(&self) -> crate::task::SchedRtEntity { self.sched.rt.snapshot() }

    /// Coherent utilization-clamp request tuple. # C: O(1) expected
    pub fn sched_uclamp_snapshot(&self) -> crate::task::SchedUclamp { self.sched.uclamp_snapshot() }

    /// Publish one utilization-clamp request tuple. # C: O(1)
    pub fn set_sched_uclamp(&self, req: crate::task::SchedUclamp) {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        self.sched.store_uclamp(req);
    }

    /// Publish policy, class, clamp, and reset-on-fork as one PI-locked
    /// configuration transaction. # C: O(1)
    pub fn set_sched_policy_controls(&self, class: SchedClass, policy: u32,
                                     req: crate::task::SchedUclamp, reset: bool) {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        self.sched.store_normal_class(class, policy);
        self.sched.store_uclamp(req);
        self.sched.store_reset_on_fork(reset);
    }

    /// Publish clamp and reset-on-fork without changing policy. # C: O(1)
    pub fn set_sched_controls(&self, req: crate::task::SchedUclamp, reset: bool) {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        self.sched.store_uclamp(req);
        self.sched.store_reset_on_fork(reset);
    }

    /// Replace the configured fair slice. # C: O(1)
    pub fn set_sched_slice_ns(&self, slice: u64) {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        self.sched.se.slice.store(slice, core::sync::atomic::Ordering::Release);
        self.sched.se.custom_slice.store(slice != 0, core::sync::atomic::Ordering::Release);
    }

    /// Reset the RT quantum to its full policy value. # C: O(1)
    pub fn reload_sched_rt_timeslice(&self) {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        self.sched.rt.time_slice.store(RR_TIMESLICE_TICKS,
            core::sync::atomic::Ordering::Release);
    }

    /// Clear accumulated RT watchdog time when leaving RT policy. # C: O(1)
    pub fn clear_sched_rt_timeout(&self) {
        let _pi = self.pi_lock.lock_irqsave::<TaskPiIrq>();
        self.sched.rt.timeout.store(0, core::sync::atomic::Ordering::Release);
    }

    #[cfg(feature = "hosted")]
    #[doc(hidden)]
    pub fn test_set_sched_rt_timeslice(&self, ticks: u32) {
        self.sched.rt.time_slice.store(ticks, core::sync::atomic::Ordering::Release);
    }

    #[cfg(feature = "hosted")]
    #[doc(hidden)]
    pub fn test_set_sched_deadline_state(&self, state: &crate::deadline::DlSched) {
        self.sched.dl.store_sched(state);
    }

    #[cfg(feature = "hosted")]
    #[doc(hidden)]
    pub fn test_set_sched_deadline_params(&self, params: &crate::deadline::DlParams) {
        self.sched.dl.set_params(params);
    }

    /// Deadline reservation snapshot for ABI observers. # C: O(1)
    pub fn sched_deadline_params(&self) -> crate::deadline::DlParams { self.sched.dl.params() }

    /// Deadline instance snapshot for ABI observers. # C: O(1)
    pub fn sched_deadline_state(&self) -> crate::deadline::DlSched { self.sched.dl.sched() }

    /// Admitted deadline bandwidth for accounting. # C: O(1)
    pub fn sched_deadline_bw(&self) -> u64 { self.sched.dl.bw() }

    /// Linux `rt_or_dl_task_policy(tsk)` — SCHED_FIFO / SCHED_RR /
    /// SCHED_DEADLINE. `prctl(PR_SET_TIMERSLACK)` is a no-op for these,
    /// since a real-time task's wakeups are not coalescable.
    /// # C: O(1)
    pub fn is_rt_or_dl_policy(&self) -> bool {
        matches!(self.sched_policy_code(), SCHED_FIFO | SCHED_RR | SCHED_DEADLINE)
    }
}

/// Whether `policy` is served by the real-time class — `SCHED_FIFO` or
/// `SCHED_RR`, the two policies whose `task_tick_rt` runs Linux's
/// `RLIMIT_RTTIME` watchdog. `SCHED_DEADLINE` is excluded: it has its own
/// overrun accounting (`dl_overrun`) and is not charged against `RLIMIT_RTTIME`.
/// # C: O(1)
pub const fn is_rt_class_policy(policy: u32) -> bool {
    matches!(policy, SCHED_FIFO | SCHED_RR)
}

/// The `SCHED_RR` quantum, in nanoseconds. ONE value backs both halves of the
/// contract: what the periodic tick actually enforces ([`RR_TIMESLICE_TICKS`])
/// and what `sched_rr_get_interval(2)` reports. Upstream has the same single
/// truth — the quantum is stored in ticks and the syscall converts that same
/// count to a timespec — so an enforced quantum that differs from the reported
/// one is not a tuning choice, it is a bug.
pub const RR_TIMESLICE_NS: u64 = 100_000_000;

/// [`RR_TIMESLICE_NS`] counted in periodic ticks — the unit `task_tick`
/// decrements. DERIVED from the live tick period, never written by hand: the
/// two were independent literals in different units in different crates, and
/// the enforced quantum was ten times the reported one.
pub const RR_TIMESLICE_TICKS: u32 = (RR_TIMESLICE_NS / crate::posix_clock::TICK_NSEC) as u32;

/// `SCHED_NORMAL` == `SCHED_OTHER`.
pub const SCHED_NORMAL: u32 = 0;
/// `SCHED_FIFO`.
pub const SCHED_FIFO: u32 = 1;
/// `SCHED_RR`.
pub const SCHED_RR: u32 = 2;
/// `SCHED_BATCH`.
pub const SCHED_BATCH: u32 = 3;
/// `SCHED_IDLE`. Distinct from [`SchedClass::Idle`], which is the per-CPU idle
/// task's class: a `SCHED_IDLE` task is a fair-class task carrying the minimum
/// weight.
pub const SCHED_IDLE: u32 = 5;
/// `SCHED_DEADLINE`.
pub const SCHED_DEADLINE: u32 = 6;

/// Wakeup-preemption decision (`wakeup_preempt` and the per-class hooks).
pub mod requeue;
pub mod wakeup;

/// The `task_tick` decision as a pure function — Linux `task_tick_rt`.
/// Split out so it is testable without a runqueue: the
/// live tick supplies `slice_left` and `has_peer` and applies the result.
///
/// `SCHED_FIFO` returns false unconditionally (FIFO has no timeslice and runs
/// until it blocks). `SCHED_RR` yields only when the quantum is exhausted AND a
/// peer exists at its level. Everything else preempts per tick.
/// # C: O(1)
pub fn rt_tick_wants_resched(policy: u32, slice_left: u32, has_peer: bool) -> bool {
    match policy {
        SCHED_FIFO => false,
        SCHED_RR   => slice_left <= 1 && has_peer,
        _          => true,
    }
}
