// Atomic encoding of a task's scheduling class — split from task.rs to keep it
// under the file-length cap (`08§7`). `Task::class_enc` stores `encode()`;
// `sched_class()` reads back `decode()`. Lets sched_setattr/setparam mutate a
// task's class lock-free without racing the read-only getattr/runqueue readers.

use crate::task::{SchedClass, SchedPolicy};

/// Linux `SCHED_CAPACITY_SCALE` — the utilization-clamp upper bound and the
/// default `uclamp_req[UCLAMP_MAX]` value every task starts with
/// (`uclamp_none(UCLAMP_MAX)`, `kernel/sched/sched.h:3682`).
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
        }
    }
    /// # C: O(1)
    pub fn decode(v: u64) -> SchedClass {
        match v & 0xff {
            1 => SchedClass::Normal { weight: (v >> 8) as u32 },
            2 => SchedClass::Rt { prio: (v >> 8) as u8, policy: SchedPolicy::from_code((v >> 16) as u8) },
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
        // The per-CPU idle task is not `SCHED_IDLE`; Linux runs it in the
        // stop/idle class and still reports policy 0.
        _ => 0,
    }
}

impl crate::task::Task {
    /// Current scheduling class (lock-free decode of `class_enc`).
    /// # C: O(1)
    pub fn sched_class(&self) -> SchedClass {
        SchedClass::decode(self.class_enc.load(core::sync::atomic::Ordering::Acquire))
    }

    /// Store a new scheduling class. Callers changing a QUEUED task's class must
    /// go through `live::runqueue::set_class` (under the rq lock) so the task is
    /// moved between the rt/cfs trees consistently.
    /// # C: O(1)
    pub fn set_sched_class(&self, c: SchedClass) {
        self.class_enc.store(c.encode(), core::sync::atomic::Ordering::Release);
    }

    /// Linux `rt_or_dl_task_policy(tsk)` — SCHED_FIFO / SCHED_RR /
    /// SCHED_DEADLINE. `prctl(PR_SET_TIMERSLACK)` is a no-op for these
    /// (`kernel/sys.c`: `if (rt_or_dl_task_policy(current)) break;`), since a
    /// real-time task's wakeups are not coalescable.
    /// # C: O(1)
    pub fn is_rt_or_dl_policy(&self) -> bool {
        matches!(self.policy.load(core::sync::atomic::Ordering::Acquire),
                 SCHED_FIFO | SCHED_RR | SCHED_DEADLINE)
    }
}

/// Linux `sysctl_sched_rr_timeslice` — 100 ms expressed in ticks. This is the
/// value `sched_rr_get_interval` reports, and until the tick became class-aware
/// nothing enforced it.
pub const RR_TIMESLICE_TICKS: u32 = 100;

/// `SCHED_FIFO` (`include/uapi/linux/sched.h`).
pub const SCHED_FIFO: u32 = 1;
/// `SCHED_RR`.
pub const SCHED_RR: u32 = 2;
/// `SCHED_DEADLINE`.
pub const SCHED_DEADLINE: u32 = 6;

/// The `task_tick` decision as a pure function — Linux `task_tick_rt`
/// (`kernel/sched/rt.c`). Split out so it is testable without a runqueue: the
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
