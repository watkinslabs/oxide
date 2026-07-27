// Atomic encoding of a task's scheduling class — split from task.rs to keep it
// under the file-length cap (`08§7`). `Task::class_enc` stores `encode()`;
// `sched_class()` reads back `decode()`. Lets sched_setattr/setparam mutate a
// task's class lock-free without racing the read-only getattr/runqueue readers.

use crate::task::{SchedClass, SchedPolicy};

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
}
