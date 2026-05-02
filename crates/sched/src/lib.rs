// Scheduler — 3-class (RT / Normal-CFS / Idle).
//
// Per docs/13 (FROZEN). Runqueue + class containers + `pick_next_task`
// land here; `schedule()` proper, `wake_up`, IPI, SMP load balance,
// and `timer_tick` ride alongside HAL `Context` in subsequent P1-N
// branches.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod cfs;
pub mod rt;
pub mod runqueue;
pub mod task;

pub use cfs::CfsRunqueue;
pub use rt::{RtRunqueue, RT_PRIO_COUNT};
pub use runqueue::RunqueueInner;
pub use task::{SchedClass, SchedPolicy, Task, TaskState};

#[cfg(test)]
mod tests;

/// Subsystem-level error per `38`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Io,
}

pub type KResult<T> = core::result::Result<T, Error>;

/// Initialization entry; called by the kernel boot phase per `00§3` /
/// `boot-flow.md`. v1 returns `NotImplemented`; bodies in P1-N.
///
/// # SAFETY: caller is the boot path, runs single-CPU with IRQs off
/// per `boot-flow.md`. Subsystem-specific preconditions documented at
/// the implementation site.
///
/// # C: O(N_pfn) once at boot
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> KResult<()> {
    klog::kinfo!("sched: init stub");
    Err(Error::NotImplemented)
}

#[cfg(test)]
mod stub_tests {
    use super::*;

    #[test]
    fn init_returns_not_implemented() {
        // SAFETY: hosted-test entry; nothing else has touched the subsystem; init's preconditions trivially hold.
        let r = unsafe { init() };
        assert_eq!(r, Err(Error::NotImplemented));
    }
}
