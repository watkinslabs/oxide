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
pub mod clock;
pub mod cmdline;
pub mod preempt;
pub mod registry;
pub mod rlimit;
pub mod rt;
pub mod runqueue;
pub mod task;

pub use cfs::CfsRunqueue;
pub use cmdline::argv_to_cmdline;
pub use rt::{RtRunqueue, RT_PRIO_COUNT};
pub use runqueue::RunqueueInner;
pub use task::{Creds, PosixTimer, SaHandler, SchedClass, SchedPolicy, Task, TaskState};

/// Maximum size in bytes of a per-arch HAL `Context` record (per
/// `13§5` + `14§5.2` / `14§6.2`). `Task` carries an opaque buffer
/// of this size; per-arch crates assert at compile-time that their
/// `Context` size does not exceed it. v1 sizes:
/// - x86_64 `ContextX86_64`: 0x40 (64 B)
/// - aarch64 `ContextAArch64`: 0x70 (112 B)
/// 128 leaves headroom for v1.x additions (FPU lazy state ptr,
/// PCID/ASID, KPTI selector) without bumping every release.
pub const ARCH_CTX_SIZE: usize = 128;

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
