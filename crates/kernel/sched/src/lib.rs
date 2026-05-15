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
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
pub mod kthread;
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
pub use task::{cap, ArchFpuBuf, Creds, PosixTimer, SaHandler, SchedClass, SchedPolicy, SigInfo, Task, TaskState, RT_QUEUE_CAP};

/// Maximum size in bytes of a per-arch HAL `Context` record (per
/// `13§5` + `14§5.2` / `14§6.2`). `Task` carries an opaque buffer
/// of this size; per-arch crates assert at compile-time that their
/// `Context` size does not exceed it. v1 sizes:
/// - x86_64 `ContextX86_64`: 0x40 (64 B)
/// - aarch64 `ContextAArch64`: 0x70 (112 B)
/// 128 leaves headroom for v1.x additions (FPU lazy state ptr,
/// PCID/ASID, KPTI selector) without bumping every release.
pub const ARCH_CTX_SIZE: usize = 128;

/// Opaque per-arch FPU/SIMD state size carried on every Task per
/// `14§7`. Sized to cover the largest per-arch shape:
///   x86_64 FXSAVE area = 512 B
///   aarch64 NEON V regs + FPCR/FPSR = 528 B
/// Plus 16-byte alignment slack. 544 satisfies both with align(16).
pub const ARCH_FPU_SIZE: usize = 544;

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

// Kernel-installed `current task` accessor. The per-CPU "current"
// pointer lives in the kernel module (it depends on per-CPU state
// the sched crate doesn't own — gs_base on x86, tpidr_el1 on arm).
// Other workspace crates that need `current()` (security, nscg,
// drivers) consume it through this hook so they don't have to
// import kernel-internal modules.
use core::sync::atomic::{AtomicU64, Ordering};
static CURRENT_HOOK: AtomicU64 = AtomicU64::new(0);
pub type CurrentFn = fn() -> Option<&'static Task>;

/// Install the per-CPU `current` accessor. Called once at boot from
/// the kernel module that owns the per-CPU state.
/// # C: O(1)
pub fn set_current_hook(f: CurrentFn) {
    CURRENT_HOOK.store(f as u64, Ordering::Release);
}

/// Returns the running task on this CPU, or `None` if unset (host
/// tests, pre-init).
/// # C: O(1)
pub fn current() -> Option<&'static Task> {
    let h = CURRENT_HOOK.load(Ordering::Acquire);
    if h == 0 { return None; }
    // SAFETY: h was installed by `set_current_hook` with matching ABI; sched_crate is the only writer.
    let f: CurrentFn = unsafe { core::mem::transmute(h) };
    f()
}

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

#[cfg(target_os = "oxide-kernel")]
pub mod live;

#[cfg(target_os = "oxide-kernel")] pub mod compat;
#[cfg(target_os = "oxide-kernel")] pub mod cred;
#[cfg(target_os = "oxide-kernel")] pub mod falloc;
#[cfg(target_os = "oxide-kernel")] pub mod prctl;
#[cfg(target_os = "oxide-kernel")] pub mod proclink;
#[cfg(target_os = "oxide-kernel")] pub mod rseq;
#[cfg(target_os = "oxide-kernel")] pub mod timers;
#[cfg(target_os = "oxide-kernel")] pub mod trace;
#[cfg(target_os = "oxide-kernel")] pub mod xfer;
