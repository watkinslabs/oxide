// IPC — pipes, signals, futex, eventfd, AF_UNIX.
//
// Per docs/24 (FROZEN). `WaitQueue` (`06§6`) lands here as the
// foundation for `block_on` / `wake_up` (`13§10`), pipe / eventfd /
// signalfd / timerfd / futex blocking, and the AF_UNIX state machine.
// Pipe / signal / futex bodies land in subsequent P1-N branches.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

mod ipc_namespace;
// futex(2) FUTEX_WAIT restart rule. Kept out of the kernel-only `live` tree so
// the `-ERESTARTSYS` vs `-ERESTART_RESTARTBLOCK` split is hosted-tested.
pub mod futex_restart;
// POSIX mqueue blocking rules (wq_sleep / prepare_timeout). Non-gated so the
// signal-before-timeout order and the timespec validation are hosted-tested.
pub mod mqueue_wait;
pub mod signal;
pub mod sysv;
pub mod sysv_shm;
pub mod waitqueue;
pub use signal::{
    SigAction, SigInfo, Signal, SignalSet, SignalState, SIG_DFL, SIG_IGN,
};
pub use waitqueue::{WaitQueue, WaitQueueInner};

#[cfg(test)]
mod signal_tests;
#[cfg(test)]
mod sysv_removed_gate_race;

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

#[cfg(target_os = "oxide-kernel")]
pub mod live;
