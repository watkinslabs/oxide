// Syscall ABI boundary crate per docs/15, docs/53. Holds the shared ABI
// vocabulary only — NOT a dispatcher. The single kernel dispatcher is
// `oxide_syscall_dispatch` in the `syscalls` crate (`15§4.1`), driven by the
// per-arch syscall_entry asm; per-syscall work lives in `syscalls`/subsystems.
//
// `args.rs` — `SyscallArgs` register block per `15§4`.
// `userptr.rs` — `UserPtr<T>` / `UserSlice<T>` range + alignment
// validation per `15§1.4`.
// `errno.rs` — Linux-numbered `Errno` enum used as the universal
// `KResult<T>` error type at the syscall boundary.
// `nrs.rs` — Linux syscall numbers. `tracepoint.rs` — sys_enter/exit hooks.
// `getrandom.rs` — `GRND_*` flags + flag-validation for `sys_getrandom`.
// `time.rs` — shared timespec→ns decode + `ktime_set`-style clamp.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod args;
pub mod errno;
pub mod getrandom;
pub mod nrs;
pub mod restart;
pub mod sigset;
pub mod time;
pub mod tracepoint;
pub mod userptr;
pub mod wait;

pub use args::SyscallArgs;
pub use errno::{Errno, KResult};
pub use userptr::{scan_user_cstr, UserPtr, UserSlice};

/// Subsystem-level error per `38`. Kept for the existing skeleton
/// `init` shim; the canonical syscall-error type is `Errno` above.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Io,
}

#[allow(dead_code)]
pub(crate) type StubResult<T> = core::result::Result<T, Error>;

/// Initialization entry; called by the kernel boot phase per `00§3` /
/// `boot-flow.md`. v1 returns `NotImplemented`; bodies in P1-N.
///
/// # SAFETY: caller is the boot path, runs single-CPU with IRQs off
/// per `boot-flow.md`. Subsystem-specific preconditions documented at
/// the implementation site.
///
/// # C: O(N_pfn) once at boot
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> StubResult<()> {
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


#[cfg(target_os = "oxide-kernel")] pub mod numa;


#[cfg(any(target_os = "oxide-kernel", test))] pub mod arm_abi;
