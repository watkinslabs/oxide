// Syscall dispatch — Linux-numbered ABI table per docs/15.
//
// `dispatch.rs` — `SyscallArgs`, `SyscallFn`, the 462-entry static
// table, `dispatch(nr, args) -> i64` with the `15§1.3` encoding.
// `userptr.rs` — `UserPtr<T>` / `UserSlice<T>` range + alignment
// validation per `15§1.4`.
// `errno.rs` — Linux-numbered `Errno` enum used as the universal
// `KResult<T>` error type at the syscall boundary.
//
// Per-syscall handlers (`sys_read`, `sys_write`, `sys_mmap`, …) land
// alongside their backing subsystems and replace the corresponding
// `sys_enosys` slot at table-build time. The arch trampoline that
// actually drives `dispatch` (`15§4.1`) is HAL-side and rides with
// the per-arch syscall_entry asm.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod dispatch;
pub mod errno;
pub mod nrs;
pub mod userptr;

pub use dispatch::{
    dispatch, handler_for, is_enosys, sys_enosys, SyscallArgs, SyscallFn,
    SYSCALL_TABLE, SYSCALL_TABLE_LEN,
};
pub use errno::{Errno, KResult};
pub use userptr::{UserPtr, UserSlice};

#[cfg(test)]
mod tests;

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
#[cfg(target_os = "oxide-kernel")] pub mod dmesg;


#[cfg(any(target_os = "oxide-kernel", test))] pub mod arm_abi;

