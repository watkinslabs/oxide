// /dev, /proc, /sys per docs/19. This crate hosts the *shared
// pseudo-FS primitive* (`pseudo.rs`) used by all three; per-FS
// bodies (per-pid procfs / sysfs KObj tree / devfs DevId nodes)
// ride in their own follow-up branches atop this surface.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod paths;
pub mod pseudo;
pub use paths::{child_under, parse_proc_path, ProcPath};
pub use pseudo::{
    DynamicOps, KResult as PseudoKResult, PseudoError, PseudoFs, PseudoLeaf, PseudoOps,
    StaticBytesOps,
};

#[cfg(test)]
mod tests;

/// Subsystem-level error per `38`. Kept for the existing skeleton
/// `init` shim; the canonical pseudo-FS error is `PseudoError`.
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


#[cfg(target_os = "oxide-kernel")]
pub mod meminfo;

#[cfg(target_os = "oxide-kernel")]
pub mod net;

#[cfg(target_os = "oxide-kernel")] pub mod pid_status;
#[cfg(target_os = "oxide-kernel")] pub mod smaps;
