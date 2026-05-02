// TTY + PTY.
//
// Skeleton per docs/28 (FROZEN). Public surface placeholder; method
// bodies land in subsequent P1-N branches.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

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
    klog::kinfo!("tty: init stub");
    Err(Error::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_returns_not_implemented() {
        // Skeletons report NotImplemented so build-system can sanity-check
        // crates link without exercising real behavior.
        // SAFETY: hosted-test entry; nothing else has touched the subsystem; init's preconditions trivially hold.
        let r = unsafe { init() };
        assert_eq!(r, Err(Error::NotImplemented));
    }
}
