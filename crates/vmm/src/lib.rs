// Virtual Memory Manager — VMA tree + page faults + COW.
//
// Per docs/11 (FROZEN). VMA tree foundation lives in `vma.rs` + `tree.rs`;
// page-fault handler, COW, TLB shootdown, and per-page metadata land in
// subsequent P1-N branches alongside HAL `MmuOps`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod address_space;
pub mod vma;
pub mod tree;

pub use address_space::{AddressSpace, MIN_USER_VA};
pub use vma::{Vma, VmaBacking, VmaFlags, VmaProt};
pub use tree::VmaTree;

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
    klog::kinfo!("vmm: init stub");
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

#[cfg(test)]
mod tests;
