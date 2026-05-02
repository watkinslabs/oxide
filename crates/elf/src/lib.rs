// ELF loader + dynamic linker plumbing per docs/31.
//
// `parser.rs` lands here: ELF64 header validation + program-header
// walk + W^X enforcement (`31§2` invariants 1-3). The actual
// `AddressSpace` mapping (`31§4` step 3.1) drives off
// `vmm::AddressSpace::mmap` which is already implemented; the
// auxv-build, ld.so chain, and exec hand-off ride alongside the
// userspace ABI work that hasn't landed.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod parser;
pub use parser::{
    parse, ElfError, ElfType, KResult as ParseResult, LoadSegment, ParsedElf, PFlags, PType,
    EI_MAG, ELFCLASS64, ELFDATA2LSB, EM_AARCH64, EM_X86_64, EV_CURRENT,
};

#[cfg(test)]
mod tests;

/// Subsystem-level error per `38`. Kept for the existing skeleton
/// `init` shim; the canonical parser error is `ElfError`.
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
    klog::kinfo!("elf: init stub");
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
