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

pub mod relocatable;
pub use relocatable::{
    parse_relocatable, ParsedRelocatable, Section, Symbol, Rela,
    SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_NOBITS, SHT_REL,
    SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR,
    STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION,
    STB_LOCAL, STB_GLOBAL, STB_WEAK,
};

pub mod dynamic;
pub mod hash;
pub use hash::{elf_hash, gnu_hash, lookup_sysv, lookup_gnu};
pub use dynamic::{
    parse_dynamic, read_strtab, DynEntry, DynInfo,
    DT_NULL, DT_NEEDED, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_JMPREL, DT_HASH, DT_GNU_HASH,
    DT_INIT, DT_FINI, DT_INIT_ARRAY, DT_FINI_ARRAY, DT_SONAME, DT_FLAGS, DT_RUNPATH,
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
