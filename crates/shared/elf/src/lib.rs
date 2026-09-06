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
    parse, ElfError, ElfType, KResult as ParseResult, LoadSegment, ParsedElf, PFlags, PType, TlsSegment,
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
pub mod shared_object;
pub use shared_object::{needed_names, parse_dependency_object, parse_shared_object, soname, SharedObject};
pub mod runtime_reloc;
pub use runtime_reloc::{apply_runtime_relocations, collect_dynamic_symbols, read_dynamic_symbol, runtime_relocation_kinds, DynamicSymbol};
pub mod hash;
pub mod dwarf;
pub mod cfa;
pub mod sections;
pub use dwarf::{encoded_pointer, find_fde, records as dwarf_records, sleb128, uleb128,
    CallFrameRecord, DwarfError, EhBases, frame_program, FrameProgram};
pub use cfa::{evaluate as evaluate_cfa, evaluate_frame, CfaContext};
pub use sections::{eh_frame, find as find_section, publish_eh_frame, PublishedEhFrame, SectionView};
pub use hash::{elf_hash, gnu_hash, lookup_sysv, lookup_gnu};

use alloc::vec::Vec;

/// One runtime-admitted native object. Bytes and their absolute source name
/// stay together until the ELF owner consumes the complete closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixlibSource { pub name: Vec<u8>, pub path: Vec<u8>, pub image: Vec<u8> }

/// Process-owned source catalog for Wine builtin ELF modules.
#[derive(Clone, Default)]
pub struct UnixlibCatalog { objects: Vec<UnixlibSource> }

impl UnixlibCatalog {
    /// Create an empty native-object source catalog. # C: O(1)
    pub fn new() -> Self { Self { objects: Vec::new() } }
    /// Admit one copied source with an absolute path and unique loader name. # C: O(image)
    pub fn add(&mut self, name: &[u8], path: &[u8], image: &[u8]) -> Result<(), ()> {
        if name.is_empty() || path.first() != Some(&b'/') || image.is_empty()
            || name.iter().any(|v| *v == 0) || path.iter().any(|v| *v == 0)
            || self.objects.iter().any(|object| object.name == name) { return Err(()); }
        self.objects.push(UnixlibSource { name: name.to_vec(), path: path.to_vec(), image: image.to_vec() }); Ok(())
    }
    /// Return the runtime-owned source matching one dependency name. # C: O(N)
    pub fn load(&self, name: &[u8]) -> Option<&UnixlibSource> { self.objects.iter().find(|object| object.name == name) }
    /// Return all admitted source objects for process handoff. # C: O(1)
    pub fn objects(&self) -> &[UnixlibSource] { &self.objects }
}
pub use dynamic::{
    parse_dynamic, read_strtab, read_strtab_bytes, DynEntry, DynInfo,
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
