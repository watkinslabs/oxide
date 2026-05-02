// ELF64 parser per `31§4`. Validates the header, walks program
// headers, returns a `ParsedElf` describing PT_LOAD segments + the
// optional interpreter path. The actual `AddressSpace` mapping +
// auxv build + ld.so chain ride alongside `vmm::AddressSpace::mmap`
// (already landed) and the userspace ABI / vDSO work that hasn't.
//
// Verifies invariants 1-3 (`31§2`) at parse time:
//   1. ELF64 + matching e_machine.
//   2. PIE preferred (ET_DYN warned-on-not, ET_EXEC accepted with
//      a flag the caller sees).
//   3. W^X — no PT_LOAD with both W and X. PT_GNU_STACK with X is
//      rejected (`31§4` step 3.4).

extern crate alloc;
use alloc::vec::Vec;
use core::convert::TryInto;

/// Parsing error per `31§9` ENOEXEC contract.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ElfError {
    Enoexec  = 8,   // wrong magic / wrong class / wrong endian / wrong arch
    Einval   = 22,  // malformed header / phdr table / wx-violation
    Eopnotsupp = 95, // PT_TLS, etc. not yet handled
}

pub type KResult<T> = core::result::Result<T, ElfError>;

// ---------------------------------------------------------------------------
// ELF64 header constants
// ---------------------------------------------------------------------------

pub const EI_MAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EV_CURRENT: u8 = 1;
pub const ELFOSABI_SYSV: u8 = 0;

pub const EM_X86_64:  u16 = 62;
pub const EM_AARCH64: u16 = 183;

#[repr(u16)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ElfType {
    Rel  = 1,
    Exec = 2,
    Dyn  = 3,
    Core = 4,
}

impl ElfType {
    /// # C: O(1)
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Rel),
            2 => Some(Self::Exec),
            3 => Some(Self::Dyn),
            4 => Some(Self::Core),
            _ => None,
        }
    }
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PType {
    Null    = 0,
    Load    = 1,
    Dynamic = 2,
    Interp  = 3,
    Note    = 4,
    Phdr    = 6,
    Tls     = 7,
    GnuStack = 0x6474_e551,
    GnuRelro = 0x6474_e552,
}

bitflags::bitflags! {
    /// PT_LOAD `p_flags` bits per ELF spec.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct PFlags: u32 {
        const X = 1 << 0;
        const W = 1 << 1;
        const R = 1 << 2;
    }
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// One PT_LOAD segment per `31§4` step 3.1. `vaddr` is the file's
/// requested vaddr; the caller adds `load_bias` for PIE.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LoadSegment {
    pub flags:    PFlags,
    pub file_off: u64,
    pub file_sz:  u64,
    pub vaddr:    u64,
    pub mem_sz:   u64,
    pub align:    u64,
}

/// Parsed ELF view. The full file is borrowed by the parser; the
/// caller drives `mmap` from these descriptors.
#[derive(Debug)]
pub struct ParsedElf<'a> {
    pub raw:        &'a [u8],
    pub elf_type:   ElfType,
    pub machine:    u16,
    pub entry:      u64,
    pub loads:      Vec<LoadSegment>,
    /// Slice of the raw file holding the interp path (with the
    /// trailing NUL trimmed).
    pub interp:     Option<&'a [u8]>,
}

impl<'a> ParsedElf<'a> {
    /// True iff a PIE binary per `31§2` invariant 2.
    /// # C: O(1)
    pub fn is_pie(&self) -> bool { self.elf_type == ElfType::Dyn }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse the header + program-header table. The supplied `arch_machine`
/// pins invariant 1 (`31§2`); pass `EM_X86_64` or `EM_AARCH64`.
/// # C: O(phdrs)
pub fn parse(file: &[u8], arch_machine: u16) -> KResult<ParsedElf<'_>> {
    if file.len() < 64 { return Err(ElfError::Enoexec); }
    if &file[0..4] != EI_MAG { return Err(ElfError::Enoexec); }
    if file[4] != ELFCLASS64 { return Err(ElfError::Enoexec); }
    if file[5] != ELFDATA2LSB { return Err(ElfError::Enoexec); }
    if file[6] != EV_CURRENT { return Err(ElfError::Enoexec); }

    let elf_type = ElfType::from_u16(u16(file, 16)?).ok_or(ElfError::Enoexec)?;
    if !matches!(elf_type, ElfType::Exec | ElfType::Dyn) {
        return Err(ElfError::Enoexec);
    }

    let machine = u16(file, 18)?;
    if machine != arch_machine {
        return Err(ElfError::Enoexec);
    }

    let entry     = u64(file, 24)?;
    let phoff     = u64(file, 32)? as usize;
    let phentsize = u16(file, 54)? as usize;
    let phnum     = u16(file, 56)? as usize;

    if phentsize < 56 { return Err(ElfError::Einval); }
    let phdr_table_end = phoff.checked_add(phentsize.checked_mul(phnum).ok_or(ElfError::Einval)?)
        .ok_or(ElfError::Einval)?;
    if phdr_table_end > file.len() { return Err(ElfError::Einval); }

    let mut loads = Vec::with_capacity(phnum);
    let mut interp: Option<&[u8]> = None;

    for i in 0..phnum {
        let base = phoff + i * phentsize;
        let p_type   = u32(file, base + 0)?;
        let p_flags  = u32(file, base + 4)?;
        let p_offset = u64(file, base + 8)? as usize;
        let p_vaddr  = u64(file, base + 16)?;
        let p_filesz = u64(file, base + 32)? as u64;
        let p_memsz  = u64(file, base + 40)? as u64;
        let p_align  = u64(file, base + 48)? as u64;

        match p_type {
            x if x == PType::Load as u32 => {
                let flags = PFlags::from_bits_truncate(p_flags);
                if flags.contains(PFlags::W) && flags.contains(PFlags::X) {
                    return Err(ElfError::Einval);
                }
                if p_filesz > p_memsz { return Err(ElfError::Einval); }
                if p_offset.checked_add(p_filesz as usize).map_or(true, |e| e > file.len()) {
                    return Err(ElfError::Einval);
                }
                loads.push(LoadSegment {
                    flags,
                    file_off: p_offset as u64,
                    file_sz:  p_filesz,
                    vaddr:    p_vaddr,
                    mem_sz:   p_memsz,
                    align:    p_align,
                });
            }
            x if x == PType::Interp as u32 => {
                let end = p_offset.checked_add(p_filesz as usize).ok_or(ElfError::Einval)?;
                if end > file.len() || p_filesz == 0 { return Err(ElfError::Einval); }
                let mut s = &file[p_offset..end];
                // Trim trailing NUL per ELF convention.
                if let Some(&0) = s.last() { s = &s[..s.len() - 1]; }
                interp = Some(s);
            }
            x if x == PType::GnuStack as u32 => {
                // Stack must NOT be executable per `31§2` invariant 3
                // ("PT_GNU_STACK ... must be off in v1; W^X").
                if (p_flags & PFlags::X.bits()) != 0 {
                    return Err(ElfError::Einval);
                }
            }
            x if x == PType::Tls as u32 => {
                // TLS template handling lands with userspace TLS support;
                // for v1 a TLS phdr is allowed but unused.
            }
            _ => {} // Other phdr kinds (Dynamic, Note, Phdr, GnuRelro) are noted by ld.so.
        }
    }

    Ok(ParsedElf { raw: file, elf_type, machine, entry, loads, interp })
}

#[inline]
fn u16(buf: &[u8], off: usize) -> KResult<u16> {
    let bytes: [u8; 2] = buf.get(off..off + 2)
        .ok_or(ElfError::Einval)?
        .try_into()
        .map_err(|_| ElfError::Einval)?;
    Ok(u16::from_le_bytes(bytes))
}

#[inline]
fn u32(buf: &[u8], off: usize) -> KResult<u32> {
    let bytes: [u8; 4] = buf.get(off..off + 4)
        .ok_or(ElfError::Einval)?
        .try_into()
        .map_err(|_| ElfError::Einval)?;
    Ok(u32::from_le_bytes(bytes))
}

#[inline]
fn u64(buf: &[u8], off: usize) -> KResult<u64> {
    let bytes: [u8; 8] = buf.get(off..off + 8)
        .ok_or(ElfError::Einval)?
        .try_into()
        .map_err(|_| ElfError::Einval)?;
    Ok(u64::from_le_bytes(bytes))
}
