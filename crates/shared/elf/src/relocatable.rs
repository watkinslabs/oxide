// ELF ET_REL parser — for kernel modules per `docs/18`. Walks the
// section header table (not the program header table); the symbol
// + relocation tables drive the kernel's runtime relocator (which
// rides P10-02+).
//
// The ParsedRelocatable returned by `parse_relocatable` exposes:
//   - Vec<Section> — every SHT entry decoded
//   - Vec<Symbol>  — SYMTAB entries (name + value + size + info)
//   - Vec<Rela>    — RELA records (offset + sym + type + addend)
//
// The runtime relocator (kernel/src/modules.rs) walks Rela,
// looks up Symbol's value (after section placement), and writes
// the relocation per R_X86_64_*.

extern crate alloc;
use alloc::vec::Vec;

use crate::parser::{ELFCLASS64, ELFDATA2LSB, EI_MAG, EV_CURRENT, ElfError, ElfType, KResult};

pub const SHT_NULL:     u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB:   u32 = 2;
pub const SHT_STRTAB:   u32 = 3;
pub const SHT_RELA:     u32 = 4;
pub const SHT_NOBITS:   u32 = 8;
pub const SHT_REL:      u32 = 9;

pub const SHF_WRITE:     u64 = 0x1;
pub const SHF_ALLOC:     u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;

pub const STT_NOTYPE:  u8 = 0;
pub const STT_OBJECT:  u8 = 1;
pub const STT_FUNC:    u8 = 2;
pub const STT_SECTION: u8 = 3;

pub const STB_LOCAL:  u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK:   u8 = 2;

#[derive(Copy, Clone, Debug)]
pub struct Section<'a> {
    pub name:      &'a str,    // resolved against shstrtab
    pub sh_type:   u32,
    pub flags:     u64,
    pub addr:      u64,
    pub offset:    u64,
    pub size:      u64,
    pub link:      u32,
    pub info:      u32,
    pub addralign: u64,
    pub entsize:   u64,
}

#[derive(Copy, Clone, Debug)]
pub struct Symbol<'a> {
    pub name:    &'a str,    // resolved against linked strtab
    pub value:   u64,
    pub size:    u64,
    pub binding: u8,         // STB_*
    pub typ:     u8,         // STT_*
    pub shndx:   u16,        // section the symbol belongs to (or SHN_UNDEF=0)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Rela {
    pub offset: u64,
    pub sym_idx: u32,
    pub r_type: u32,
    pub addend: i64,
    /// Section the relocation applies to (i.e. `link.info` of
    /// the SHT_RELA section that contained this record).
    pub apply_to_shndx: u32,
}

#[derive(Debug)]
pub struct ParsedRelocatable<'a> {
    pub sections: Vec<Section<'a>>,
    pub symbols:  Vec<Symbol<'a>>,
    pub relas:    Vec<Rela>,
    pub e_machine: u16,
}

#[inline] fn u16_at(buf: &[u8], off: usize) -> KResult<u16> {
    Ok(u16::from_le_bytes(buf.get(off..off+2).ok_or(ElfError::Einval)?.try_into().unwrap()))
}
#[inline] fn u32_at(buf: &[u8], off: usize) -> KResult<u32> {
    Ok(u32::from_le_bytes(buf.get(off..off+4).ok_or(ElfError::Einval)?.try_into().unwrap()))
}
#[inline] fn u64_at(buf: &[u8], off: usize) -> KResult<u64> {
    Ok(u64::from_le_bytes(buf.get(off..off+8).ok_or(ElfError::Einval)?.try_into().unwrap()))
}
#[inline] fn i64_at(buf: &[u8], off: usize) -> KResult<i64> {
    Ok(i64::from_le_bytes(buf.get(off..off+8).ok_or(ElfError::Einval)?.try_into().unwrap()))
}

fn cstr_at(buf: &[u8], off: usize) -> KResult<&str> {
    let s = buf.get(off..).ok_or(ElfError::Einval)?;
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    core::str::from_utf8(&s[..end]).map_err(|_| ElfError::Einval)
}

/// Parse an ELF64 ET_REL file. Returns its section + symbol +
/// relocation tables for downstream use by the kernel modules
/// loader.
/// # C: O(N_sections + N_symbols + N_relas)
pub fn parse_relocatable<'a>(file: &'a [u8]) -> KResult<ParsedRelocatable<'a>> {
    if file.len() < 64 { return Err(ElfError::Einval); }
    if file[0..4] != EI_MAG { return Err(ElfError::Enoexec); }
    if file[4] != ELFCLASS64 { return Err(ElfError::Enoexec); }
    if file[5] != ELFDATA2LSB { return Err(ElfError::Enoexec); }
    if file[6] != EV_CURRENT { return Err(ElfError::Enoexec); }
    let elf_type = ElfType::from_u16(u16_at(file, 16)?).ok_or(ElfError::Enoexec)?;
    if elf_type != ElfType::Rel { return Err(ElfError::Enoexec); }
    let e_machine = u16_at(file, 18)?;
    let e_shoff   = u64_at(file, 0x28)? as usize;
    let e_shentsize = u16_at(file, 0x3A)? as usize;
    let e_shnum     = u16_at(file, 0x3C)? as usize;
    let e_shstrndx  = u16_at(file, 0x3E)? as usize;
    if e_shentsize != 64 || e_shnum == 0 { return Err(ElfError::Einval); }
    if e_shstrndx >= e_shnum { return Err(ElfError::Einval); }

    // Locate shstrtab section bytes first.
    let shstr_off = e_shoff + e_shstrndx * e_shentsize;
    let shstr_data_off = u64_at(file, shstr_off + 0x18)? as usize;
    let shstr_data_size = u64_at(file, shstr_off + 0x20)? as usize;
    let shstr = file.get(shstr_data_off..shstr_data_off + shstr_data_size)
        .ok_or(ElfError::Einval)?;

    // Walk all sections.
    let mut sections: Vec<Section<'a>> = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let off = e_shoff + i * e_shentsize;
        let sh_name = u32_at(file, off)? as usize;
        let name = cstr_at(shstr, sh_name)?;
        let sh_type = u32_at(file, off + 0x04)?;
        let flags   = u64_at(file, off + 0x08)?;
        let addr    = u64_at(file, off + 0x10)?;
        let offset  = u64_at(file, off + 0x18)?;
        let size    = u64_at(file, off + 0x20)?;
        let link    = u32_at(file, off + 0x28)?;
        let info    = u32_at(file, off + 0x2C)?;
        let addralign = u64_at(file, off + 0x30)?;
        let entsize  = u64_at(file, off + 0x38)?;
        sections.push(Section {
            name, sh_type, flags, addr, offset, size, link, info, addralign, entsize,
        });
    }

    // Walk SYMTAB sections (typically just one).
    let mut symbols: Vec<Symbol<'a>> = Vec::new();
    for s in sections.iter().filter(|s| s.sh_type == SHT_SYMTAB) {
        let strtab_idx = s.link as usize;
        if strtab_idx >= sections.len() { return Err(ElfError::Einval); }
        let strtab_sec = sections[strtab_idx];
        let strtab = file.get(strtab_sec.offset as usize .. (strtab_sec.offset + strtab_sec.size) as usize)
            .ok_or(ElfError::Einval)?;
        let entsize = s.entsize as usize;
        if entsize != 24 { return Err(ElfError::Einval); }
        let nentries = (s.size / s.entsize) as usize;
        for i in 0..nentries {
            let off = s.offset as usize + i * entsize;
            let st_name  = u32_at(file, off)? as usize;
            let st_info  = file[off + 4];
            let _st_other = file[off + 5];
            let st_shndx = u16_at(file, off + 6)?;
            let st_value = u64_at(file, off + 8)?;
            let st_size  = u64_at(file, off + 16)?;
            let name = cstr_at(strtab, st_name)?;
            symbols.push(Symbol {
                name, value: st_value, size: st_size,
                binding: (st_info >> 4),
                typ:     (st_info & 0x0F),
                shndx:   st_shndx,
            });
        }
    }

    // Walk SHT_RELA sections. (SHT_REL is rare on x86_64.)
    let mut relas: Vec<Rela> = Vec::new();
    for s in sections.iter().filter(|s| s.sh_type == SHT_RELA) {
        let entsize = s.entsize as usize;
        if entsize != 24 { return Err(ElfError::Einval); }
        let nentries = (s.size / s.entsize) as usize;
        for i in 0..nentries {
            let off = s.offset as usize + i * entsize;
            let r_offset = u64_at(file, off)?;
            let r_info   = u64_at(file, off + 8)?;
            let r_addend = i64_at(file, off + 16)?;
            relas.push(Rela {
                offset:  r_offset,
                sym_idx: (r_info >> 32) as u32,
                r_type:  (r_info & 0xFFFF_FFFF) as u32,
                addend:  r_addend,
                apply_to_shndx: s.info,
            });
        }
    }

    Ok(ParsedRelocatable { sections, symbols, relas, e_machine })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_rel_type() {
        // Build a minimal ELF64 ET_DYN header (which the existing
        // executable parser accepts) and confirm parse_relocatable
        // rejects it.
        let mut buf = std::vec![0u8; 64];
        buf[0..4].copy_from_slice(&EI_MAG);
        buf[4] = ELFCLASS64;
        buf[5] = ELFDATA2LSB;
        buf[6] = EV_CURRENT;
        buf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        assert_eq!(parse_relocatable(&buf).err().unwrap(), ElfError::Enoexec);
    }

    #[test]
    fn rejects_short_buffer() {
        let buf = std::vec![0u8; 16];
        assert_eq!(parse_relocatable(&buf).err().unwrap(), ElfError::Einval);
    }
}
