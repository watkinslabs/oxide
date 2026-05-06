// Minimum kernel-modules loader. Takes a `.ko` ET_REL ELF + a
// symbol resolver, places each loadable section into a freshly-
// allocated heap buffer, resolves symbols, applies relocations.
//
// The product is a `LoadedModule` that pins the section buffers
// in memory + records the resolved symbol vaddrs. Calling
// `init_module()` on the loaded code is the next step (P10-04);
// requires the kernel-side mmap-with-EXEC permissions which is
// orthogonal — for now hosted-test exercises the relocator end
// to end against synthetic .ko payloads.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use elf::{
    parse_relocatable, ParsedRelocatable,
    SHF_ALLOC, SHT_NOBITS, SHT_PROGBITS,
};

use crate::relocator::{apply, RelocError};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LoadError {
    BadElf,
    Reloc(RelocError),
    UndefinedSymbol,
    SectionTooLarge,
}

/// One placed-in-memory section.
pub struct PlacedSection {
    pub name:    String,
    pub bytes:   Vec<u8>,    // owns the placed bytes (heap)
    pub vbase:   u64,        // virtual base address (== bytes.as_ptr() in v1)
    pub flags:   u64,        // SHF_*
}

/// Loaded module record. Borrowed by the kernel-side module
/// registry; dropping it frees the section bytes (and so unloads
/// the module).
pub struct LoadedModule {
    pub sections: Vec<PlacedSection>,
    /// Resolved (name → absolute VA) for every defined symbol.
    pub symbols:  BTreeMap<String, u64>,
}

/// Symbol resolver: looks up an external symbol name and returns
/// its absolute virtual address. Used for symbols the module
/// references (e.g. `klog_write_raw`, `kassert`) that aren't
/// defined inside the module itself.
pub trait SymResolver {
    fn resolve(&self, name: &str) -> Option<u64>;
}

/// Place sections + resolve symbols + apply relocations.
/// Returns the LoadedModule on success.
/// # C: O(N_sections + N_symbols + N_relocs)
pub fn load_module<R: SymResolver>(bytes: &[u8], resolver: &R) -> Result<LoadedModule, LoadError> {
    let parsed: ParsedRelocatable<'_> = parse_relocatable(bytes).map_err(|_| LoadError::BadElf)?;

    // Phase 1: place each ALLOC section into a fresh heap Vec.
    // Section index → (vbase, bytes). We build a parallel Vec<Option>
    // so non-ALLOC slots are None.
    let mut placed: Vec<Option<PlacedSection>> = Vec::with_capacity(parsed.sections.len());
    for s in &parsed.sections {
        if (s.flags & SHF_ALLOC) == 0 {
            placed.push(None);
            continue;
        }
        let mut buf = alloc::vec![0u8; s.size as usize];
        if s.sh_type == SHT_PROGBITS {
            let src = bytes.get(s.offset as usize .. (s.offset + s.size) as usize)
                .ok_or(LoadError::BadElf)?;
            buf.copy_from_slice(src);
        }
        // SHT_NOBITS (.bss) stays zero-initialized.
        let _ = SHT_NOBITS;
        let vbase = buf.as_ptr() as u64;
        placed.push(Some(PlacedSection {
            name:  s.name.to_string(),
            bytes: buf,
            vbase,
            flags: s.flags,
        }));
    }

    // Phase 2: resolve symbols. Defined symbols (shndx != 0) get
    // section_vbase + value; undefined (shndx==0) go through the
    // resolver.
    let mut symbol_addrs: Vec<Option<u64>> = Vec::with_capacity(parsed.symbols.len());
    let mut named_symbols: BTreeMap<String, u64> = BTreeMap::new();
    for sym in &parsed.symbols {
        if sym.shndx == 0 {
            // Undefined — must resolve externally.
            if sym.name.is_empty() {
                symbol_addrs.push(None);
                continue;
            }
            match resolver.resolve(sym.name) {
                Some(v) => {
                    symbol_addrs.push(Some(v));
                    named_symbols.insert(sym.name.to_string(), v);
                }
                None => return Err(LoadError::UndefinedSymbol),
            }
        } else {
            let idx = sym.shndx as usize;
            if idx >= placed.len() {
                return Err(LoadError::BadElf);
            }
            let base = match &placed[idx] {
                Some(ps) => ps.vbase,
                None     => 0, // symbol in non-ALLOC section (e.g. debug)
            };
            let v = base.wrapping_add(sym.value);
            symbol_addrs.push(Some(v));
            if !sym.name.is_empty() {
                named_symbols.insert(sym.name.to_string(), v);
            }
        }
    }

    // Phase 3: apply each relocation. Skip relocs that target a
    // non-ALLOC section.
    for r in &parsed.relas {
        let target_idx = r.apply_to_shndx as usize;
        if target_idx >= placed.len() { continue; }
        let target = match &mut placed[target_idx] {
            Some(ps) => ps,
            None     => continue,
        };
        let sym_value = match symbol_addrs.get(r.sym_idx as usize) {
            Some(Some(v)) => *v,
            _ => return Err(LoadError::UndefinedSymbol),
        };
        let dest_base = target.vbase;
        apply(r.r_type, r.offset, r.addend, sym_value, &mut target.bytes, dest_base)
            .map_err(LoadError::Reloc)?;
    }

    // Collect placed sections (drop the Option wrapping).
    let sections: Vec<PlacedSection> = placed.into_iter().filter_map(|x| x).collect();
    Ok(LoadedModule { sections, symbols: named_symbols })
}

#[cfg(test)]
mod tests {
    use super::*;
    use elf::{
        EI_MAG, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, EM_X86_64,
    };

    /// Build a tiny synthetic ET_REL with one .text section
    /// (alloc | exec, 8 bytes), one local symbol pointing at
    /// offset 0, no relocs. Verifies the loader's section
    /// placement + symbol resolution paths.
    fn build_minimal_rel() -> Vec<u8> {
        // Layout (offsets are file-relative):
        //   [0..0x40)  ELF header
        //   [0x40..0x48) .text bytes (8 bytes of 0x90 NOPs)
        //   [0x48..)   shstrtab + strtab + symtab + sht
        let text = std::vec![0x90u8; 8];
        let shstrtab = b"\0.text\0.shstrtab\0.strtab\0.symtab\0";
        let strtab   = b"\0sym1\0";
        // symtab: 2 entries × 24 bytes = 48 bytes.
        //   [0]: STN_UNDEF (all zero)
        //   [1]: name_off=1 (sym1), value=0, size=0, info=STB_LOCAL|STT_FUNC, shndx=1 (.text)
        let mut symtab = std::vec![0u8; 24];
        // sym1
        symtab.extend_from_slice(&1u32.to_le_bytes());           // st_name
        symtab.push(0x02);                                       // info: STB_LOCAL|STT_FUNC
        symtab.push(0);                                          // other
        symtab.extend_from_slice(&1u16.to_le_bytes());           // shndx
        symtab.extend_from_slice(&0u64.to_le_bytes());           // value
        symtab.extend_from_slice(&0u64.to_le_bytes());           // size

        // Build sections vector: 5 sections (NULL, .text, .shstrtab, .strtab, .symtab)
        // Calculate offsets.
        let text_off = 0x40usize;
        let text_sz  = text.len();
        let shstr_off = text_off + text_sz;
        let shstr_sz  = shstrtab.len();
        let strtab_off = shstr_off + shstr_sz;
        let strtab_sz  = strtab.len();
        let symtab_off = strtab_off + strtab_sz;
        let symtab_sz  = symtab.len();
        let sht_off    = symtab_off + symtab_sz;

        let mut buf = std::vec![0u8; sht_off];
        // ELF header
        buf[0..4].copy_from_slice(&EI_MAG);
        buf[4] = ELFCLASS64;
        buf[5] = ELFDATA2LSB;
        buf[6] = EV_CURRENT;
        buf[7] = 0;  // ELFOSABI_SYSV
        buf[16..18].copy_from_slice(&1u16.to_le_bytes());   // ET_REL
        buf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        buf[0x28..0x30].copy_from_slice(&(sht_off as u64).to_le_bytes());     // e_shoff
        buf[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());                // e_shentsize
        buf[0x3C..0x3E].copy_from_slice(&5u16.to_le_bytes());                 // e_shnum
        buf[0x3E..0x40].copy_from_slice(&2u16.to_le_bytes());                 // e_shstrndx (.shstrtab)
        // Section bytes
        buf[text_off..text_off + text_sz].copy_from_slice(&text);
        buf[shstr_off..shstr_off + shstr_sz].copy_from_slice(shstrtab);
        buf[strtab_off..strtab_off + strtab_sz].copy_from_slice(strtab);
        buf[symtab_off..symtab_off + symtab_sz].copy_from_slice(&symtab);
        // SHT (5 × 64 bytes = 320 bytes)
        let mut sht = std::vec![0u8; 5 * 64];
        // Section [0] NULL — all zero.
        // Section [1] .text — sh_name=1, type=PROGBITS, flags=ALLOC|EXEC, offset=0x40, size=8
        sht[64..68].copy_from_slice(&1u32.to_le_bytes());                    // sh_name=1
        sht[68..72].copy_from_slice(&1u32.to_le_bytes());                    // sh_type=PROGBITS
        sht[72..80].copy_from_slice(&((SHF_ALLOC | 0x4) as u64).to_le_bytes()); // ALLOC|EXEC
        sht[88..96].copy_from_slice(&(text_off as u64).to_le_bytes());       // sh_offset
        sht[96..104].copy_from_slice(&(text_sz as u64).to_le_bytes());       // sh_size
        // Section [2] .shstrtab — sh_name=7
        sht[64*2..64*2+4].copy_from_slice(&7u32.to_le_bytes());
        sht[64*2+4..64*2+8].copy_from_slice(&3u32.to_le_bytes());            // SHT_STRTAB
        sht[64*2+24..64*2+32].copy_from_slice(&(shstr_off as u64).to_le_bytes());
        sht[64*2+32..64*2+40].copy_from_slice(&(shstr_sz as u64).to_le_bytes());
        // Section [3] .strtab — sh_name=17
        sht[64*3..64*3+4].copy_from_slice(&17u32.to_le_bytes());
        sht[64*3+4..64*3+8].copy_from_slice(&3u32.to_le_bytes());
        sht[64*3+24..64*3+32].copy_from_slice(&(strtab_off as u64).to_le_bytes());
        sht[64*3+32..64*3+40].copy_from_slice(&(strtab_sz as u64).to_le_bytes());
        // Section [4] .symtab — sh_name=25
        sht[64*4..64*4+4].copy_from_slice(&25u32.to_le_bytes());
        sht[64*4+4..64*4+8].copy_from_slice(&2u32.to_le_bytes());            // SHT_SYMTAB
        sht[64*4+24..64*4+32].copy_from_slice(&(symtab_off as u64).to_le_bytes());
        sht[64*4+32..64*4+40].copy_from_slice(&(symtab_sz as u64).to_le_bytes());
        sht[64*4+40..64*4+44].copy_from_slice(&3u32.to_le_bytes());          // sh_link → strtab
        sht[64*4+56..64*4+64].copy_from_slice(&24u64.to_le_bytes());          // sh_entsize=24

        buf.extend_from_slice(&sht);
        buf
    }

    struct EmptyResolver;
    impl SymResolver for EmptyResolver {
        fn resolve(&self, _: &str) -> Option<u64> { None }
    }

    #[test]
    fn loads_minimal_rel() {
        let buf = build_minimal_rel();
        let m = load_module(&buf, &EmptyResolver).unwrap();
        assert!(m.sections.iter().any(|s| s.name == ".text"));
        assert_eq!(m.symbols.get("sym1").copied().is_some(), true);
    }

    #[test]
    fn rejects_undefined_symbol() {
        // Build a minimal rel and inject an UNDEF symbol that
        // points at no section. The loader should fail when no
        // resolver entry matches.
        // Simplest: hand it a rel whose symbol shndx==0 (UNDEF).
        // build_minimal_rel doesn't have one; construct manually.
        let mut buf = build_minimal_rel();
        // Mutate symbol's shndx to 0 (UNDEF) at the second symtab
        // entry. symtab off ≈ 0x40 + text + shstr + strtab. Easier:
        // search for the unique shndx=1 byte sequence (st_shndx
        // field at byte 6 of entry). The 2nd entry starts at
        // symtab_off + 24 — hardcoded easier: we know layout.
        // Find the 0x01,0x00 short at offset 6 in the second
        // entry by linear scan.
        let mut found = None;
        for o in (0..buf.len() - 24).rev() {
            if &buf[o + 6..o + 8] == &[1, 0]
                && &buf[o..o + 4] == &1u32.to_le_bytes()  // st_name=1 -> "sym1"
                && buf[o + 4] == 0x02  // info
            {
                found = Some(o);
                break;
            }
        }
        let off = found.expect("locate sym1");
        buf[off + 6] = 0; buf[off + 7] = 0;  // shndx → 0 (UNDEF)
        assert_eq!(load_module(&buf, &EmptyResolver).err().unwrap(), LoadError::UndefinedSymbol);
    }
}
