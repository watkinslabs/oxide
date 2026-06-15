// Self-relocation bootstrap (docs/59§5, docs/31§5). Before the rtld can
// call any non-inlined function it must relocate itself: walk its own
// `_DYNAMIC`, and for every R_*_RELATIVE entry write `base + addend` into
// the slot at `base + offset`. RELATIVE is the only reloc type that needs
// no symbol lookup, so it is the only one applicable pre-bootstrap. Other
// reloc types are handled by the full loader (G12c) once an allocator and
// the link map exist.
use crate::dynamic::{self, Dyn};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_AARCH64_RELATIVE: u32 = 1027;

/// # C: low 32 bits of r_info — the relocation type
#[inline]
pub fn r_type(info: u64) -> u32 { (info & 0xffff_ffff) as u32 }
/// # C: high 32 bits of r_info — the symbol table index
#[inline]
pub fn r_sym(info: u64) -> u32 { (info >> 32) as u32 }
/// # C: true for the arch's RELATIVE reloc (base + addend, no symbol)
#[inline]
pub fn is_relative(t: u32) -> bool { t == R_X86_64_RELATIVE || t == R_AARCH64_RELATIVE }

/// Apply `count` RELATIVE relocations from the table at `rela` to the image
/// loaded at `base`. Non-RELATIVE entries are skipped (handled later).
///
/// # C: for each RELATIVE e: *(base+e.r_offset) = base + e.r_addend
pub unsafe fn relocate_relative(base: u64, rela: *const Rela, count: usize) {
    // SAFETY: caller guarantees [rela, rela+count) is a valid Rela array in
    // the loaded image and that every RELATIVE slot (base + r_offset) is an
    // aligned, writable 8-byte word inside a PT_LOAD segment.
    unsafe {
        let mut i = 0;
        while i < count {
            let e = &*rela.add(i);
            if is_relative(r_type(e.r_info)) {
                let slot = base.wrapping_add(e.r_offset) as *mut u64;
                slot.write(base.wrapping_add(e.r_addend as u64));
            }
            i += 1;
        }
    }
}

/// Self-relocate the rtld: parse its own `_DYNAMIC` for DT_RELA/RELASZ/
/// RELAENT and apply all RELATIVE entries against `base`.
///
/// # C: relocate_relative over the rtld's own DT_RELA table
pub unsafe fn relocate_self(base: u64, dynv: *const Dyn) {
    // SAFETY: dynv points at the rtld's `_DYNAMIC` array (NUL-tag
    // terminated); the DT_RELA table it names lives at base+rela and is a
    // valid Rela array per the ELF the linker produced.
    unsafe {
        let info = parse_dynv(dynv);
        if let Some(rela) = info.rela {
            if info.relasz != 0 {
                let ent = if info.relaent != 0 { info.relaent } else { 24 };
                let ptr = base.wrapping_add(rela) as *const Rela;
                let count = (info.relasz / ent) as usize;
                relocate_relative(base, ptr, count);
            }
        }
    }
}

/// Walk a NUL-terminated `_DYNAMIC` array via raw pointer (no slice/std) and
/// extract the bootstrap tags. Used by relocate_self before any allocator.
unsafe fn parse_dynv(dynv: *const Dyn) -> dynamic::DynInfo {
    // SAFETY: dynv is a DT_NULL-terminated _DYNAMIC array; we read entries
    // sequentially until the terminator, staying within the array.
    unsafe {
        let mut rela = None;
        let mut relasz = 0u64;
        let mut relaent = 24u64;
        let mut p = dynv;
        loop {
            let d = &*p;
            match d.d_tag {
                dynamic::DT_NULL => break,
                dynamic::DT_RELA => rela = Some(d.d_val),
                dynamic::DT_RELASZ => relasz = d.d_val,
                dynamic::DT_RELAENT => relaent = d.d_val,
                _ => {}
            }
            p = p.add(1);
        }
        dynamic::DynInfo { rela, relasz, relaent, ..dynamic::DynInfo::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::{Dyn, DT_NULL, DT_RELA, DT_RELAENT, DT_RELASZ};

    #[test]
    fn type_sym_split() {
        let info = ((5u64) << 32) | (R_X86_64_RELATIVE as u64);
        assert_eq!(r_type(info), R_X86_64_RELATIVE);
        assert_eq!(r_sym(info), 5);
        assert!(is_relative(r_type(info)));
        assert!(!is_relative(1)); // R_X86_64_64 is not RELATIVE
    }

    // Exercise the real apply path against an in-process image buffer: lay
    // out a _DYNAMIC + RELA table + target slots inside one allocation, use
    // its address as the load base, run relocate_self, and check each slot
    // received base + addend. This verifies the pointer arithmetic and the
    // 8-byte writes, not just the helpers.
    #[test]
    fn relocate_self_applies_relative() {
        // 4 KiB image. Layout (offsets):
        //   0x000.. : 8 target slots (64 bytes)
        //   0x100.. : RELA table (3 entries: 2 RELATIVE, 1 non-RELATIVE)
        //   0x200.. : _DYNAMIC
        let mut img = std::vec![0u8; 4096];
        let base = img.as_ptr() as u64;

        let rela_off = 0x100u64;
        let dyn_off = 0x200u64;
        let entries = [
            Rela { r_offset: 0x00, r_info: R_X86_64_RELATIVE as u64, r_addend: 0x111 },
            Rela { r_offset: 0x08, r_info: ((3u64) << 32) | 1 /* R_X86_64_64, skipped */, r_addend: 0x999 },
            Rela { r_offset: 0x10, r_info: R_AARCH64_RELATIVE as u64, r_addend: 0x222 },
        ];
        // write RELA entries
        for (i, e) in entries.iter().enumerate() {
            let o = rela_off as usize + i * 24;
            img[o..o + 8].copy_from_slice(&e.r_offset.to_le_bytes());
            img[o + 8..o + 16].copy_from_slice(&e.r_info.to_le_bytes());
            img[o + 16..o + 24].copy_from_slice(&e.r_addend.to_le_bytes());
        }
        // write _DYNAMIC
        let dynv = [
            Dyn { d_tag: DT_RELA, d_val: rela_off },
            Dyn { d_tag: DT_RELASZ, d_val: 24 * 3 },
            Dyn { d_tag: DT_RELAENT, d_val: 24 },
            Dyn { d_tag: DT_NULL, d_val: 0 },
        ];
        for (i, d) in dynv.iter().enumerate() {
            let o = dyn_off as usize + i * 16;
            img[o..o + 8].copy_from_slice(&d.d_tag.to_le_bytes());
            img[o + 8..o + 16].copy_from_slice(&d.d_val.to_le_bytes());
        }

        // SAFETY: dynv lives at base+dyn_off inside img; the RELA table and
        // every target slot are inside the same live 4 KiB allocation.
        unsafe { relocate_self(base, base.wrapping_add(dyn_off) as *const Dyn) };

        let slot = |o: usize| u64::from_le_bytes(img[o..o + 8].try_into().unwrap());
        assert_eq!(slot(0x00), base.wrapping_add(0x111)); // RELATIVE applied
        assert_eq!(slot(0x08), 0); // non-RELATIVE skipped
        assert_eq!(slot(0x10), base.wrapping_add(0x222)); // aarch64 RELATIVE applied
    }
}
