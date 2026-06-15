// In-place relocation over real mappings (docs/59§5). Unlike `crate::dl`
// (which relocates into Vec buffers for hosted testing), this applies relocs
// directly to the mmap'd segments at their runtime addresses, resolving
// symbols through the global link-map scope. Reloc *classification* and the
// value arithmetic are pure + hosted-tested; the memory writes + IFUNC/COPY
// side effects are freestanding.
#[cfg(feature = "freestanding")]
use crate::reloc::Rela;

// x86_64 reloc types
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_IRELATIVE: u32 = 37;
pub const R_X86_64_DTPMOD64: u32 = 16;
pub const R_X86_64_DTPOFF64: u32 = 17;
pub const R_X86_64_TPOFF64: u32 = 18;
// aarch64 reloc types
pub const R_AARCH64_ABS64: u32 = 257;
pub const R_AARCH64_TLS_DTPMOD: u32 = 1028;
pub const R_AARCH64_TLS_DTPREL: u32 = 1029;
pub const R_AARCH64_TLS_TPREL: u32 = 1030;
pub const R_AARCH64_COPY: u32 = 1024;
pub const R_AARCH64_GLOB_DAT: u32 = 1025;
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
pub const R_AARCH64_RELATIVE: u32 = 1027;
pub const R_AARCH64_IRELATIVE: u32 = 1032;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    Relative,  // B + A (no symbol)
    Sym,       // S + A (GLOB_DAT / JUMP_SLOT / ABS64)
    Irelative, // (B + A)() resolver
    Copy,      // memcpy(slot, S, symsize)
    Tls,       // deferred to G12f
    Unsupported,
}

/// Classify a relocation type into an arch-independent kind.
/// # C: r_type → Kind (x86_64 + aarch64)
pub fn classify(r_type: u32) -> Kind {
    match r_type {
        R_X86_64_RELATIVE | R_AARCH64_RELATIVE => Kind::Relative,
        R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT | R_X86_64_64
        | R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT | R_AARCH64_ABS64 => Kind::Sym,
        R_X86_64_IRELATIVE | R_AARCH64_IRELATIVE => Kind::Irelative,
        R_X86_64_COPY | R_AARCH64_COPY => Kind::Copy,
        // TLS types (16/17/18, 1028/1029/1030) handled in G12f.
        16 | 17 | 18 | 1028 | 1029 | 1030 => Kind::Tls,
        _ => Kind::Unsupported,
    }
}

/// The 8-byte value to store for a non-side-effecting reloc. `base` is the
/// object load bias, `sym` the resolved symbol address (0 if none), `addend`
/// the RELA addend. None for kinds that aren't a plain 64-bit store.
///
/// # C: Relative→B+A, Sym→S+A
pub fn value_for(kind: Kind, base: u64, sym: u64, addend: i64) -> Option<u64> {
    match kind {
        Kind::Relative => Some(base.wrapping_add(addend as u64)),
        Kind::Sym => Some(sym.wrapping_add(addend as u64)),
        _ => None,
    }
}

#[cfg(feature = "freestanding")]
pub use imp::{apply, RelocCtx};

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::reloc::{r_sym, r_type};
    use crate::symbol::{SymView, STB_WEAK};

    /// Everything the applier needs about the object being relocated.
    /// `tls_offset` is this object's TLS module's tp offset (from
    /// tls::layout); 0 if the object has no PT_TLS. `tls_modid` is its
    /// 1-based TLS module id (for DTPMOD).
    pub struct RelocCtx<'a> {
        pub base: u64,
        pub sym: SymView<'a>,
        pub tls_offset: i64,
        pub tls_modid: u64,
    }

    /// Resolve symbol index `idx` to a runtime address: try the global scope
    /// by name first (interposition), then a local definition, then 0 for a
    /// weak undefined. None = unresolved strong symbol (link error).
    fn sym_addr<R: Fn(&[u8]) -> Option<u64>>(ctx: &RelocCtx, idx: u32, resolve: &R) -> Option<u64> {
        if idx == 0 { return Some(0); }
        let name = ctx.sym.name(idx)?;
        if let Some(a) = resolve(name) { return Some(a); }
        if ctx.sym.is_defined(idx) { return Some(ctx.base.wrapping_add(ctx.sym.value(idx)?)); }
        if ctx.sym.binding(idx) == Some(STB_WEAK) { return Some(0); }
        None
    }

    /// Apply `count` RELA entries in place. `resolve(name)->addr` is the
    /// global link-map lookup. Returns Err(reloc index) on an unresolved
    /// strong symbol or unsupported type.
    ///
    /// # C: apply each RELA to base+r_offset, symbols via global resolve
    pub unsafe fn apply<R: Fn(&[u8]) -> Option<u64>>(
        ctx: &RelocCtx, rela: *const Rela, count: usize, resolve: &R,
    ) -> Result<(), usize> {
        // SAFETY: [rela, rela+count) is a valid RELA array in the object's
        // mapping; each slot base+r_offset is a writable word in a PT_LOAD.
        unsafe {
            let mut i = 0;
            while i < count {
                let e = &*rela.add(i);
                let kind = classify(r_type(e.r_info));
                let slot = ctx.base.wrapping_add(e.r_offset);
                match kind {
                    Kind::Relative => {
                        (slot as *mut u64).write(ctx.base.wrapping_add(e.r_addend as u64));
                    }
                    Kind::Sym => {
                        let s = sym_addr(ctx, r_sym(e.r_info), resolve).ok_or(i)?;
                        (slot as *mut u64).write(s.wrapping_add(e.r_addend as u64));
                    }
                    Kind::Irelative => {
                        let resolver = ctx.base.wrapping_add(e.r_addend as u64);
                        let f: extern "C" fn() -> u64 = core::mem::transmute(resolver);
                        (slot as *mut u64).write(f());
                    }
                    Kind::Copy => {
                        // memcpy symsize bytes from the resolved symbol to slot.
                        let idx = r_sym(e.r_info);
                        let src = sym_addr(ctx, idx, resolve).ok_or(i)?;
                        let size = sym_size(ctx, idx);
                        core::ptr::copy_nonoverlapping(src as *const u8, slot as *mut u8, size);
                    }
                    Kind::Tls => {
                        // TLS symbol value = offset within its module's TLS
                        // block (st_value); local def for same-object refs.
                        let idx = r_sym(e.r_info);
                        let sv = if idx == 0 { 0 } else { ctx.sym.value(idx).unwrap_or(0) };
                        let t = r_type(e.r_info);
                        let val: u64 = match t {
                            R_X86_64_DTPMOD64 | R_AARCH64_TLS_DTPMOD => ctx.tls_modid,
                            R_X86_64_DTPOFF64 | R_AARCH64_TLS_DTPREL => crate::tls::dtpoff(sv, e.r_addend),
                            R_X86_64_TPOFF64 | R_AARCH64_TLS_TPREL =>
                                crate::tls::tpoff(ctx.tls_offset, sv).wrapping_add(e.r_addend) as u64,
                            _ => { i += 1; continue; }
                        };
                        (slot as *mut u64).write(val);
                    }
                    Kind::Unsupported => return Err(i),
                }
                i += 1;
            }
            Ok(())
        }
    }

    fn sym_size(ctx: &RelocCtx, idx: u32) -> usize {
        // st_size @16 of the Elf64_Sym; 0 if out of range. Safe slice read.
        let base = (idx as usize) * crate::symbol::SYMENT + 16;
        ctx.sym.symtab.get(base..base + 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()) as usize)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_both_arches() {
        assert_eq!(classify(R_X86_64_RELATIVE), Kind::Relative);
        assert_eq!(classify(R_AARCH64_RELATIVE), Kind::Relative);
        assert_eq!(classify(R_X86_64_GLOB_DAT), Kind::Sym);
        assert_eq!(classify(R_X86_64_JUMP_SLOT), Kind::Sym);
        assert_eq!(classify(R_AARCH64_ABS64), Kind::Sym);
        assert_eq!(classify(R_X86_64_IRELATIVE), Kind::Irelative);
        assert_eq!(classify(R_AARCH64_COPY), Kind::Copy);
        assert_eq!(classify(18), Kind::Tls);
        assert_eq!(classify(0xdead), Kind::Unsupported);
    }

    #[test]
    fn value_arithmetic() {
        assert_eq!(value_for(Kind::Relative, 0x1000, 0, 0x24), Some(0x1024));
        assert_eq!(value_for(Kind::Sym, 0x1000, 0x5000, 0x8), Some(0x5008));
        assert_eq!(value_for(Kind::Irelative, 0x1000, 0, 0), None);
        assert_eq!(value_for(Kind::Copy, 0x1000, 0, 0), None);
    }
}
