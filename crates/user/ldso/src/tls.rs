// Thread-Local Storage layout (docs/59§5, docs/54). Each module with a
// PT_TLS contributes an initialization image (filesz init bytes + zeroed tail
// to memsz, `align`). The rtld lays these out into a static TLS block per
// thread and builds a DTV (dynamic thread vector) so __tls_get_addr and the
// TLS relocs (DTPMOD/DTPOFF/TPOFF) resolve a (module, offset) to an address.
//
// Two ABI variants (docs/54):
//   Variant II (x86_64): TLS sits BELOW the thread pointer; tp points at the
//     TCB; module blocks are at NEGATIVE tp offsets.
//   Variant I (aarch64): TLS sits ABOVE the thread pointer after a 2-word TCB
//     reserve; module blocks are at POSITIVE tp offsets.
// The per-module tp offset math is pure + hosted-tested for both variants;
// allocating the block + DTV and setting tp is freestanding (G12g, when a
// TLS-using binary runs through the rtld).
use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Variant { One, Two }

/// This target's TLS variant.
/// # C: aarch64 → Variant I, x86_64 → Variant II
pub const fn target_variant() -> Variant {
    #[cfg(target_arch = "aarch64")]
    { Variant::One }
    #[cfg(not(target_arch = "aarch64"))]
    { Variant::Two }
}

/// Variant I reserves 2 words (the TCB head) before the first module block.
pub const TCB_RESERVE: u64 = 16;

#[inline]
fn round_up(x: u64, a: u64) -> u64 { let a = a.max(1); (x + a - 1) & !(a - 1) }

/// Compute each module's signed tp offset (the address to add to the thread
/// pointer to reach the module's TLS block base) and the total block size.
/// Input: per-module (memsz, align), in link order (module id = index + 1).
///
/// # C: per-module tp offset (II negative / I positive) + total block size
pub fn layout(modules: &[(u64, u64)], v: Variant) -> (Vec<i64>, u64) {
    let mut offs = Vec::with_capacity(modules.len());
    match v {
        Variant::Two => {
            // blocks grow downward from tp; tp_offset = -(distance below tp).
            let mut acc = 0u64;
            for &(memsz, align) in modules {
                acc = round_up(acc + memsz, align);
                offs.push(-(acc as i64));
            }
            (offs, acc)
        }
        Variant::One => {
            // blocks grow upward from tp after the TCB reserve.
            let mut acc = TCB_RESERVE;
            let mut maxa = 1u64;
            for &(memsz, align) in modules {
                acc = round_up(acc, align);
                offs.push(acc as i64);
                acc += memsz;
                maxa = maxa.max(align);
            }
            (offs, round_up(acc, maxa))
        }
    }
}

/// TPOFF reloc value: the symbol's offset relative to the thread pointer.
/// `module_tp_offset` is from `layout`; sign already encodes the variant.
/// # C: module_tp_offset + sym_value
pub fn tpoff(module_tp_offset: i64, sym_value: u64) -> i64 {
    module_tp_offset.wrapping_add(sym_value as i64)
}

/// DTPOFF reloc value: offset within the module's own TLS block.
/// # C: sym_value + addend
pub fn dtpoff(sym_value: u64, addend: i64) -> u64 {
    sym_value.wrapping_add(addend as u64)
}

#[cfg(feature = "freestanding")]
pub use imp::tls_get_addr;

#[cfg(feature = "freestanding")]
mod imp {
    // __tls_get_addr takes a pointer to a {module_id, offset} pair (the GOT
    // TLS descriptor) and returns the runtime address of that TLS datum:
    // dtv[module_id] + offset. The DTV pointer is at the first word of the
    // thread pointer (variant I) / the second word of the TCB (variant II); allocation +
    // population happens when the link map's TLS image is instantiated (G12g).
    #[repr(C)]
    pub struct TlsIndex { pub module: u64, pub offset: u64 }

    /// # C: void *__tls_get_addr(tls_index *ti) = dtv[ti->module] + ti->offset
    #[no_mangle]
    pub unsafe extern "C" fn tls_get_addr(ti: *const TlsIndex) -> *mut u8 {
        // SAFETY: ti points at a GOT TLS descriptor; the DTV is read from the
        // thread pointer. Until G12g instantiates a real DTV this returns the
        // descriptor's offset against a null DTV slot (single-TLS-module path
        // uses TPOFF, not this) — wired fully with the link-map TLS image.
        unsafe {
            let dtv = current_dtv();
            if dtv.is_null() { return (*ti).offset as *mut u8; }
            let block = *dtv.add((*ti).module as usize);
            (block as *mut u8).add((*ti).offset as usize)
        }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn current_dtv() -> *const usize {
        // SAFETY: x86_64 variant II stores the DTV at fs:8 in the glibc TCB
        // head; fs:0 and fs:16 are the TCB/self pointers.
        unsafe { let p: usize; core::arch::asm!("mov {}, fs:8", out(reg) p); p as *const usize }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe fn current_dtv() -> *const usize {
        // SAFETY: on variant I the DTV pointer is the first word at the thread
        // pointer (tpidr_el0).
        unsafe { let p: usize; core::arch::asm!("mrs {}, tpidr_el0", out(reg) p); (p as *const *const usize).read() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_two_negative_offsets() {
        // two modules: exe (memsz 0x30, align 0x10), lib (memsz 0x18, align 0x8)
        let (offs, total) = layout(&[(0x30, 0x10), (0x18, 0x8)], Variant::Two);
        // exe: acc = round_up(0x30,0x10)=0x30 → -0x30
        // lib: acc = round_up(0x30+0x18,0x8)=0x48 → -0x48
        assert_eq!(offs, std::vec![-0x30, -0x48]);
        assert_eq!(total, 0x48);
        // a var at sym 0x8 in the exe lives at fs:(-0x30+0x8) = fs:-0x28
        assert_eq!(tpoff(offs[0], 0x8), -0x28);
    }

    #[test]
    fn variant_one_positive_offsets() {
        let (offs, total) = layout(&[(0x30, 0x10), (0x18, 0x8)], Variant::One);
        // exe: acc=round_up(16,0x10)=16 → +16 ; then acc=16+0x30=0x40
        // lib: acc=round_up(0x40,0x8)=0x40 → +0x40 ; then acc=0x40+0x18=0x58
        assert_eq!(offs, std::vec![16, 0x40]);
        assert_eq!(total, round_up_pub(0x58, 0x10));
        assert_eq!(tpoff(offs[1], 0x4), 0x44);
    }

    #[test]
    fn dtpoff_is_within_module() {
        assert_eq!(dtpoff(0x10, 0x4), 0x14);
    }

    fn round_up_pub(x: u64, a: u64) -> u64 { (x + a - 1) & !(a - 1) }
}
