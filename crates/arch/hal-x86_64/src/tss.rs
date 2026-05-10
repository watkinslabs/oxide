// x86_64 64-bit TSS install per Intel SDM Vol. 3 §7.7.
//
// Single static TSS (BSS), referenced by a 16-byte system descriptor
// in the kernel-owned GDT at selector 0x48. `ltr 0x48` loads it.
// Phase 1 sets RSP0 only; IST slots stay zero until the IRQ-on-IST
// stacks land alongside the userspace `iretq` smoke (P1-82).
//
// 64-bit TSS layout (104 B, no IO bitmap):
//   0x00  reserved (4)
//   0x04  RSP0 (8)         ← kernel stack on CPL3→CPL0 transition
//   0x0C  RSP1 (8)
//   0x14  RSP2 (8)
//   0x1C  reserved (8)
//   0x24  IST1..IST7 (7×8)
//   0x5C  reserved (8)
//   0x64  reserved (2)
//   0x66  IO-bitmap base offset (2)  ← 0x68 = past TSS = no bitmap
//
// 16-byte system descriptor at GDT[9..11]:
//   bits 0..15   limit_lo (= 103)
//   bits 16..39  base_lo (24)
//   bits 40..47  access (P|DPL|S=0|TYPE=9)  → 0x89 (avail 64-bit TSS)
//   bits 48..51  limit_hi
//   bits 52..55  flags (G=0 for byte gran)
//   bits 56..63  base_mid (8)
//   bits 64..95  base_hi (32)
//   bits 96..127 reserved zero

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

/// Selector for the kernel TSS in the GDT (offset 0x50, post-P2-02).
pub const TSS_SEL: u16 = 0x50;

/// 64-bit TSS, repr(C, packed) per Intel SDM Vol. 3 Fig. 7-11. The
/// 4-byte misalignment of the RSP fields (offsets 0x04/0x0C/0x14)
/// matches hardware's expected layout.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct Tss64 {
    pub _resv0:  u32,
    pub rsp0:    u64,
    pub rsp1:    u64,
    pub rsp2:    u64,
    pub _resv1:  u64,
    pub ist1:    u64,
    pub ist2:    u64,
    pub ist3:    u64,
    pub ist4:    u64,
    pub ist5:    u64,
    pub ist6:    u64,
    pub ist7:    u64,
    pub _resv2:  u64,
    pub _resv3:  u16,
    pub iomap_base: u16,
}

impl Tss64 {
    /// Empty TSS with iomap_base = sizeof(Tss64) (= no IO bitmap).
    /// # C: O(1)
    pub const fn empty() -> Self {
        Self {
            _resv0: 0,
            rsp0: 0, rsp1: 0, rsp2: 0,
            _resv1: 0,
            ist1: 0, ist2: 0, ist3: 0, ist4: 0,
            ist5: 0, ist6: 0, ist7: 0,
            _resv2: 0,
            _resv3: 0,
            iomap_base: core::mem::size_of::<Tss64>() as u16,
        }
    }
}

#[repr(C, align(16))]
struct TssCell(UnsafeCell<Tss64>);

// SAFETY: cross-thread mutation mediated by single-threaded boot
// install + later `set_rsp0` writes which are u64-aligned and atomic
// from the CPU's perspective. The CPU itself reads RSP0 on CPL3→CPL0
// transition (rare; serialized by the transition itself).
unsafe impl Sync for TssCell {}

static TSS: TssCell = TssCell(UnsafeCell::new(Tss64::empty()));

/// Cached base address of the TSS, exposed to GDT install so it can
/// stamp the descriptor's split base fields. Set on first call to
/// `tss_base_addr()`; same on every subsequent boot iteration.
static TSS_BASE: AtomicU64 = AtomicU64::new(0);

/// Linear address of the kernel-wide TSS. Used by `gdt::write_tss_descriptor`.
/// # C: O(1)
pub fn tss_base_addr() -> u64 {
    let cached = TSS_BASE.load(Ordering::Relaxed);
    if cached != 0 { return cached; }
    let base = TSS.0.get() as u64;
    TSS_BASE.store(base, Ordering::Relaxed);
    base
}

/// Update RSP0 (kernel stack pointer used on ring3→ring0 transition).
/// Called by per-task switch-in once the userspace path lands.
/// # SAFETY: caller asserts `rsp0` is the high end of a writable
/// kernel stack belonging to the about-to-run task; runs on the
/// owning CPU (single-CPU v1).
/// # C: O(1)
/// # Ctx: process|context-switch path
pub unsafe fn set_rsp0(rsp0: u64) {
    // SAFETY: TSS is a single-CPU shared static; per fn contract, the
    // caller serialises calls (context-switch path holds preempt off).
    // The 8-byte RSP0 store is a single mov; the CPU only re-reads
    // on CPL3→CPL0, which is far in the future relative to this write.
    let tss = unsafe { &mut *TSS.0.get() };
    tss.rsp0 = rsp0;
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",
    ".globl oxide_load_tr",
    ".type  oxide_load_tr, @function",
    // di = TSS selector. Loads TR; CPU marks the descriptor's TYPE
    // = busy 64-bit TSS (0xB) on success.
    "oxide_load_tr:",
    "    ltr di",
    "    ret",
    ".size oxide_load_tr, . - oxide_load_tr",
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_load_tr(sel: u16);
}

/// Load the task register with `TSS_SEL`. Pre-condition: GDT is the
/// kernel-owned one (`gdt::install_kernel_gdt` ran), TSS descriptor
/// at `TSS_SEL` is present and TYPE=0x9 (available, not busy).
///
/// # SAFETY: caller is the boot path; runs single-CPU with IRQs
/// masked. Once-per-boot (re-loading the same selector marks it busy
/// then reload would #GP).
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn install_tss() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: oxide_load_tr is a single `ltr` instruction; legal
        // at CPL=0 with the GDT descriptor at TSS_SEL satisfying
        // TYPE=0x9 (the GDT install populates it that way).
        unsafe { oxide_load_tr(TSS_SEL); }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { /* host: no-op */ }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tss_size_is_104() {
        // SDM Vol. 3 §7.7: 64-bit TSS = 104 bytes (no IO bitmap).
        assert_eq!(core::mem::size_of::<Tss64>(), 104);
    }

    #[test]
    fn tss_field_offsets() {
        // SDM Vol. 3 Fig. 7-11; layout is hardware-fixed.
        assert_eq!(core::mem::offset_of!(Tss64, rsp0), 0x04);
        assert_eq!(core::mem::offset_of!(Tss64, rsp1), 0x0C);
        assert_eq!(core::mem::offset_of!(Tss64, rsp2), 0x14);
        assert_eq!(core::mem::offset_of!(Tss64, ist1), 0x24);
        assert_eq!(core::mem::offset_of!(Tss64, ist7), 0x24 + 6 * 8);
        assert_eq!(core::mem::offset_of!(Tss64, iomap_base), 0x66);
    }

    #[test]
    fn empty_tss_iomap_base_is_size() {
        // iomap_base == sizeof(TSS) ⇒ no IO bitmap (Intel SDM 19.5.2).
        let t = Tss64::empty();
        assert_eq!(t.iomap_base as usize, core::mem::size_of::<Tss64>());
    }

    #[test]
    fn tss_sel_is_0x50() {
        // P2-02 moved TSS to sel 0x50 to make room for the
        // user CS32/DS/CS64 sysret triple at 0x38/0x40/0x48.
        assert_eq!(TSS_SEL, 0x50);
    }

    #[test]
    fn tss_base_addr_stable() {
        let a = tss_base_addr();
        let b = tss_base_addr();
        assert_eq!(a, b, "TSS base is a static; must be stable across calls");
        assert_ne!(a, 0, "must point at the actual TSS static");
    }

    #[test]
    fn set_rsp0_round_trip() {
        // SAFETY: hosted test entry; single-threaded with no concurrent writers; defers to set_rsp0 whose contract requires single-CPU serialisation.
        unsafe { set_rsp0(0xDEAD_BEEF_CAFE_BABE); }
        // SAFETY: hosted test; only this thread accesses TSS, so a raw read of the UnsafeCell payload races nothing.
        let read = unsafe { (*TSS.0.get()).rsp0 };
        assert_eq!(read, 0xDEAD_BEEF_CAFE_BABE);
        // SAFETY: hosted test reset; same single-thread justification as the prior set_rsp0 call above.
        unsafe { set_rsp0(0); }
    }

    #[test]
    fn install_tss_compiles_on_host() {
        // SAFETY: hosted; the asm path is cfg'd out so this exercises
        // only the no-op fallback.
        unsafe { install_tss() };
    }
}
