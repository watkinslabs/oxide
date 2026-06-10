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

// SAFETY: each CPU mutates only its OWN slot (`TSS[current_cpu()]`) via
// `set_rsp0`; the 8-byte RSP0 store is a single mov, and the CPU re-reads
// RSP0 only on its own CPL3→CPL0 transition (serialized by the transition).
// No cross-CPU sharing of a slot, so no data race.
unsafe impl Sync for TssCell {}

/// Per-CPU TSS count. Matches `cpu::MAX_CPUS` (64): one TSS per possible
/// CPU so each AP scheduling user tasks has its own RSP0 (a shared TSS
/// would clobber across CPUs on every switch). GDT carries one 16-byte
/// TSS descriptor per slot at selector `TSS_SEL + cpu*0x10`.
pub const NR_TSS: usize = 64;

/// Per-CPU TSS array. CPU `i` uses `TSS[i]`, loaded via `ltr(TSS_SEL +
/// i*0x10)` and updated via `set_rsp0` (indexed by `current_cpu()`).
static TSS: [TssCell; NR_TSS] =
    [const { TssCell(UnsafeCell::new(Tss64::empty())) }; NR_TSS];

/// Linear address of CPU `cpu`'s TSS. Used by `gdt::install_kernel_gdt`
/// to stamp the per-CPU TSS descriptors' split base fields.
/// # C: O(1)
pub fn tss_base_addr(cpu: usize) -> u64 {
    TSS[cpu.min(NR_TSS - 1)].0.get() as u64
}

/// Update THIS CPU's RSP0 (kernel stack used on ring3→ring0 transition).
/// Called by the context-switch path (per-task kernel stack). Indexes the
/// per-CPU TSS by `current_cpu()` so an AP never clobbers the BSP's RSP0.
/// # SAFETY: caller asserts `rsp0` is the high end of a writable kernel
/// stack belonging to the about-to-run task on THIS CPU; runs preempt-off
/// on the owning CPU.
/// # C: O(1)
/// # Ctx: process|context-switch path
pub unsafe fn set_rsp0(rsp0: u64) {
    use hal::CpuOps;
    let cpu = (crate::X86CpuOps::current_cpu() as usize).min(NR_TSS - 1);
    // SAFETY: this CPU is the sole writer of its own slot; single mov store.
    let tss = unsafe { &mut *TSS[cpu].0.get() };
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
    // Boot CPU is always cpu 0 here, and this runs in EARLY boot
    // (boot-x86_64 GDT/TSS install) BEFORE `set_percpu_base` sets gs — so
    // it must NOT read `current_cpu()` (gs:0 would be garbage → wrong
    // selector → bad TSS → first user task's ring3→ring0 wedges). The
    // BSP's TSS is slot 0 → `TSS_SEL` (0x50). An AP loads its own via
    // `install_tss_for_cpu` after its gs is established.
    // SAFETY: ltr 0x50 with the GDT slot-0 descriptor TYPE=0x9 (avail).
    unsafe { install_tss_for_cpu(0); }
}

/// Load CPU `cpu`'s task register with its own per-CPU TSS selector
/// (`TSS_SEL + cpu*0x10`). Called from AP bring-up AFTER the AP's gs /
/// per-CPU area is established. Each CPU ltr's a DISTINCT descriptor, so
/// the busy bit is per-descriptor (no cross-CPU #GP on the same selector).
/// # SAFETY: caller is the owning CPU's bring-up, CPL=0, IRQs masked; the
/// GDT descriptor at `TSS_SEL + cpu*0x10` is present + TYPE=0x9 (available).
/// # C: O(1)
pub unsafe fn install_tss_for_cpu(cpu: u16) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let sel = TSS_SEL + cpu * 0x10;
        // SAFETY: single `ltr`; legal at CPL=0; descriptor available per fn contract.
        unsafe { oxide_load_tr(sel); }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = cpu; }
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
        let a = tss_base_addr(0);
        let b = tss_base_addr(0);
        assert_eq!(a, b, "TSS base is a static; must be stable across calls");
        assert_ne!(a, 0, "must point at the actual TSS static");
        // Distinct CPUs get distinct TSS slots (per-CPU RSP0, no clobber).
        assert_ne!(tss_base_addr(0), tss_base_addr(1), "per-CPU TSS slots distinct");
    }

    #[test]
    fn set_rsp0_round_trip() {
        // On host, current_cpu() == 0, so set_rsp0 writes TSS[0].
        // SAFETY: hosted test entry; single-threaded with no concurrent writers; defers to set_rsp0 whose contract requires single-CPU serialisation.
        unsafe { set_rsp0(0xDEAD_BEEF_CAFE_BABE); }
        // SAFETY: hosted test; only this thread accesses TSS, so a raw read of the UnsafeCell payload races nothing.
        let read = unsafe { (*TSS[0].0.get()).rsp0 };
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
