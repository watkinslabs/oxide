use core::sync::atomic::Ordering;

use super::regs::{
    CTLR_ARE_NS, CTLR_ENGRP0, CTLR_ENGRP1, GICD_CTLR, GICD_IGROUPR, GICD_IIDR, GICD_TYPER, GICD_VA,
    GICR_TYPER, GICR_VA, GICR_WAKER, WAKER_CHILDREN_ASLEEP, WAKER_PROCESSOR_SLEEP,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GicStatus {
    AlreadyOn,
    Enabled { typer: u32, gicd_iidr: u32, gicr_typer_lo: u32 },
}

/// Bring up GICv3: assert ARE_NS + EnableGrp1NS in GICD; wake the
/// per-CPU redistributor; enable the system-register CPU interface
/// (ICC_SRE_EL1, ICC_PMR_EL1, ICC_IGRPEN1_EL1).
///
/// # SAFETY: caller asserts both `gicd_va` and `gicr_va` are
/// freshly Device-attr-mapped; runs single-CPU pre-init, IRQ-off.
/// # C: O(spin until ChildrenAsleep)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn enable(gicd_va: u64, gicr_va: u64) -> GicStatus {
    if GICD_VA.load(Ordering::Acquire) != 0 {
        return GicStatus::AlreadyOn;
    }
    // SAFETY: VAs freshly Device-nGnRnE mapped; single-CPU pre-init; sole writer to GIC state during boot.
    unsafe {
        // 0. Declare every implemented SPI Non-secure Group 1, BEFORE the group
        //    enables go on. On a single-security-state GICv3 the reset group is
        //    Group 0, which is signalled as FIQ — an SPI left at reset never
        //    reaches the IRQ vector at all, however correctly it is enabled,
        //    routed, prioritised and configured afterwards.
        let typer_pre = core::ptr::read_volatile((gicd_va + GICD_TYPER as u64) as *const u32);
        for off in crate::gic_group::spi_igroupr_offsets(typer_pre) {
            core::ptr::write_volatile((gicd_va + GICD_IGROUPR as u64 + off as u64) as *mut u32, u32::MAX);
        }

        // 1. Distributor: ARE_NS=1, both group enables on.
        let gicd_ctlr = (gicd_va + GICD_CTLR as u64) as *mut u32;
        let cur = core::ptr::read_volatile(gicd_ctlr);
        core::ptr::write_volatile(
            gicd_ctlr,
            cur | CTLR_ARE_NS | CTLR_ENGRP0 | CTLR_ENGRP1,
        );

        // 2. Redistributor: clear ProcessorSleep, wait ChildrenAsleep=0.
        let waker = (gicr_va + GICR_WAKER as u64) as *mut u32;
        let w = core::ptr::read_volatile(waker);
        core::ptr::write_volatile(waker, w & !WAKER_PROCESSOR_SLEEP);
        let mut spin = 0u32;
        while core::ptr::read_volatile(waker) & WAKER_CHILDREN_ASLEEP != 0 {
            spin = spin.wrapping_add(1);
            if spin > 1_000_000 { break; }
            core::hint::spin_loop();
        }

        // 3. CPU interface via system registers.
        //    ICC_SRE_EL1.SRE=1: enable sysreg interface.
        //    ICC_PMR_EL1=0xFF: let every priority through.
        //    ICC_IGRPEN1_EL1=1: enable Group 1 NS interrupts.
        // SAFETY: ICC_* sysregs are privileged at EL1; sequence per ARM ARM D7 (GICv3 architecture).
        core::arch::asm!(
            "mrs  x9,  s3_0_c12_c12_5",   // ICC_SRE_EL1
            "orr  x9,  x9,  #1",
            "msr  s3_0_c12_c12_5, x9",
            "isb",
            "mov  x9,  #0xff",
            "msr  s3_0_c4_c6_0,   x9",    // ICC_PMR_EL1
            "mov  x9,  #1",
            "msr  s3_0_c12_c12_7, x9",    // ICC_IGRPEN1_EL1
            "isb",
            out("x9") _,
            options(nostack, preserves_flags),
        );

        let typer         = core::ptr::read_volatile((gicd_va + GICD_TYPER as u64) as *const u32);
        let gicd_iidr     = core::ptr::read_volatile((gicd_va + GICD_IIDR  as u64) as *const u32);
        let gicr_typer_lo = core::ptr::read_volatile((gicr_va + GICR_TYPER as u64) as *const u32);

        GICD_VA.store(gicd_va, Ordering::Release);
        GICR_VA.store(gicr_va, Ordering::Release);

        GicStatus::Enabled { typer, gicd_iidr, gicr_typer_lo }
    }
}

/// GICv3 redistributor stride on QEMU virt: 128 KiB per PE (RD frame at
/// +0, SGI frame at +0x10000). CPU N's frame = base + N·stride.
#[cfg(target_arch = "aarch64")]
pub const GICR_STRIDE: u64 = 0x2_0000;

/// CPU0's redistributor base VA (= the region base), stashed by `enable`.
/// AP redistributor VA = `gicr_base() + cpu_idx * GICR_STRIDE`.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub fn gicr_base() -> u64 { GICR_VA.load(Ordering::Acquire) }

/// SMP AP bring-up of the GICv3 CPU interface (`13§11`): wake THIS PE's
/// redistributor at `ap_gicr_va`, then enable its system-register CPU
/// interface (ICC_SRE/PMR/IGRPEN1). The distributor is global (already
/// up via the BSP's `enable`), so this is the per-PE half only — it does
/// NOT touch GICD or the GICD_VA/GICR_VA stash (those stay the BSP's).
///
/// # SAFETY: caller is an AP at EL1, IRQs masked; `ap_gicr_va` is this
/// PE's redistributor frame, Device-attr mapped by the BSP before CPU_ON.
/// # C: O(spin until ChildrenAsleep)
/// # Ctx: AP bring-up, IRQ-off
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn ap_cpu_interface_enable(ap_gicr_va: u64) {
    // SAFETY: per fn contract; this PE's own redistributor + CPU-interface sysregs.
    unsafe {
        // Wake this PE's redistributor.
        let waker = (ap_gicr_va + GICR_WAKER as u64) as *mut u32;
        let w = core::ptr::read_volatile(waker);
        core::ptr::write_volatile(waker, w & !WAKER_PROCESSOR_SLEEP);
        let mut spin = 0u32;
        while core::ptr::read_volatile(waker) & WAKER_CHILDREN_ASLEEP != 0 {
            spin = spin.wrapping_add(1);
            if spin > 1_000_000 { break; }
            core::hint::spin_loop();
        }
        // CPU interface: ICC_SRE_EL1.SRE=1, ICC_PMR_EL1=0xFF, ICC_IGRPEN1_EL1=1.
        core::arch::asm!(
            "mrs  x9,  s3_0_c12_c12_5",
            "orr  x9,  x9,  #1",
            "msr  s3_0_c12_c12_5, x9",   // ICC_SRE_EL1
            "isb",
            "mov  x9,  #0xff",
            "msr  s3_0_c4_c6_0,   x9",   // ICC_PMR_EL1
            "mov  x9,  #1",
            "msr  s3_0_c12_c12_7, x9",   // ICC_IGRPEN1_EL1
            "isb",
            out("x9") _,
            options(nostack, preserves_flags),
        );
    }
}
