// aarch64 SMP AP per-CPU bring-up (`13§11`). The arm AP entry (`ap_main`)
// lives in the leaf `hal-aarch64` crate, which can't depend on `sched` /
// `arch_irq`; this kernel-side hook does the parts that need them. It
// runs ON the AP (called from `ap_main` after VBAR is set): maps + wakes
// the AP's own GICv3 redistributor, enables the resched SGI + CPU
// interface, and installs the AP's per-CPU runqueue. Installed at boot
// via `hal_aarch64::smp::set_ap_init_hook`.

#![cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
use hal_aarch64::mmu_ops::ArmMmu;

fn device_flags() -> PageFlags {
    PageFlags::READ | PageFlags::WRITE | PageFlags::NO_CACHE | PageFlags::WRITE_THROUGH
}

/// Per-AP GIC + runqueue bring-up. `aff0` is the AP's affinity-0 id
/// (== redistributor index on QEMU virt). Derives the AP's redistributor
/// from CPU0's base (`gic::gicr_base()`; VA low-32 == PA), maps its RD +
/// SGI frames, wakes the CPU interface, enables the resched SGI, then
/// installs this CPU's runqueue.
/// # SAFETY: runs on the target AP at EL1, IRQs masked, VBAR installed;
/// sole writer of its own per-CPU GIC + runqueue state. Shared page
/// tables (TTBR1) tolerate the device map (own TLB flushed by `map`).
/// # C: O(map depth) + O(spin until ChildrenAsleep)
pub unsafe fn ap_init(aff0: u32) {
    let base_va = arch_irq::gic::gicr_base();
    if base_va == 0 { return; } // GIC not up (shouldn't happen post-boot)
    let stride = arch_irq::gic::GICR_STRIDE;
    let ap_va = base_va + aff0 as u64 * stride;
    let ap_pa = (base_va & 0xFFFF_FFFF) + aff0 as u64 * stride;
    // SAFETY: ap_va/ap_pa name this PE's redistributor frames (RD at +0,
    // SGI at +0x10000); Device-attr map into the shared kernel half; then
    // the GIC helpers operate on this PE's own frame + sysregs.
    unsafe {
        <ArmMmu as MmuOps>::map(Va(ap_va), Pa(ap_pa), device_flags(), PageSize::P4K);
        <ArmMmu as MmuOps>::map(Va(ap_va + 0x1_0000), Pa(ap_pa + 0x1_0000), device_flags(), PageSize::P4K);
        arch_irq::gic::ap_cpu_interface_enable(ap_va);
        arch_irq::gic::enable_sgi_on(ap_va, arch_irq::gic::RESCHED_SGI);
        sched::live::install_default_runqueue();
    }
}

/// Install the AP-init hook + the arm resched-IPI sender. Boot path,
/// before `bring_up_aps_arm`.
/// # C: O(1)
pub fn install_hooks() {
    hal_aarch64::smp::set_ap_init_hook(ap_init);
    sched::live::set_send_resched_ipi_hook(arch_irq::gic::send_resched_ipi);
}
