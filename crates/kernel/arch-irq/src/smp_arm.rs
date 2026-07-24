// aarch64 SMP AP per-CPU bring-up (`13§11`), the arm peer of `smp_x86`.
// The low-level AP entry (`ap_main`) lives in `hal-aarch64`; this module
// does the per-AP GIC + runqueue parts that need `sched` + the GIC driver. It
// runs ON the AP (called from `ap_main` after VBAR is set): maps + wakes
// the AP's own GICv3 redistributor, enables the resched SGI + CPU
// interface, and installs the AP's per-CPU runqueue. Installed at boot
// via `hal_aarch64::smp::set_ap_init_hook`.


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
    let base_va = crate::gic::gicr_base();
    if base_va == 0 { return; } // GIC not up (shouldn't happen post-boot)
    let stride = crate::gic::GICR_STRIDE;
    let ap_va = base_va + aff0 as u64 * stride;
    let ap_pa = (base_va & 0xFFFF_FFFF) + aff0 as u64 * stride;
    // SAFETY: ap_va/ap_pa name this PE's redistributor frames (RD at +0,
    // SGI at +0x10000); Device-attr map into the shared kernel half; then
    // the GIC helpers operate on this PE's own frame + sysregs.
    unsafe {
        <ArmMmu as MmuOps>::map(Va(ap_va), Pa(ap_pa), device_flags(), PageSize::P4K);
        <ArmMmu as MmuOps>::map(Va(ap_va + 0x1_0000), Pa(ap_pa + 0x1_0000), device_flags(), PageSize::P4K);
        crate::gic::ap_cpu_interface_enable(ap_va);
        crate::gic::enable_sgi_on(ap_va, crate::gic::RESCHED_SGI);
        // Enable this AP's CNTV virtual-timer PPI (INTID 27) + arm it
        // periodic so the AP preempts on its own tick, not just resched
        // SGIs. The dispatcher's UART/softirq work is BSP-gated; an AP
        // tick only reschedules. Period matches the BSP (10_000).
        crate::gic::enable_sgi_on(ap_va, 27);
        sched::live::install_default_runqueue();
        // F699: arm THIS AP's per-CPU IRQ stack before its timer starts
        // ticking (below). Runs on the AP with TPIDR set by ap_main and IRQs
        // still masked; the shared C213 kstack window is visible via TTBR1.
        match sched::kstack::alloc_leaked_top() {
            Some(top) => hal_aarch64::set_irq_stack_top(top),
            None => klog::write_raw(b"[IRQSTK] AP hardirq stack alloc failed; on task stack\n"),
        }
        hal_aarch64::timer::timer_periodic(10_000);
    }
}

/// Install the AP-init hook + the arm resched-IPI sender. Boot path,
/// before `bring_up_aps_psci`.
/// # C: O(1)
pub fn install_hooks() {
    hal_aarch64::smp::set_ap_init_hook(ap_init);
    hal_aarch64::smp::set_ap_idle_hook(ap_idle_loop);
    sched::live::set_send_resched_ipi_hook(crate::gic::send_resched_ipi);
}

/// AP idle→schedule loop (B3.5). Bridges hal-aarch64's AP_IDLE_HOOK to
/// `sched::halt_forever` (hal can't depend on sched). Never returns.
/// # SAFETY: called on the AP after its per-CPU runqueue + GIC + timer are
/// up and IRQs unmasked; halt_forever runs the idle→schedule loop forever.
unsafe fn ap_idle_loop() -> ! {
    sched::halt_forever()
}

/// Feed the ACPI-MADT GICC MPIDRs (already in `cpu` from the ACPI walk)
/// into the PSCI AP params. The EFI/GRUB arm path has no DTB `/cpus` list,
/// so `boot-aarch64`'s `publish_psci_ap_params` enumerated zero secondaries;
/// this overrides just the MPIDR list (keeping the self-boot page-table phys
/// it set) before `bring_up_aps_psci`. No-op when `cpu` is empty (the
/// `-kernel`/DTB path keeps its own list).
/// # C: O(N_cpus)
pub fn publish_madt_mpidrs() {
    let n = cpu::count();
    if n == 0 { return; }
    let mut mpidrs = [0u64; 16];
    let mut k = 0usize;
    let mut i = 0u32;
    while i < n && k < mpidrs.len() {
        if let Some((id, _flags)) = cpu::get(i as usize) {
            mpidrs[k] = id as u64;
            k += 1;
        }
        i += 1;
    }
    if k > 0 { hal_aarch64::smp::set_psci_ap_mpidrs(&mpidrs[..k]); }
}
