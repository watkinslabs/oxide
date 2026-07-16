use super::regs::{GICR_IGROUPR0, GICR_IPRIORITYR, GICR_ISENABLER0, GICR_SGI_OFFSET};

/// Enable SGI/PPI `intid` (< 32) in a specific redistributor's SGI frame
/// (`ap_gicr_va + 0x10000`) at default priority. Per-PE, so APs call this
/// on their own frame (the BSP's `enable_intid` only touches CPU0's).
/// # SAFETY: caller asserts `ap_gicr_va` is a mapped redistributor; intid < 32.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn enable_sgi_on(ap_gicr_va: u64, intid: u32) {
    let sgi = ap_gicr_va + GICR_SGI_OFFSET;
    // SAFETY: per fn contract; IGROUPR0, ISENABLER0, and IPRIORITYR live in the SGI frame.
    unsafe {
        let bit = 1u32 << (intid & 31);
        let group = (sgi + GICR_IGROUPR0 as u64) as *mut u32;
        core::ptr::write_volatile(group, core::ptr::read_volatile(group) | bit);
        let prio = (sgi + GICR_IPRIORITYR as u64 + intid as u64) as *mut u8;
        core::ptr::write_volatile(prio, 0xa0);
        let isenabler = (sgi + GICR_ISENABLER0 as u64) as *mut u32;
        core::ptr::write_volatile(isenabler, bit);
        core::arch::asm!("dsb sy", "isb", options(nostack, preserves_flags));
    }
}

/// Send SGI `intid` (0..15) to the PE with affinity-0 == `target_aff0`
/// (Aff1/2/3 = 0 on QEMU virt) via ICC_SGI1R_EL1. Used as the cross-CPU
/// resched IPI (`13§9`/§11).
/// # SAFETY: caller asserts the CPU interface is enabled; intid < 16.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn send_sgi(target_aff0: u32, intid: u32) {
    // ICC_SGI1R_EL1: INTID[27:24], Aff1[23:16]=0, TargetList[15:0]=1<<aff0.
    let val: u64 = ((intid as u64 & 0xf) << 24) | (1u64 << (target_aff0 & 0xf));
    // SAFETY: ICC_SGI1R_EL1 (s3_0_c12_c11_5) is writable at EL1; generates the SGI.
    unsafe {
        core::arch::asm!(
            "msr s3_0_c12_c11_5, {v:x}",
            "isb",
            v = in(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// SGI INTID used as the cross-CPU resched IPI (`13§9`/§11).
#[cfg(target_arch = "aarch64")]
pub const RESCHED_SGI: u32 = 0;

/// arm resched-IPI: send the resched SGI to CPU `cpu` (affinity-0 ==
/// `cpu` on QEMU virt). Matches the `SendReschedIpiFn` ABI so it can be
/// installed via `sched::live::set_send_resched_ipi_hook`. Always
/// "succeeds" (SGI generation is fire-and-forget).
/// # SAFETY: caller asserts the GIC CPU interface is enabled on the sender.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn send_resched_ipi(cpu: u32) -> bool {
    // SAFETY: per fn contract; SGI write via ICC_SGI1R_EL1.
    unsafe { send_sgi(cpu, RESCHED_SGI); }
    true
}

/// Install arm diag hooks. The cross-CPU heartbeat detector
/// (`sched::diag::percpu`) already names a frozen CPU + its last
/// task/syscall from another CPU — that is the primary arm visibility
/// and needs no hook. The FIQ-SGI register-dump *poke* (Group-0
/// pseudo-NMI to make the wedged CPU print its own regs) is NOT yet
/// wired: it needs the FIQ vector entries (vbar 0x300/0x500, today
/// halting) routed to a print+eret handler plus Group-0 SGI config, and
/// can't be SMP-verified in the current harness. Left uninstalled so the
/// sysrq backtrace honestly reports "no FIQ sender" rather than lying.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub fn install_diag_hooks() {
    // intentionally no set_poke_hook — see doc comment.
}
