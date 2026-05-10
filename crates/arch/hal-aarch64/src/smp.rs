// aarch64 AP startup boot-CPU side. PSCI CPU_ON brings each
// secondary up at `oxide_ap_entry_arm` with x0 = context_id.
// Per-AP context is a `ApContext` allocated by the boot CPU,
// holding the AP's per-CPU page + stack top. The AP reads
// these from x0 and finishes its bring-up in `ap_main`.
//
// This is the boot-CPU outgoing half. AP-side asm prologue +
// Rust entry land in `smp_arm_entry.rs` (the `global_asm!`
// trampoline + `ap_main`).

#![cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, Ordering};

const AP_STACK_BYTES: usize = 16 * 1024;
const AP_PERCPU_BYTES: usize = 4096;

/// Per-AP context. The AP receives a pointer to this in x0
/// when PSCI CPU_ON jumps it into `oxide_ap_entry_arm`. Layout
/// is read-only after the boot CPU publishes it, so plain
/// fields suffice.
#[repr(C)]
pub struct ApContext {
    /// Top of the AP's kernel stack (16-byte-aligned).
    pub stack_top: u64,
    /// Per-CPU page (cpu_id at offset 0, then scratch).
    pub percpu_base: u64,
    /// Boot CPU's announce slot — AP increments via fetch_add.
    /// Boxed so the address survives drop of the ApContext box
    /// (which lives forever once published anyway).
    pub online_signal: u64,
}

/// Trampoline asm entry point. Sets up SP, calls `ap_main`.
/// Fixed name so PSCI CPU_ON's entry_pa can be `&oxide_ap_entry_arm`.
core::arch::global_asm!(
    ".global oxide_ap_entry_arm",
    ".section .text.ap_entry,\"ax\",@progbits",
    "oxide_ap_entry_arm:",
    // x0 = context_id (the ApContext pointer per psci::cpu_on).
    // Load stack_top, set SP, then branch to Rust ap_main with
    // the same x0.
    "  ldr x9, [x0, #0]",     // x9 = stack_top
    "  mov sp, x9",
    "  bl  ap_main",
    // ap_main returns ! — but be defensive.
    "1: wfe",
    "  b 1b",
);

/// AP-side Rust entry. Sets TPIDR_EL1 to the AP's per-CPU page,
/// records arrival in the online counter, then halts on wfe.
/// Real workflows (per-CPU runqueue install, vector table,
/// IRQ unmask) land alongside the load balancer in P4-15+.
///
/// # SAFETY: caller is the asm trampoline; `ctx` is the boot
/// CPU's published ApContext for this AP; AP is in EL1 with
/// MMU + caches still in the boot-CPU-visible state per PSCI.
/// # C: O(1)
#[no_mangle]
pub unsafe extern "C" fn ap_main(ctx: *const ApContext) -> ! {
    use hal::CpuOps;
    // SAFETY: per fn contract — ctx is the boot CPU's published, owned ApContext for this AP; sole writer here is this AP for its own per-CPU slot.
    unsafe {
        let c = &*ctx;
        // Stamp cpu_id (low u32 of mpidr) at percpu offset 0;
        // boot CPU pre-populated it but be safe.
        let pc = c.percpu_base as *mut u32;
        let mpidr: u64;
        core::arch::asm!("mrs {x}, MPIDR_EL1", x = out(reg) mpidr, options(nomem, nostack));
        core::ptr::write_volatile(pc, mpidr as u32);
        crate::ArmCpuOps::set_percpu_base(c.percpu_base as *mut u8);
        // Mark ourselves online via the boot CPU's cpu::smp::ap_arrived.
        let _ = cpu::smp::ap_arrived();
    }
    loop {
        // SAFETY: WFE is always legal at any EL; idle hint only.
        unsafe { core::arch::asm!("wfe"); }
    }
}

/// Boot-CPU AP startup entry. Iterates `cpu::smp::enumerate_aps()`,
/// allocates each AP's context + stack + per-CPU page, and
/// calls PSCI CPU_ON.
///
/// # SAFETY: caller is the boot path post-ACPI-walk; PSCI
/// conduit is configured (EDK2 / QEMU virt expose SMC).
/// # C: O(N_aps)
pub unsafe fn bring_up_aps_arm() -> usize {
    let aps = cpu::smp::enumerate_aps();
    let mut started = 0;
    for &mpidr in aps.iter() {
        // Allocate stack + per-CPU page + context.
        let stack: Box<[u8]> = alloc::vec![0u8; AP_STACK_BYTES].into_boxed_slice();
        let stack_top = (Box::leak(stack).as_ptr() as u64) + AP_STACK_BYTES as u64;
        let percpu: Box<[u8]> = alloc::vec![0u8; AP_PERCPU_BYTES].into_boxed_slice();
        let percpu_base = Box::leak(percpu).as_ptr() as u64;
        let ctx = Box::leak(Box::new(ApContext {
            stack_top:    stack_top & !0xfu64, // 16B align
            percpu_base,
            online_signal: 0,
        }));
        // PSCI CPU_ON jumps the target to oxide_ap_entry_arm with
        // x0 = ctx pointer.
        extern "C" {
            fn oxide_ap_entry_arm();
        }
        let entry_pa = oxide_ap_entry_arm as usize as u64;
        let context_id = ctx as *const ApContext as u64;
        // SAFETY: per fn contract — secure-monitor SMC; entry_pa is a kernel-mapped function (identity-mapped via the kernel's HHDM/upper half is accessible from EL1 once PSCI gives the AP control).
        let status = unsafe {
            crate::psci::cpu_on(mpidr as u64, entry_pa, context_id)
        };
        if matches!(status, crate::psci::PsciStatus::Success) {
            started += 1;
        }
    }
    started
}

#[allow(dead_code)]
static AP_LANES: AtomicU32 = AtomicU32::new(0);
