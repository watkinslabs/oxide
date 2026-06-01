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
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

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
/// AP per-CPU bring-up hook, installed by the kernel (which can reach
/// `arch_irq::gic` + `sched`, unlike this leaf HAL crate). Called from
/// `ap_main` with the AP's affinity-0 id after TPIDR_EL1 + VBAR are set;
/// the hook wakes the AP's GIC redistributor + CPU interface, enables the
/// resched SGI, and installs the AP's per-CPU runqueue. `None` → the AP
/// stays a bare idle CPU (pre-F326 behaviour).
#[cfg(target_os = "oxide-kernel")]
static AP_INIT_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the AP per-CPU bring-up hook. Boot path, before `cpu_on`.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn set_ap_init_hook(f: unsafe fn(u32)) {
    AP_INIT_HOOK.store(f as *mut (), Ordering::Release);
}

/// AP-side Rust entry. Sets TPIDR_EL1 to the AP's per-CPU page + VBAR,
/// runs the kernel AP-init hook (GIC CPU-interface + runqueue), marks
/// itself online, unmasks IRQs, then idles on `wfi` so a resched SGI
/// (`gic::send_resched_ipi`) wakes it to run scheduled work.
///
/// # SAFETY: caller is the asm trampoline; `ctx` is the boot CPU's
/// published ApContext for this AP; AP is at EL1, MMU + caches in the
/// boot-CPU-visible state per PSCI.
/// # C: O(1)
#[no_mangle]
pub unsafe extern "C" fn ap_main(ctx: *const ApContext) -> ! {
    use hal::CpuOps;
    let aff0: u32;
    // SAFETY: per fn contract — ctx is the boot CPU's published, owned ApContext for this AP; sole writer here is this AP for its own per-CPU slot.
    unsafe {
        let c = &*ctx;
        let pc = c.percpu_base as *mut u32;
        let mpidr: u64;
        core::arch::asm!("mrs {x}, MPIDR_EL1", x = out(reg) mpidr, options(nomem, nostack));
        aff0 = (mpidr & 0xff) as u32;
        core::ptr::write_volatile(pc, aff0);
        crate::ArmCpuOps::set_percpu_base(c.percpu_base as *mut u8);
    }
    // Vector table (HAL-local) so this PE can take exceptions/IRQs.
    // SAFETY: AP at EL1, IRQs masked; install_default writes VBAR_EL1.
    unsafe { crate::vbar::install_default(); }
    // Kernel AP-init hook: GIC CPU interface + resched SGI + runqueue.
    #[cfg(target_os = "oxide-kernel")]
    {
        let p = AP_INIT_HOOK.load(Ordering::Acquire);
        if !p.is_null() {
            // SAFETY: hook was installed at boot by the kernel with the exact `unsafe fn(u32)` ABI; transmute restores that fn-ptr and we invoke it on this AP for its own per-CPU GIC + runqueue state.
            unsafe {
                let f: unsafe fn(u32) = core::mem::transmute(p);
                f(aff0);
            }
        }
    }
    // Mark ourselves online via the boot CPU's cpu::smp::ap_arrived.
    let _ = cpu::smp::ap_arrived();
    // Unmask IRQs (clear DAIF.I) so resched SGIs are delivered.
    // SAFETY: VBAR + GIC CPU interface installed above; daifclr #2 clears the IRQ mask at EL1.
    unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)); }
    loop {
        // SAFETY: WFI is legal at EL1; parks until an IRQ (resched SGI / timer) wakes us; the IRQ-exit picker then runs whatever this CPU's runqueue holds.
        unsafe { core::arch::asm!("wfi"); }
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
