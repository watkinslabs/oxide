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

/// Kernel-side mirror of Limine's aarch64 `limine_smp_info`. Limine jumps
/// the AP to `goto_address` (MMU-on, EL1, kernel page tables) with
/// `x0 = &SmpInfoArm`; `extra_argument` (offset 0x20) carries our
/// `ApContext` pointer. Mirrored here to avoid a cyclic dep on limine-proto.
#[repr(C)]
pub struct SmpInfoArm {
    pub processor_id:   u32,   // 0x00
    pub gic_iface_no:   u32,   // 0x04
    pub mpidr:          u64,   // 0x08
    pub reserved:       u64,   // 0x10
    pub goto_address:   AtomicPtr<()>, // 0x18
    pub extra_argument: u64,   // 0x20  (= ApContext ptr)
}

// Trampoline asm entry. Limine enters here MMU-on with `x0 = &SmpInfoArm`.
// Reads `extra_argument` (our ApContext) at +0x20, sets SP from
// `ctx.stack_top`, then calls `ap_main(ctx)`.
core::arch::global_asm!(
    ".global oxide_ap_entry_arm",
    ".section .text.ap_entry,\"ax\",@progbits",
    "oxide_ap_entry_arm:",
    "  ldr x1, [x0, #0x20]",  // x1 = extra_argument = ApContext*
    "  ldr x9, [x1, #0]",     // x9 = ctx.stack_top
    "  mov sp, x9",
    "  mov x0, x1",           // ap_main(ctx)
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

/// Boot-CPU AP startup via Limine's SMP response (`13§11`). Walks the
/// `[*mut SmpInfoArm; smp_count]` array Limine filled, and for each
/// non-BSP entry allocates a stack + per-CPU page + `ApContext`, publishes
/// `extra_argument` then stores `goto_address = oxide_ap_entry_arm`. Limine
/// then starts the parked AP MMU-ON at our higher-half entry (no PSCI
/// MMU-off trampoline). `bsp_aff0` is the boot CPU's affinity-0 id.
/// Returns the number of APs released. No-op when `smp_info_array == 0`
/// (Limine SMP absent) or `smp_count < 2` (uniprocessor).
///
/// # SAFETY: caller is the boot path; `smp_info_array` is Limine's
/// bootloader-owned `cpus[]` (alive for the rest of boot); each pointee is
/// a `SmpInfoArm`. Allocator up.
/// # C: O(N_aps)
pub unsafe fn bring_up_aps_arm(smp_info_array: u64, smp_count: u64, bsp_aff0: u32) -> usize {
    if smp_info_array == 0 || smp_count == 0 { return 0; }
    let table = smp_info_array as *const *mut SmpInfoArm;
    extern "C" { fn oxide_ap_entry_arm(); }
    let mut started = 0usize;
    for i in 0..smp_count as usize {
        // SAFETY: per fn contract — table is `[*mut SmpInfoArm; smp_count]`; index i in range.
        let info_ptr = unsafe { *table.add(i) };
        if info_ptr.is_null() { continue; }
        // SAFETY: info_ptr is a Limine-owned SmpInfoArm alive for boot.
        let info = unsafe { &*info_ptr };
        if (info.mpidr & 0xff) as u32 == bsp_aff0 { continue; } // skip BSP
        let stack: Box<[u8]> = alloc::vec![0u8; AP_STACK_BYTES].into_boxed_slice();
        let stack_top = (Box::leak(stack).as_ptr() as u64) + AP_STACK_BYTES as u64;
        let percpu: Box<[u8]> = alloc::vec![0u8; AP_PERCPU_BYTES].into_boxed_slice();
        let percpu_base = Box::leak(percpu).as_ptr() as u64;
        let ctx = Box::leak(Box::new(ApContext {
            stack_top:    stack_top & !0xfu64, // 16B align
            percpu_base,
            online_signal: 0,
        }));
        // Publish extra_argument THEN goto_address (the go signal). Limine
        // reads them seq-cst; Release-ordered stores suffice.
        // SAFETY: info is the AP's parked SmpInfoArm; the AP only reads after goto_address is set.
        unsafe { (*info_ptr).extra_argument = ctx as *const ApContext as u64; }
        info.goto_address.store(oxide_ap_entry_arm as *mut (), Ordering::Release);
        started += 1;
    }
    started
}

#[allow(dead_code)]
static AP_LANES: AtomicU32 = AtomicU32::new(0);
