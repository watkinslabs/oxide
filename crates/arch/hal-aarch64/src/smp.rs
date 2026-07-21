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
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

const AP_STACK_BYTES: usize = 16 * 1024;
const AP_PERCPU_BYTES: usize = 4096;
const AP_ONLINE_SPINS: u32 = 50_000_000;

/// Installed by the memory owner before SMP starts. Keeping this injection at
/// the HAL boundary avoids making HAL depend on PMM while ensuring AP per-CPU
/// pages have the same canonical PMM/memcg lifecycle as x86.
static PERCPU_ALLOC_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the permanent per-CPU page allocator before `bring_up_aps_psci`.
/// # C: O(1)
pub fn set_percpu_alloc_hook(hook: fn() -> Option<*mut u8>) {
    PERCPU_ALLOC_HOOK.store(hook as usize, Ordering::Release);
}

fn alloc_percpu_page() -> Option<*mut u8> {
    let raw = PERCPU_ALLOC_HOOK.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: setter stores only a function with this exact ABI before AP startup.
    let hook: fn() -> Option<*mut u8> = unsafe { core::mem::transmute(raw) };
    hook()
}

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

/// Kernel-image base: turns a linked code VA into its load-time physical
/// address (`phys = VA - KERNEL_BASE + load_base`, image maps KB→load_base).
const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Translate a kernel VA to its physical address via the MMU (AT S1E1R +
/// PAR_EL1). Robust regardless of which kernel mapping (image-linear, HHDM,
/// vmalloc) backs the VA — the boot CPU asks the page tables. Returns 0 on
/// a translation fault.
/// # SAFETY: `va` is a mapped kernel VA; `at s1e1r` + `mrs par_el1` only read
/// translation state.
/// # C: O(1)
unsafe fn va_to_pa(va: u64) -> u64 {
    let par: u64;
    // SAFETY: AT S1E1R does a stage-1 EL1 read translation of `va` into
    // PAR_EL1; no memory is accessed. isb orders the AT before the PAR read.
    unsafe {
        core::arch::asm!(
            "at s1e1r, {v}",
            "isb",
            "mrs {p}, par_el1",
            v = in(reg) va, p = out(reg) par,
            options(nostack, preserves_flags),
        );
    }
    if par & 1 != 0 { return 0; } // PAR_EL1.F: translation fault
    (par & 0x000F_FFFF_FFFF_F000) | (va & 0xFFF)
}
/// MPIDR_EL1 affinity mask (Aff0..Aff3), for BSP-vs-AP identity compares.
const MPIDR_AFF_MASK: u64 = 0xFF_00FF_FFFF;

/// Physical "boot block" the PSCI AP trampoline reads MMU-OFF — its address
/// travels as the PSCI `context_id`. A secondary brought up by `CPU_ON`
/// cannot dereference a high-VA `ApContext` until its MMU is on, so every
/// value the MMU-enable needs lives here, in a kernel-heap allocation whose
/// physical address (`VA - HHDM_OFFSET`) is identity-mapped via
/// `_sb_l1_ident` and thus readable with the MMU off. Field offsets are
/// load-bearing — the trampoline indexes them by constant.
#[repr(C)]
struct ApBootBlock {
    ttbr0_identity_pa: u64, // 0x00  _sb_ap_l0 phys (low identity for enable)
    ttbr1_pa:          u64, // 0x08  _sb_ttbr1_l0 phys (kernel high map)
    ttbr0_kernel_pa:   u64, // 0x10  _sb_ttbr0_l0 phys (user-AS root, post-jump)
    mair:              u64, // 0x18  MAIR_EL1 value
    tcr:               u64, // 0x20  TCR_EL1 value
    ctx_va:            u64, // 0x28  ApContext* (high HHDM VA, used MMU-on)
}

/// Max secondaries the static MPIDR list holds (QEMU `virt` tops out far
/// below this; real boards rarely exceed it for v1).
const MAX_AP_CPUS: usize = 16;

/// Boot-CPU-published PSCI AP parameters. `boot-aarch64` (which owns the
/// DTB, the self-boot page tables, and the load base) fills this via
/// `set_psci_ap_params` before `kernel_main`; `bring_up_aps_psci` reads it
/// once the heap is up. No `static mut`: an `UnsafeCell` behind a single
/// boot-CPU writer (pre-SMP) then read-only, gated by `PSCI_PARAMS_SET`.
struct PsciApParams {
    ap_l0_pa:        u64,
    ttbr1_pa:        u64,
    ttbr0_kernel_pa: u64,
    load_base:       u64,
    mpidrs:          [u64; MAX_AP_CPUS],
    cpu_count:       usize,
}

struct ParamsCell(core::cell::UnsafeCell<PsciApParams>);
// SAFETY: written once by the boot CPU before any AP exists, then only ever
// read; `PSCI_PARAMS_SET` orders the publication. No concurrent mutation.
unsafe impl Sync for ParamsCell {}
static PSCI_PARAMS: ParamsCell = ParamsCell(core::cell::UnsafeCell::new(PsciApParams {
    ap_l0_pa: 0, ttbr1_pa: 0, ttbr0_kernel_pa: 0, load_base: 0,
    mpidrs: [0; MAX_AP_CPUS], cpu_count: 0,
}));
static PSCI_PARAMS_SET: AtomicU32 = AtomicU32::new(0);

/// Publish the PSCI AP parameters from `boot-aarch64`'s self-boot path.
/// All addresses are PHYSICAL except `mpidrs` (DTB `/cpus` reg values).
/// Boot CPU only, before SMP bring-up.
/// # C: O(min(mpidrs.len(), MAX_AP_CPUS))
pub fn set_psci_ap_params(
    ap_l0_pa: u64, ttbr1_pa: u64, ttbr0_kernel_pa: u64, load_base: u64, mpidrs: &[u64],
) {
    // SAFETY: sole writer is the boot CPU before any AP is started; no
    // reader runs until PSCI_PARAMS_SET is observed Release/Acquire below.
    unsafe {
        let p = &mut *PSCI_PARAMS.0.get();
        p.ap_l0_pa = ap_l0_pa;
        p.ttbr1_pa = ttbr1_pa;
        p.ttbr0_kernel_pa = ttbr0_kernel_pa;
        p.load_base = load_base;
        let n = mpidrs.len().min(MAX_AP_CPUS);
        p.cpu_count = n;
        for i in 0..n { p.mpidrs[i] = mpidrs[i]; }
    }
    PSCI_PARAMS_SET.store(1, Ordering::Release);
}

/// Override just the MPIDR list (keeping the page-table phys + load_base
/// from `set_psci_ap_params`). The EFI/GRUB arm path has no DTB, so its DTB
/// `/cpus` list is empty; the kernel calls this with the ACPI-MADT GICC
/// MPIDRs (from `cpu_topology`) before `bring_up_aps_psci`. Boot CPU only.
/// # C: O(min(mpidrs.len(), MAX_AP_CPUS))
pub fn set_psci_ap_mpidrs(mpidrs: &[u64]) {
    // SAFETY: sole writer is the boot CPU pre-SMP; no AP reads until
    // bring_up_aps_psci runs after this returns.
    unsafe {
        let p = &mut *PSCI_PARAMS.0.get();
        let n = mpidrs.len().min(MAX_AP_CPUS);
        p.cpu_count = n;
        for i in 0..n { p.mpidrs[i] = mpidrs[i]; }
    }
    PSCI_PARAMS_SET.store(1, Ordering::Release);
}

// PSCI AP trampoline. `CPU_ON` enters here MMU-OFF, EL2-or-EL1, with
// x0 = phys(ApBootBlock). It reads the boot block, drops EL2->EL1, installs
// the self-boot page tables, enables the MMU, jumps to the higher half, then
// calls `ap_main(ctx)`. Mirrors `_arm_entry`'s EL drop + MMU enable but
// sources every address from the boot block (no boot-aarch64 symbol deps).
core::arch::global_asm!(
    ".global oxide_ap_entry_arm_psci",
    ".section .text.ap_entry,\"ax\",@progbits",
    "oxide_ap_entry_arm_psci:",
    // x0 = phys(ApBootBlock), MMU OFF. Latch fields into callee-saved regs
    // (they survive the EL2->EL1 eret).
    "  ldr x19, [x0, #0x00]",   // ttbr0_identity_pa (_sb_ap_l0)
    "  ldr x20, [x0, #0x08]",   // ttbr1_pa (_sb_ttbr1_l0)
    "  ldr x21, [x0, #0x10]",   // ttbr0_kernel_pa (_sb_ttbr0_l0)
    "  ldr x22, [x0, #0x18]",   // mair
    "  ldr x23, [x0, #0x20]",   // tcr
    "  ldr x24, [x0, #0x28]",   // ctx_va (high HHDM VA)
    // If at EL2, route EL1 AArch64 + timer + GICv3 SRE, then eret to EL1.
    "  mrs x0, CurrentEL",
    "  lsr x0, x0, #2",
    "  cmp x0, #2",
    "  b.ne _ap_psci_el1",
    "  movz x9, #0x8000, lsl #16",   // HCR_EL2.RW (EL1=AArch64)
    "  msr hcr_el2, x9",
    "  mov x9, #3",                  // CNTHCTL_EL2 EL1PCTEN|EL1PCEN
    "  msr cnthctl_el2, x9",
    "  msr cntvoff_el2, xzr",
    "  mov x9, #0xf",                // ICC_SRE_EL2 Enable|DFB|DIB|SRE
    "  msr S3_4_C12_C9_5, x9",
    "  isb",
    "  movz x9, #0x03c5",            // SPSR_EL2: EL1h, DAIF masked
    "  msr spsr_el2, x9",
    "  adr x9, _ap_psci_el1",        // ELR = phys label (MMU off)
    "  msr elr_el2, x9",
    "  eret",
    "_ap_psci_el1:",
    // EL1, MMU OFF. Install MAIR/TCR/TTBRs from the boot block.
    "  msr mair_el1, x22",
    "  msr tcr_el1, x23",
    "  msr ttbr0_el1, x19",          // low identity (_sb_ap_l0)
    "  msr ttbr1_el1, x20",          // kernel high (_sb_ttbr1_l0)
    "  dsb sy",
    "  tlbi vmalle1",
    "  dsb sy",
    "  isb",
    // Enable MMU + caches: SCTLR_EL1 M(0)|C(2)|I(12). CLEAR A(1)+SA0(4)
    // so EL0 unaligned Normal-memory access is hardware-handled (match
    // the BSP in selfboot.rs; firmware can leave A=1 at handoff).
    "  mrs x9, sctlr_el1",
    "  movz x10, #0x1005",
    "  orr x9, x9, x10",
    "  bic x9, x9, #(1 << 1)",   // A — alignment check off (match BSP/Linux)
    "  msr sctlr_el1, x9",
    "  isb",
    // Jump to the higher-half label via its absolute linked VA.
    "  movz x9, #:abs_g0_nc:_ap_psci_high",
    "  movk x9, #:abs_g1_nc:_ap_psci_high",
    "  movk x9, #:abs_g2_nc:_ap_psci_high",
    "  movk x9, #:abs_g3:_ap_psci_high",
    "  br x9",
    "_ap_psci_high:",
    // Higher half, MMU on (TTBR1). Swap TTBR0 to the kernel user-AS root
    // (matches the BSP's post-_arm_high state: [0] cleared, ready for
    // per-process user mappings).
    "  msr ttbr0_el1, x21",
    "  dsb sy",
    "  tlbi vmalle1",
    "  dsb sy",
    "  isb",
    // SP = ctx.stack_top (ApContext offset 0); ap_main(ctx).
    "  ldr x9, [x24, #0]",
    "  mov sp, x9",
    "  mov x0, x24",
    "  bl ap_main",
    "_ap_psci_park: wfe",
    "  b _ap_psci_park",
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

/// AP idle/schedule-loop hook (B3.5). Installed by the kernel to
/// `sched::halt_forever` so the AP runs the idle→schedule() loop (picking up
/// migrated tasks) instead of a bare `wfi` park. hal-aarch64 can't call
/// `sched` (layering), so it's a fn-ptr like AP_INIT_HOOK. Never returns.
static AP_IDLE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the AP idle-loop hook (kernel side, before `cpu_on`).
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn set_ap_idle_hook(f: unsafe fn() -> !) {
    AP_IDLE_HOOK.store(f as *mut (), Ordering::Release);
}

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
    #[cfg(feature = "debug-irq")]
    {
        klog::write_raw(b"[ap] entered ap_main aff=");
        klog::write_dec_u64(aff0 as u64);
        klog::write_raw(b"\n");
    }
    // Vector table (HAL-local) so this PE can take exceptions/IRQs.
    // SAFETY: AP at EL1, IRQs masked; install_default writes VBAR_EL1.
    unsafe { crate::vbar::install_default(); }
    // FP/SIMD access is configured per PE.  The scheduler saves and restores
    // the incoming and outgoing task's FPSIMD state on every context switch,
    // so an AP must enable CPACR_EL1.FPEN before it can enter its runqueue.
    // This mirrors the BSP setup in `_start_rust` and is required even before
    // the AP first returns to EL0.
    crate::fpu_enable();
    // SAFETY: AP bring-up before this PE runs EL0; enables architected counter reads.
    unsafe { crate::timer::enable_el0_counter_access(); }
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
    // Publish this AP's logical id in the online bitmap (symmetry with x86;
    // aarch64 uses hardware-broadcast `tlbi vae1is` so no shootdown IPI runs,
    // but keeping the bitmap correct costs nothing).
    if let Some(lg) = cpu::logical_id_for_hardware(aff0) {
        // SAFETY: this AP is the sole writer for its own online bit.
        unsafe { cpu::smp::mark_online(lg); }
    }
    #[cfg(feature = "debug-irq")]
    {
        klog::write_raw(b"[ap] online aff=");
        klog::write_dec_u64(aff0 as u64);
        klog::write_raw(b"\n");
    }
    // Unmask IRQs (clear DAIF.I) so resched SGIs + timer ticks are delivered.
    // SAFETY: VBAR + GIC CPU interface installed above; daifclr #2 clears the IRQ mask at EL1.
    unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)); }
    // B3.5: enter the idle→schedule() loop (halt_forever) so this AP picks up
    // tasks placed on its runqueue (ttwu / load balancer) — a bare wfi park
    // never calls schedule(), and post-Phase-A the IRQ-exit picker only runs
    // on return-to-user, so a parked AP would never run kernel-context work.
    #[cfg(target_os = "oxide-kernel")]
    {
        let p = AP_IDLE_HOOK.load(Ordering::Acquire);
        if !p.is_null() {
            // SAFETY: hook installed at boot with the exact `unsafe fn() -> !`
            // ABI (sched::halt_forever); it runs this AP's idle→schedule loop
            // and never returns.
            unsafe {
                let f: unsafe fn() -> ! = core::mem::transmute(p);
                f();
            }
        }
    }
    // Fallback (hook unset / non-kernel build): bare wfi park.
    loop {
        // SAFETY: WFI is legal at EL1; parks until an IRQ wakes us.
        unsafe { core::arch::asm!("wfi"); }
    }
}

/// Clean a VA range to the Point of Coherency so a CPU running with caches
/// off (a freshly-`CPU_ON`'d AP, before it sets SCTLR.C) reads the data from
/// RAM rather than a stale line. 64-byte stride covers the QEMU `virt` line
/// size; `dsb sy` orders the cleans before the `CPU_ON` SMC/HVC.
/// # SAFETY: `va..va+len` is a live mapped kernel allocation; `dc cvac` at
/// EL1 cleans by VA with no side effects beyond cache state.
/// # C: O(len / line)
unsafe fn clean_dcache_to_poc(va: u64, len: usize) {
    const LINE: u64 = 64;
    let mut p = va & !(LINE - 1);
    let end = va + len as u64;
    while p < end {
        // SAFETY: dc cvac cleans the cache line for VA p to PoC; p is within
        // a live kernel mapping; no memory is read or written by the op.
        unsafe { core::arch::asm!("dc cvac, {x}", x = in(reg) p, options(nostack, preserves_flags)); }
        p += LINE;
    }
    // SAFETY: dsb sy drains the cache-maintenance ops before the caller's CPU_ON.
    unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)); }
}

/// Boot-CPU AP startup via PSCI `CPU_ON` (Limine-free). For each non-BSP
/// MPIDR from the DTB `/cpus` list (published by `set_psci_ap_params`),
/// allocate a stack + per-CPU page + `ApContext` + a physical `ApBootBlock`,
/// clean the block to PoC, then `cpu_on(mpidr, entry_pa, phys(block))`. The
/// AP enters `oxide_ap_entry_arm_psci` MMU-off, installs the self-boot page
/// tables, and reaches `ap_main`. Returns APs released. No-op (SMP=1) when
/// params are unset or only the BSP is present — so a `-smp 1` boot runs
/// none of this.
///
/// # SAFETY: caller is `kernel_main` post-heap-init on the boot CPU; the
/// self-boot page tables named in the params are live for the rest of boot.
/// # C: O(N_aps)
pub unsafe fn bring_up_aps_psci() -> usize {
    let set = PSCI_PARAMS_SET.load(Ordering::Acquire);
    // SAFETY: params published once pre-SMP; we are the sole reader now.
    let p = unsafe { &*PSCI_PARAMS.0.get() };
    #[cfg(feature = "debug-irq")]
    {
        klog::write_raw(b"[smp-psci] set=");
        klog::write_dec_u64(set as u64);
        klog::write_raw(b" cpus=");
        klog::write_dec_u64(p.cpu_count as u64);
        klog::write_raw(b" load_base=");
        klog::write_hex_u64(p.load_base);
        klog::write_raw(b" ap_l0=");
        klog::write_hex_u64(p.ap_l0_pa);
        klog::write_raw(b" mpidr0=");
        klog::write_hex_u64(p.mpidrs[0]);
        klog::write_raw(b" mpidr1=");
        klog::write_hex_u64(if p.cpu_count > 1 { p.mpidrs[1] } else { 0 });
        klog::write_raw(b"\n");
    }
    if set == 0 { return 0; }
    if p.cpu_count < 2 { return 0; }
    let bsp_mpidr: u64;
    // SAFETY: MPIDR_EL1 read on the boot CPU; identifies the BSP to skip.
    unsafe { core::arch::asm!("mrs {x}, MPIDR_EL1", x = out(reg) bsp_mpidr, options(nomem, nostack)); }
    let bsp_aff = bsp_mpidr & MPIDR_AFF_MASK;
    extern "C" { fn oxide_ap_entry_arm_psci(); }
    let entry_pa = p.load_base + (oxide_ap_entry_arm_psci as *const () as u64).wrapping_sub(KERNEL_BASE);
    let mut started = 0usize;
    for i in 0..p.cpu_count {
        let mpidr = p.mpidrs[i];
        if (mpidr & MPIDR_AFF_MASK) == bsp_aff { continue; } // skip BSP
        let stack: Box<[u8]> = alloc::vec![0u8; AP_STACK_BYTES].into_boxed_slice();
        let stack_top = ((Box::leak(stack).as_ptr() as u64) + AP_STACK_BYTES as u64) & !0xfu64;
        if AP_PERCPU_BYTES != hal::PAGE_SIZE_BYTES as usize { continue; }
        let Some(percpu) = alloc_percpu_page() else { continue; };
        let percpu_base = percpu as u64;
        let ctx = Box::leak(Box::new(ApContext { stack_top, percpu_base, online_signal: 0 }));
        let bb = Box::leak(Box::new(ApBootBlock {
            ttbr0_identity_pa: p.ap_l0_pa,
            ttbr1_pa:          p.ttbr1_pa,
            ttbr0_kernel_pa:   p.ttbr0_kernel_pa,
            mair:              0x0000_0000_0000_FF04,
            tcr:               0x0000_0005_B510_3510,
            ctx_va:            ctx as *const ApContext as u64,
        }));
        let bb_va = bb as *const ApBootBlock as u64;
        // SAFETY: bb is a fresh heap allocation; clean its bytes to PoC so the
        // AP (caches off) reads the boot block from RAM.
        unsafe { clean_dcache_to_poc(bb_va, core::mem::size_of::<ApBootBlock>()); }
        // The kernel heap lives in the kernel-image high half (not HHDM), so
        // VA-HHDM gives garbage. Translate the boot block's kernel VA to its
        // physical address via the MMU (AT S1E1R) — what the AP reads MMU-off
        // through the identity map.
        // SAFETY: bb_va is a live mapped kernel VA; AT s1e1r reads PAR_EL1 only.
        let bb_pa = unsafe { va_to_pa(bb_va) };
        let before = cpu::smp::online_count();
        // SAFETY: PSCI conduit configured (HVC on QEMU virt); entry_pa is the
        // trampoline's load-time phys; bb_pa is cleaned and identity-mapped.
        let st = unsafe { crate::psci::cpu_on(mpidr, entry_pa, bb_pa) };
        #[cfg(feature = "debug-irq")]
        {
            klog::write_raw(b"[smp-psci] cpu_on mpidr=");
            klog::write_hex_u64(mpidr);
            klog::write_raw(b" entry=");
            klog::write_hex_u64(entry_pa);
            klog::write_raw(b" bb=");
            klog::write_hex_u64(bb_pa);
            klog::write_raw(b" st=");
            klog::write_dec_u64(st as i32 as u64);
            klog::write_raw(b"\n");
        }
        if matches!(st, crate::psci::PsciStatus::Success | crate::psci::PsciStatus::AlreadyOn) {
            let mut spins = 0u32;
            while cpu::smp::online_count() == before && spins < AP_ONLINE_SPINS {
                spins = spins.wrapping_add(1);
                core::hint::spin_loop();
            }
            // `ap_arrived` publishes the completed per-CPU runqueue with
            // release ordering; do not expose an AP until acquire observes it.
            if cpu::smp::online_count() > before { started += 1; }
        }
    }
    started
}

#[allow(dead_code)]
static AP_LANES: AtomicU32 = AtomicU32::new(0);
