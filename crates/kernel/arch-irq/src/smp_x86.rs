// x86_64 AP startup via LAPIC INIT/SIPI (Intel SDM Vol 3 §8.4) per `13§11`.
//
// Limine is gone (self-boot/GRUB), so the old parked-AP `goto_address`
// path is dead. We start each AP ourselves: copy a real-mode→long-mode
// trampoline to a low phys page, identity-map it in the kernel master
// PML4, then INIT → SIPI → SIPI off the ACPI MADT topology (`cpu::get`).
// The trampoline (16→32→64) loads the master CR3 (PAE+LME+**NXE** — the
// kernel uses NX-marked PTEs; NXE off makes bit 63 reserved → #PF),
// sets the per-AP stack, and `jmp`s `oxide_ap_entry_64` → `ap_main_x86`.
//
// STATUS: ENABLED (F428). `bring_up_aps_x86` INIT/SIPI-starts each MADT AP
// to long mode; `ap_main_x86` then makes it a full scheduling target:
// FSGSBASE, GS_BASE, syscall MSRs (EFER.SCE/STAR/LSTAR/SFMASK), IDTR, LAPIC
// enable, per-CPU runqueue + TSS + syscall-kstack + LAPIC timer, then `sti`
// idle. User tasks DO migrate onto the AP and issue `syscall` here — so the
// per-AP syscall-MSR install is mandatory (without it the AP #UDs on
// `syscall`/`sysretq`).

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use alloc::boxed::Box;
use core::sync::atomic::AtomicPtr;

use boot_info::BootInfo;

/// Kernel-side mirror of `limine_proto::SmpInfoX86`. Layout matches
/// Limine v6+ verbatim (`#[repr(C)]`); kept here to avoid a cyclic
/// crate dependency with `limine-proto` (which uses `kernel::*`).
/// `boot-x86_64`'s `build_boot_info` writes the array pointer +
/// count + bsp_lapic_id into `BootInfo`; this struct's fields
/// match the same offsets the bootloader populates.
#[repr(C)]
pub struct SmpInfoX86 {
    pub processor_id:   u32,
    pub lapic_id:       u32,
    pub reserved:       u64,
    pub goto_address:   AtomicPtr<()>,
    pub extra_argument: u64,
}

/// Per-AP context published by the boot CPU via
/// `SmpInfoX86::extra_argument`. Layout is read-only after publish.
#[repr(C)]
pub struct ApContext {
    /// Per-CPU page (logical cpu_id at offset 0, then scratch).
    pub percpu_base: u64,
}

/// AP-side entry. Limine jumps the parked AP here with
/// `rdi = info` once the boot CPU stores us in `info.goto_address`.
///
/// # SAFETY: caller is Limine; AP is in long mode, kernel AS
/// active, IRQs masked, stack already set up by Limine.
/// 64-bit landing pad the real-mode trampoline jumps to (`jmp rax`)
/// once long mode is on. The trampoline set rdi=percpu_base,
/// esi=logical_cpu_id, rsp=per-AP stack top from its patched data block.
/// Forwards to the shared `ap_main_x86`.
/// # SAFETY: entered from the trampoline in 64-bit mode, kernel CR3
/// (master) active, IRQs masked, rsp = a valid kernel stack top.
/// # C: O(1)
#[no_mangle]
pub unsafe extern "C" fn oxide_ap_entry_64(percpu_base: u64, logical_cpu_id: u64) -> ! {
    // SAFETY: trampoline passed a freshly-allocated per-CPU page + this
    // AP's dense scheduler CPU id; we are the sole user of both for this AP.
    unsafe { ap_main_x86(percpu_base, logical_cpu_id as u32) }
}

/// Shared AP bring-up body: enable FSGSBASE, stamp logical cpu_id + GS_BASE,
/// load IDTR, enable the LAPIC, install the per-CPU runqueue, mark
/// online, arm the LAPIC timer, then park in the `sti; hlt` idle
/// loop. Diverges.
/// # SAFETY: long mode, CPL=0, IRQs masked, kernel CR3 active, a
/// valid kernel stack installed; `percpu_base` is this AP's private
/// 4 KiB page.
/// # C: O(1)
unsafe fn ap_main_x86(percpu_base: u64, logical_cpu_id: u32) -> ! {
    let ctx = ApContext { percpu_base };
    let ctx = &ctx;

    // B3.4: load the shared kernel GDT FIRST. The SIPI trampoline left this
    // AP on its own minimal 4-entry GDT (CS=0x18); kernel CS/DS (0x28/0x30)
    // and the per-CPU TSS selectors (0x50+cpu*0x10) only exist in the kernel
    // GDT. MUST precede the GS_BASE setup below: the reload writes GS=0x30
    // (→ GS base 0), so the wrgsbase that follows re-establishes the per-CPU
    // base correctly. Without this, `ltr` of the AP's TSS selector #GP's →
    // triple fault (the old "AP scheduling wedges the boot").
    // SAFETY: AP at CPL=0, long mode, kernel master CR3; BSP completed
    // install_kernel_gdt; we only reload to descriptors present in it.
    unsafe { hal_x86_64::load_kernel_gdt_for_ap(); }

    // Configure THIS AP's `syscall`/`sysret` MSRs (EFER.SCE, STAR, LSTAR,
    // SFMASK). The SIPI trampoline set only EFER.LME|NXE, so SCE is OFF and
    // STAR/LSTAR are unset on a fresh AP — a user task scheduled here would
    // #UD on `syscall`, and a task that entered via `syscall` on the BSP then
    // migrated would #UD on `sysretq` here. MUST follow load_kernel_gdt_for_ap
    // (STAR's selectors key to the kernel GDT) and does NOT touch gs:[8] (the
    // per-CPU syscall kstack is seeded by init_percpu_syscall_kstack below).
    // SAFETY: AP at CPL=0, long mode, kernel GDT loaded above; install_syscall_msrs
    // writes only privileged MSRs from kernel-controlled constants matching that GDT.
    unsafe { hal_x86_64::install_syscall_msrs(); }

    // Enable SSE/SSE2 on this AP (CR0.MP + clear CR0.EM, CR4.OSFXSR|OSXMMEXCPT).
    // CR0/CR4 are per-CPU: the SIPI trampoline leaves the AP without these, so
    // the FIRST SSE insn a user task runs here (`pxor`/`movups` — musl libc
    // startup uses them pervasively) #UDs → unrecoverable fault → the AP halts
    // in oxide_fault_common and the boot wedges. The BSP does this at
    // _start_rust right after install_syscall_msrs; the AP must match.
    // SAFETY: AP at CPL=0, long mode; privileged CR0/CR4 writes legal; this AP
    // is the sole writer of its own CR0/CR4 (the regs are per-CPU).
    unsafe { hal_x86_64::enable_sse(); }

    // Enable CR4.FSGSBASE on this AP (Limine leaves it off per-AP).
    // SAFETY: AP runs CPL=0 here; CR4 write is legal; bit 16 enables rd/wrgsbase which we use immediately below.
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {cr4}, cr4", cr4 = out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= 1u64 << 16;
        core::arch::asm!("mov cr4, {cr4}", cr4 = in(reg) cr4, options(nomem, nostack, preserves_flags));
    }

    // Stamp logical cpu_id at percpu offset 0 + install GS_BASE.
    // SAFETY: ctx.percpu_base is a freshly-allocated 4 KiB page owned by this AP from publish; sole writer is this AP.
    unsafe {
        let pc = ctx.percpu_base as *mut u32;
        core::ptr::write_volatile(pc, logical_cpu_id);
        use hal::CpuOps;
        hal_x86_64::X86CpuOps::set_percpu_base(ctx.percpu_base as *mut u8);
    }

    // Install IDTR on this AP so it can vector exceptions through
    // the BSP-populated IDT. The IDT array itself is shared; only
    // the per-CPU IDTR register needs loading here.
    // SAFETY: BSP ran install_default_idt before bring_up_aps_x86;
    // load_idtr_for_ap reads only IDT.as_ptr() to build the IDTR
    // operand and issues `lidt`. Legal at CPL=0.
    unsafe { hal_x86_64::load_idtr_for_ap(); }

    // Software-enable this AP's LAPIC + set IA32_APIC_BASE.E. The
    // LAPIC MMIO virtual address (LAPIC_BASE_VA, set by the BSP)
    // aliases per-CPU on x86 — each CPU sees its own LAPIC page
    // through the same VA. Required before this AP can take any
    // local interrupt (timer, IPI).
    // SAFETY: BSP ran lapic::enable() so LAPIC_BASE_VA is non-zero;
    // CPU is at CPL=0 IRQs masked; sole writer for this CPU's
    // SVR + IA32_APIC_BASE MSR.
    let _ = unsafe { crate::lapic::enable_for_ap() };

    // B3.4: AP scheduling participation. The per-CPU foundation is in place
    // (per-CPU TSS RSP0 = B3.2, per-CPU syscall slots = B3.3), so the AP can
    // schedule without clobbering the BSP's kernel-stack pointers.
    // SAFETY: AP at CPL=0, long mode, kernel master CR3, gs = this AP's
    // per-CPU area (cpu_id = logical_cpu_id at offset 0); sole owner of its state.
    unsafe {
        // 1. Per-CPU runqueue + idle task. `this_cpu()` (gs:0) is the dense
        //    logical CPU id, so install_default_runqueue populates GLOBALS[cpu].
        //    own slot (register_timers + schedule-hook are idempotent).
        sched::live::install_default_runqueue();
        // 2. Load THIS AP's TSS (selector TSS_SEL + cpu*0x10) so a user
        //    task scheduled here lands ring3→ring0 on this CPU's RSP0.
        hal_x86_64::install_tss_for_cpu(logical_cpu_id as u16);
        // 2b. SMP-IST: populate THIS AP's TSS IST slots (#DF/NMI/#DB/#MC)
        //     immediately after `ltr`, BEFORE the `sti` below — the shared
        //     IDT gates already carry the IST indices (BSP set them), so the
        //     AP's slots must be non-zero before any IST-routed fault (esp.
        //     the non-maskable NMI/#DF) can fire on this CPU. Without a
        //     dedicated #DF stack an AP fault mid kernel-stack-switch
        //     corrupts the live stack → triple fault (the -smp 2 flake).
        //     SAFETY: this AP is the sole writer of its own TSS slot; the
        //     allocator is live (BSP brought it up pre-SMP); runs IRQ-off.
        hal_x86_64::setup_ist_stacks(logical_cpu_id as u16);
        // 3. Seed this AP's syscall-kstack slot (gs:[8]); per-task tops then
        //    come from set_syscall_kstack on each switch. Use this AP's stack
        //    top as the pre-first-switch scratch.
        hal_x86_64::init_percpu_syscall_kstack(hal_x86_64::boot_syscall_kstack_top());
        // 3b. F699: arm THIS AP's per-CPU hardirq stack (gs:[24]) BEFORE the
        //     `sti` below, so the IRQ handler + do_softirq run off the
        //     interrupted stack once this AP takes IRQs. Guard-paged + leaked;
        //     `None` (frame exhaustion) leaves the slot 0 ⇒ dispatch on the
        //     interrupted stack (pre-fix behavior, no crash).
        match sched::kstack::alloc_leaked_top() {
            // SAFETY: this AP's gs base is set; `top` outlives the kernel.
            Some(top) => hal_x86_64::init_percpu_hardirq_stack(top),
            None => klog::write_raw(b"[IRQSTK] AP hardirq stack alloc failed; on task stack\n"),
        }
        // 4. Arm this AP's LAPIC timer (same period as the BSP's elf path) so
        //    it preempts + wakes from idle. The LAPIC MMIO VA aliases per-CPU.
        let _ = crate::lapic::timer_periodic(1_000_000);
        // 5. Mark ourselves online only after the per-CPU scheduler and timer
        //    state exists. The BSP may send a resched IPI immediately after
        //    observing online_count reach the target.
        let _ = ::cpu::smp::ap_arrived();
        // Publish this AP's logical id in the online bitmap so the TLB
        // shootdown sender targets it (and waits for its ACK). Set AFTER the
        // LAPIC + IDT are live so the AP can actually service a shootdown IPI.
        // SAFETY: this AP is the sole writer for its own online bit.
        unsafe { ::cpu::smp::mark_online(logical_cpu_id as u32); }
        // 6. Enter the idle→schedule loop with IRQs on (sti) — replaces the
        //    cli;hlt park. The AP runs its idle task until ttwu (B2) migrates
        //    a task onto its runqueue and IPIs it.
        core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
    }
    sched::halt_forever()
}

const AP_PERCPU_BYTES: usize = 4096;
/// AP kernel stack size (16 KiB, matches the BSP boot stack budget).
const AP_STACK_BYTES: usize = 16 * 1024;
/// Physical page (4 KiB-aligned, <1 MiB) holding the real-mode AP
/// trampoline. SIPI startup vector = `TRAMP_PA >> 12` (must fit u8).
const TRAMP_PA: u64 = 0x8000;

// Real-mode → long-mode AP trampoline. INIT/SIPI starts each AP in
// 16-bit real mode at CS:IP = (vector<<12):0 = TRAMP_PA. This code is
// copied to TRAMP_PA at bring-up and TRAMP_PA is identity-mapped in
// the kernel CR3 so it keeps executing once paging turns on. All
// absolute refs use the literal TRAMP_PA base; 64-bit reads are
// RIP-relative (load-base independent). Per-AP fields (stack/percpu/
// cpu) + cr3/entry are patched into the data block before each SIPI.
core::arch::global_asm!(
    ".section .text.ap_tramp,\"ax\",@progbits",
    ".code16",
    ".globl oxide_ap_tramp",
    "oxide_ap_tramp:",
    "    cli",
    "    cld",
    "    xor   ax, ax",
    "    mov   ds, ax",
    "    mov   es, ax",
    "    mov   ss, ax",
    "    lgdt  [0x8f60]",               // gdtptr @ TRAMP_PA + 0xf60
    "    mov   eax, cr0",
    "    or    eax, 1",                 // CR0.PE
    "    mov   cr0, eax",
    // far jump to 32-bit protected mode: 0x66 (opsize) 0xEA off32 sel16
    "    .byte 0x66, 0xea",
    "    .long oxide_ap_tramp_32 - oxide_ap_tramp + 0x8000",
    "    .word 0x08",
    ".code32",
    "oxide_ap_tramp_32:",
    "    mov   ax, 0x10",
    "    mov   ds, ax",
    "    mov   es, ax",
    "    mov   ss, ax",
    "    mov   eax, cr4",
    "    or    eax, 0x20",              // CR4.PAE
    "    mov   cr4, eax",
    "    mov   eax, [0x8f00]",          // cr3 @ TRAMP_PA + 0xf00
    "    mov   cr3, eax",
    "    mov   ecx, 0xc0000080",        // IA32_EFER
    "    rdmsr",
    "    or    eax, 0x900",             // EFER.LME (0x100) | EFER.NXE (0x800)
    "    wrmsr",                        // NXE required: kernel PTEs use the NX
    //                                     bit; with NXE=0 it's reserved → #PF
    "    mov   eax, cr0",
    "    or    eax, 0x80000001",        // CR0.PG | CR0.PE → long mode
    "    mov   cr0, eax",
    // far jump to 64-bit: 0xEA off32 sel16 (64-code selector 0x18)
    "    .byte 0xea",
    "    .long oxide_ap_tramp_64 - oxide_ap_tramp + 0x8000",
    "    .word 0x18",
    ".code64",
    "oxide_ap_tramp_64:",
    "    mov   rsp, [rip + oxide_ap_tramp_stack]",
    "    mov   rdi, [rip + oxide_ap_tramp_percpu]",
    "    mov   rsi, [rip + oxide_ap_tramp_cpu]",
    "    mov   rax, [rip + oxide_ap_tramp_entry]",
    "    jmp   rax",
    // Data block at fixed offset 0xf00 (so the .code16/.code32 stages
    // can use numeric absolute [0x8f00]/[0x8f60] operands — a memory
    // operand can't carry symbol arithmetic).
    "    .org  0xf00",
    ".globl oxide_ap_tramp_cr3",
    "oxide_ap_tramp_cr3:    .quad 0",   // 0xf00
    ".globl oxide_ap_tramp_entry",
    "oxide_ap_tramp_entry:  .quad 0",   // 0xf08
    ".globl oxide_ap_tramp_stack",
    "oxide_ap_tramp_stack:  .quad 0",   // 0xf10
    ".globl oxide_ap_tramp_percpu",
    "oxide_ap_tramp_percpu: .quad 0",   // 0xf18
    ".globl oxide_ap_tramp_cpu",
    "oxide_ap_tramp_cpu:    .quad 0",   // 0xf20
    "    .org  0xf40",
    "oxide_ap_tramp_gdt:",               // 0xf40
    "    .quad 0x0000000000000000",     // null
    "    .quad 0x00cf9a000000ffff",     // 0x08: 32-bit code
    "    .quad 0x00cf92000000ffff",     // 0x10: 32-bit data
    "    .quad 0x00209a0000000000",     // 0x18: 64-bit code (L=1)
    "    .org  0xf60",
    "oxide_ap_tramp_gdtptr:",            // 0xf60
    "    .word 0x1f",                   // limit = 4*8 - 1
    "    .long oxide_ap_tramp_gdt - oxide_ap_tramp + 0x8000",
    "    .org  0x1000",
    ".globl oxide_ap_tramp_end",
    "oxide_ap_tramp_end:",
    ".code64",
);

extern "C" {
    static oxide_ap_tramp: u8;
    static oxide_ap_tramp_end: u8;
    static oxide_ap_tramp_cr3: u8;
    static oxide_ap_tramp_entry: u8;
    static oxide_ap_tramp_stack: u8;
    static oxide_ap_tramp_percpu: u8;
    static oxide_ap_tramp_cpu: u8;
}

/// Reserve the AP real-mode trampoline page (`TRAMP_PA`) from the PMM so
/// the buddy allocator never hands it out — `bring_up_aps_x86` copies the
/// 16→32→64 trampoline blob there at SMP bring-up. MUST be called right
/// after PMM init, BEFORE the first allocation: `reserve_early` silently
/// skips an already-allocated page (would re-introduce the corruption).
/// No-op at SMP=1 too (harmless — the page just stays reserved). No-op if
/// `TRAMP_PA` is outside seeded RAM (then the PMM never managed it).
/// # C: O(1)
/// # Ctx: pre-init, single-CPU, right after PMM init
pub fn reserve_trampoline_page() {
    if let Some(p) = pmm::setup::pmm_static() {
        // pfn = TRAMP_PA >> 12 = 8. One 4 KiB page covers the blob + its
        // GDT/data block (all within [TRAMP_PA, TRAMP_PA+0x1000)).
        let _ = p.reserve_early(hal::Pfn(TRAMP_PA >> 12), 1);
    }
}

/// Boot-CPU AP startup via LAPIC INIT/SIPI per Intel SDM Vol 3 §8.4.
/// Copies the trampoline to TRAMP_PA, identity-maps it, then for each
/// enabled MADT CPU (skipping the BSP) patches the per-AP data block
/// and sends INIT → SIPI → SIPI, waiting for the AP to mark itself
/// online. Replaces the dead Limine `goto_address` path. `_info` is
/// unused (the MB2/GRUB BootInfo has no SMP table — topology comes
/// from the ACPI MADT via `cpu::get`).
/// # SAFETY: caller is the boot path post-ACPI-walk + post-LAPIC
/// enable + post-MmuOps init; single-CPU; IRQs masked.
/// # C: O(N_aps)
#[allow(unreachable_code, unused_variables, unused_unsafe, unused_mut)]
pub unsafe fn bring_up_aps_x86(_info: &BootInfo) -> usize {
    use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
    // ENABLED (F428): INIT/SIPI bring-up brings each AP to long mode +
    // online (LAPIC). Blocker (1) — TRAMP_PA not reserved from the PMM —
    // is fixed by `reserve_trampoline_page()` (called from kmain right
    // after PMM init). The AP then PARKS quiescent in `ap_main_x86`
    // (cli;hlt): online + counted, but NOT yet a scheduling target —
    // blocker (2), AP scheduling participation, lands next (per-CPU TSS +
    // syscall slots + runqueue/timer/idle integration). So an un-gated AP
    // here does NOT schedule and cannot wedge the BSP via blocker (2).
    let hhdm = pmm::user_as::hhdm_offset();
    if hhdm == 0 { return 0; }
    if AP_PERCPU_BYTES != hal::PAGE_SIZE_BYTES as usize { return 0; }

    // 1. Copy the trampoline blob to TRAMP_PA (via its HHDM mirror).
    // SAFETY: symbols bound the global_asm blob; TRAMP_PA's HHDM mirror
    // is a kernel-writable alias of conventional low RAM; blob ≤ 4 KiB.
    let (blob, blob_len, cr3_off, entry_off, stack_off, percpu_off, cpu_off) = unsafe {
        let s = &oxide_ap_tramp as *const u8;
        let e = &oxide_ap_tramp_end as *const u8;
        let base = s as usize;
        (s,
         e as usize - base,
         &oxide_ap_tramp_cr3 as *const u8 as usize - base,
         &oxide_ap_tramp_entry as *const u8 as usize - base,
         &oxide_ap_tramp_stack as *const u8 as usize - base,
         &oxide_ap_tramp_percpu as *const u8 as usize - base,
         &oxide_ap_tramp_cpu as *const u8 as usize - base)
    };
    let tramp = (hhdm + TRAMP_PA) as *mut u8;
    // SAFETY: blob is the linked trampoline; tramp is its low-RAM HHDM mirror; non-overlapping, len ≤ 4 KiB.
    unsafe { core::ptr::copy_nonoverlapping(blob, tramp, blob_len); }

    // 2. Patch the constant data-block fields (cr3 + 64-bit entry).
    // Use the KERNEL MASTER PML4, not read_cr3(): x86 user tasks share the
    // global user AS (clone_global_arc), so mapping the trampoline into the
    // active CR3 pollutes systemd's address space (wedges first-boot). The
    // master carries all kernel mappings (LAPIC, HHDM, kernel text) + we add
    // the trampoline identity below; the AP runs on it.
    let master = hal_x86_64::mmu_ops::kernel_master();
    // SAFETY: read_cr3 is a privileged CR3 read at CPL=0, side-effect-free; only used as a fallback if the master PML4 PA wasn't captured.
    let live = unsafe { hal_x86_64::read_cr3() };
    let cr3 = (if master != 0 { master } else { live }) & !(hal::PAGE_SIZE_BYTES - 1);
    // SAFETY: offsets lie within the copied blob; aligned .quad slots.
    unsafe {
        core::ptr::write_volatile(tramp.add(cr3_off) as *mut u64, cr3);
        core::ptr::write_volatile(tramp.add(entry_off) as *mut u64,
            oxide_ap_entry_64 as *const () as usize as u64);
    }

    // 3. Identity-map the trampoline page so it keeps executing once
    //    CR0.PG turns on with the kernel CR3.
    // SAFETY: TRAMP_PA is conventional low RAM not owned by any kernel
    // subsystem after boot; identity map is torn down implicitly (page
    // only touched during bring-up); RWX needed for the 16/32/64 code.
    unsafe {
        <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::map_at(
            cr3, Va(TRAMP_PA), Pa(TRAMP_PA),
            PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC, PageSize::P4K);
    }

    let bsp = crate::lapic::local_apic_id();
    let mut started = 0usize;
    let n = ::cpu::count() as usize;
    for i in 0..n {
        let (id, flags) = match ::cpu::get(i) { Some(t) => t, None => break };
        if id == bsp { continue; }
        if (flags & (::cpu::FLAG_ENABLED | ::cpu::FLAG_ONLINE_CAPABLE)) == 0 { continue; }

        // Per-AP kernel stack + per-CPU page (leaked; live for boot).
        let stack: Box<[u8]> = alloc::vec![0u8; AP_STACK_BYTES].into_boxed_slice();
        let stack_top = Box::leak(stack).as_ptr() as u64 + AP_STACK_BYTES as u64;
        let Some(percpu) = pmm::setup::alloc_percpu_page() else { continue; };
        let percpu_base = percpu as u64;
        // SAFETY: per-AP slots within the copied blob; we bring up one
        // AP at a time (wait for online below) so no writer races.
        unsafe {
            core::ptr::write_volatile(tramp.add(stack_off) as *mut u64, stack_top & !0xf);
            core::ptr::write_volatile(tramp.add(percpu_off) as *mut u64, percpu_base);
            core::ptr::write_volatile(tramp.add(cpu_off) as *mut u64, i as u64);
        }

        let before = ::cpu::smp::online_count();
        let vec = (TRAMP_PA >> 12) as u8;
        // SAFETY: LAPIC enabled by the BSP; INIT then two SIPIs per Intel
        // SDM Vol 3 §8.4.4.1; wait_icr_idle bounds each delivery.
        unsafe {
            crate::lapic::write_icr(id, crate::lapic::icr_lo_init_assert());
            crate::lapic::wait_icr_idle();
            crate::lapic::busy_wait_us(10_000);
            crate::lapic::write_icr(id, crate::lapic::icr_lo_sipi(vec));
            crate::lapic::wait_icr_idle();
            crate::lapic::busy_wait_us(200);
            crate::lapic::write_icr(id, crate::lapic::icr_lo_sipi(vec));
            crate::lapic::wait_icr_idle();
        }
        // Wait (bounded) for the AP to increment the online count.
        let mut spins = 0u32;
        while ::cpu::smp::online_count() == before && spins < 50_000_000 {
            spins = spins.wrapping_add(1);
            // SAFETY: pause is a microarch hint, no side effects.
            unsafe { core::arch::asm!("pause", options(nomem, nostack, preserves_flags)); }
        }
        if ::cpu::smp::online_count() > before {
            started += 1;
        } else {
        }
    }
    started
}
