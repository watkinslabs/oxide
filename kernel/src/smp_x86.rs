// x86_64 AP startup via Limine SMP request per `13§11`.
//
// Limine starts every AP in long mode, parks it spinning on
// `SmpInfoX86::goto_address`, and gives us the array of
// `*mut SmpInfoX86` via the SMP response. Boot CPU walks the
// array, wires each non-BSP entry's goto_address to
// `oxide_ap_entry_x86`, and the parked AP jumps in with
// `rdi = &SmpInfoX86`.
//
// AP entry path:
//   1. Read extra_argument from the SmpInfoX86 → ApContext ptr.
//   2. Enable CR4.FSGSBASE (Limine leaves it off per-AP).
//   3. Stamp cpu_id (lapic_id) at offset 0 of the AP's per-CPU
//      page, then set GS_BASE to it via wrgsbase.
//   4. Increment smp::ONLINE via ap_arrived().
//   5. Halt on hlt — real workflows (per-CPU runqueue install,
//      IDT, IRQ unmask) ride alongside the load balancer in
//      P4-17+.

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use alloc::boxed::Box;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::BootInfo;

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
    /// Per-CPU page (cpu_id at offset 0, then scratch).
    pub percpu_base: u64,
}

/// AP-side entry. Limine jumps the parked AP here with
/// `rdi = info` once the boot CPU stores us in `info.goto_address`.
///
/// # SAFETY: caller is Limine; AP is in long mode, kernel AS
/// active, IRQs masked, stack already set up by Limine.
/// # C: O(1)
#[no_mangle]
pub unsafe extern "C" fn oxide_ap_entry_x86(info: *mut SmpInfoX86) -> ! {
    // SAFETY: per fn contract — `info` is the AP's own SmpInfoX86 published by Limine; sole reader/writer for its own slot from this AP.
    let info_ref = unsafe { &mut *info };
    let ctx_ptr  = info_ref.extra_argument as *mut ApContext;
    // SAFETY: ctx_ptr was published by `bring_up_aps_x86` via Box::leak; the box outlives boot.
    let ctx      = unsafe { &*ctx_ptr };
    let lapic_id = info_ref.lapic_id;

    // Enable CR4.FSGSBASE on this AP (Limine leaves it off per-AP).
    // SAFETY: AP runs CPL=0 here; CR4 write is legal; bit 16 enables rd/wrgsbase which we use immediately below.
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {cr4}, cr4", cr4 = out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= 1u64 << 16;
        core::arch::asm!("mov cr4, {cr4}", cr4 = in(reg) cr4, options(nomem, nostack, preserves_flags));
    }

    // Stamp cpu_id at percpu offset 0 + install GS_BASE.
    // SAFETY: ctx.percpu_base is a freshly-allocated 4 KiB page owned by this AP from publish; sole writer is this AP.
    unsafe {
        let pc = ctx.percpu_base as *mut u32;
        core::ptr::write_volatile(pc, lapic_id);
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

    // Install this AP's per-CPU runqueue + idle task per `13§6`.
    // The AP's `this_cpu()` (gs:0) now returns lapic_id; the per-CPU
    // runqueue array indexes by that, so install_default_runqueue
    // populates the AP's slot specifically.
    // SAFETY: AP runs single-threaded for its own slot; GS_BASE just
    // installed; allocator has been brought up by the BSP and is
    // safely shared across CPUs (kalloc uses internal locking).
    unsafe { crate::sched::install_default_runqueue(); }

    // Mark ourselves online.
    let _ = crate::smp::ap_arrived();

    loop {
        // SAFETY: hlt is always legal at CPL=0; idle hint, IRQs masked so we wake only on NMI.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
    }
}

const AP_PERCPU_BYTES: usize = 4096;

/// Boot-CPU AP startup entry. Walks the Limine SMP response,
/// allocates each AP's per-CPU page + ApContext, and stores the
/// kernel entry into `goto_address` so the parked AP jumps in.
///
/// # SAFETY: caller is the boot path post-ACPI-walk;
/// `info.smp_info_array` is the Limine-supplied table or 0;
/// each pointed-to `SmpInfoX86` is owned by Limine for the
/// rest of boot.
/// # C: O(N_aps)
pub unsafe fn bring_up_aps_x86(info: &BootInfo) -> usize {
    if info.smp_info_array == 0 || info.smp_count == 0 { return 0; }
    let table = info.smp_info_array as *const *mut SmpInfoX86;
    let bsp = info.bsp_lapic_id;
    let mut started = 0usize;
    for i in 0..info.smp_count as usize {
        // SAFETY: per fn contract — table is `[*mut SmpInfoX86; smp_count]` owned by Limine; index i is in range.
        let cpu_ptr = unsafe { *table.add(i) };
        if cpu_ptr.is_null() { continue; }
        // SAFETY: cpu_ptr is a Limine-owned SmpInfoX86 alive for the rest of boot.
        let cpu = unsafe { &*cpu_ptr };
        if cpu.lapic_id == bsp { continue; }

        // Allocate the AP's per-CPU page + ApContext.
        let percpu: Box<[u8]> = alloc::vec![0u8; AP_PERCPU_BYTES].into_boxed_slice();
        let percpu_base = Box::leak(percpu).as_ptr() as u64;
        let ctx = Box::leak(Box::new(ApContext { percpu_base }));

        // Publish extra_argument THEN goto_address (the latter is
        // the AP's go signal). Limine reads them with seq-cst
        // semantics so plain stores ordered by Release work.
        // SAFETY: cpu is the AP's parked SmpInfoX86; the AP only reads after we publish goto_address.
        unsafe {
            (*cpu_ptr).extra_argument = ctx as *const ApContext as u64;
        }
        cpu.goto_address.store(
            oxide_ap_entry_x86 as *mut (),
            Ordering::Release,
        );
        started += 1;
    }
    started
}
