// x86_64 AP real-mode → long-mode startup trampoline (Limine-free).
//
// SIPI starts each AP in 16-bit real mode at CS:IP = (page<<8):0 where
// `page` is the SIPI vector (we use PA 0x8000 → page 0x08). Limine used to
// run this transition for us; with Limine gone the kernel owns it.
//
// The blob is linked into the kernel (high VA) but COPIED to PA 0x8000 at
// runtime, so it is fully relocatable: it derives its own physical base from
// `CS << 4` (= 0x8000) and patches the GDTR base + the far-jump pointers at
// runtime. Per-AP parameters (kernel CR3, stack top, 64-bit entry VA,
// SmpInfoX86 ptr) are written by the boot CPU into a fixed block at
// `0x8000 + AP_PARAM_OFF` before each SIPI.
//
// Layout in the copied page (all offsets from 0x8000):
//   0x000  trampoline code (16→32→64-bit) + embedded GDT/GDTR/far-ptrs
//   AP_PARAM_OFF (0x0F00)  ApBootParams { cr3, stack_top, entry, info }
//
// Intel SDM Vol 3 §8.4 (MP init) + §10.4.4 (INIT-SIPI-SIPI).

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

/// Physical address the trampoline is copied to (must be < 1 MiB, page
/// aligned; the SIPI vector is `TRAMP_PA >> 12`).
pub const TRAMP_PA: u64 = 0x8000;
/// SIPI startup-page vector (TRAMP_PA >> 12).
pub const TRAMP_PAGE: u8 = (TRAMP_PA >> 12) as u8;
/// Offset (within the copied page) of the per-AP parameter block.
pub const AP_PARAM_OFF: u64 = 0x0F00;

/// Per-AP parameters the trampoline reads MMU-/paging-off from low memory.
/// `#[repr(C)]`, offsets are load-bearing (the asm indexes them by constant).
#[repr(C)]
pub struct ApBootParams {
    pub cr3:       u64, // 0x00  kernel PML4 physical address (BSP read_cr3)
    pub stack_top: u64, // 0x08  per-AP kernel stack top (16-byte aligned)
    pub entry:     u64, // 0x10  oxide_ap_entry_x86 virtual address
    pub info:      u64, // 0x18  &SmpInfoX86 (passed in rdi)
}

core::arch::global_asm!(
    r#"
.intel_syntax noprefix
.section .text.ap_tramp, "ax"
.code16
.global ap_tramp_start
.global ap_tramp_end
ap_tramp_start:
    cli
    cld
    # DS = CS (= 0x0800) so [disp16] reads our copied page (DS<<4 = 0x8000).
    mov ax, cs
    mov ds, ax

    # Load the GDT (base + far-ptr targets are hardcoded to 0x8000-relative
    # absolute addresses in the data below — no runtime patching needed since
    # the copy target TRAMP_PA is fixed).
    lgdt [OFF_GDTR]

    # Enter protected mode.
    mov eax, cr0
    or  eax, 1
    mov cr0, eax

    # Far jump to 32-bit code: 0x66 (32-bit offset) FF /5 ModRM 0x2E
    # (mod=00 rm=110 = disp16) → ljmp DS:[OFF_FAR32] (m16:32 far ptr).
    .byte 0x66
    .byte 0xFF
    .byte 0x2E
    .word OFF_FAR32

.code32
prot32:
    mov ax, 0x10          # 32-bit flat data selector
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax

    # Enable PAE (CR4.PAE, bit 5).
    mov eax, cr4
    or  eax, (1 << 5)
    mov cr4, eax

    # CR3 = kernel PML4 phys (low 32 bits — PML4 < 4 GiB). Absolute addr
    # (32-bit flat, DS base 0, paging off → physical 0x8F00).
    mov eax, [0x8F00]     # ApBootParams.cr3 low dword
    mov cr3, eax

    # EFER.LME (bit 8) + EFER.NXE (bit 11). NXE is REQUIRED: the kernel page
    # tables set the NX bit (63) on data/MMIO pages; with NXE off that bit is
    # RESERVED → any access to an NX page faults (#PF reserved-bit). The BSP
    # enables NXE at boot; the AP must match or it faults on the first LAPIC
    # MMIO / data access in oxide_ap_entry_x86.
    mov ecx, 0xC0000080
    rdmsr
    or  eax, (1 << 8) | (1 << 11)
    wrmsr

    # Enable paging (CR0.PG, bit 31) — activates long mode (compat).
    mov eax, cr0
    or  eax, (1 << 31)
    mov cr0, eax

    # Far jump to 64-bit code: FF /5 ModRM 0x2D (mod=00 rm=101 = disp32) →
    # ljmp [ABS_FAR64] (m16:32 far ptr, sel 0x18 → L=1).
    .byte 0xFF
    .byte 0x2D
    .long ABS_FAR64

.code64
long64:
    # Load the 64-bit params (absolute low addresses; identity-mapped).
    mov rsp, [0x8F08]    # ApBootParams.stack_top
    mov rdi, [0x8F18]    # ApBootParams.info → rdi (1st arg)
    mov rax, [0x8F10]    # ApBootParams.entry
    jmp rax              # → oxide_ap_entry_x86 (loads the kernel GDT first)

.align 8
ap_gdt:
    .quad 0x0000000000000000      # 0x00 null
    .quad 0x00CF9A000000FFFF      # 0x08 32-bit code (G,D,P,DPL0,exec/read)
    .quad 0x00CF92000000FFFF      # 0x10 32-bit data (G,B,P,DPL0,read/write)
    .quad 0x00209A0000000000      # 0x18 64-bit code (L,P,DPL0,code)
    .quad 0x0000920000000000      # 0x20 64-bit data
ap_gdt_end:

ap_gdtr:
    .word ap_gdt_end - ap_gdt - 1            # limit
    .long 0x8000 + ap_gdt - ap_tramp_start   # base (hardcoded, TRAMP_PA fixed)

far32_ptr:
    .long 0x8000 + prot32 - ap_tramp_start   # 32-bit offset
    .word 0x08                               # selector

far64_ptr:
    .long 0x8000 + long64 - ap_tramp_start   # 64-bit-mode jump offset
    .word 0x18                               # selector

# Offset constants for the bracketed memory operands (single value each).
.set OFF_GDTR,   ap_gdtr   - ap_tramp_start
.set OFF_FAR32,  far32_ptr - ap_tramp_start
.set ABS_FAR64,  0x8000 + far64_ptr - ap_tramp_start

.global ap_tramp_end
ap_tramp_end:
.att_syntax prefix
"#
);

extern "C" {
    /// First byte of the trampoline blob (kernel VA).
    pub static ap_tramp_start: u8;
    /// One past the last byte of the trampoline blob (kernel VA).
    pub static ap_tramp_end: u8;
}

use crate::smp_x86::{ApContext, SmpInfoX86};
use alloc::boxed::Box;

const AP_STACK_BYTES: usize = 16 * 1024;

/// Busy-wait `ns` nanoseconds on the monotonic clock (for INIT-SIPI timing).
/// # SAFETY: reads the monotonic counter only; no memory effects.
/// # C: O(ns / poll)
unsafe fn busy_wait_ns(ns: u64) {
    use hal::TimerOps;
    let start = hal_x86_64::X86TimerOps::monotonic_ns().0;
    while hal_x86_64::X86TimerOps::monotonic_ns().0.wrapping_sub(start) < ns {
        core::hint::spin_loop();
    }
}

/// Boot-CPU AP startup via INIT-SIPI-SIPI (Limine-free). Identity-maps the
/// trampoline page in the current (kernel) AS, copies the blob there, then for
/// each enabled non-BSP CPU in `cpu_topology` (filled by the ACPI MADT LAPIC
/// walk): allocates a stack + per-CPU page + `SmpInfoX86`/`ApContext`, writes
/// the `ApBootParams`, and sends INIT then 2×SIPI (Intel SDM §8.4.4.1). Brings
/// CPUs up serially (waits for each to mark itself online) so the single
/// low-memory param block isn't raced. Returns APs released.
///
/// # SAFETY: boot CPU, post-ACPI-walk + post-heap-init; the BSP's CR3 is the
/// live kernel root (the AP shares it via CR3); the LAPIC is enabled.
/// # C: O(N_aps)
pub unsafe fn bring_up_aps_x86_initsipi() -> usize {
    use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
    let n = ::cpu::count();
    if n < 2 { return 0; }
    let hhdm = hal_x86_64::mmu_ops::hhdm_offset();
    if hhdm == 0 { return 0; }
    // Use the BSP's LIVE root as the AP's CR3 so the identity map below (done
    // in the current AS) and the AP's translations share one PML4.
    let cr3 = hal_x86_64::read_cr3() & !0xfffu64;

    // Identity-map the trampoline page in the CURRENT AS: the AP runs there
    // through the CR0.PG transition (compat mode) before the higher-half jump.
    // SAFETY: maps low VA==PA for one page in the (otherwise-empty low half of
    // the) live kernel root; transient + benign (kernel never uses low VAs).
    unsafe {
        <X86Mmu as MmuOps>::map(
            Va(TRAMP_PA), Pa(TRAMP_PA),
            PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC, PageSize::P4K,
        );
    }
    // Copy the blob to PA TRAMP_PA via its HHDM alias.
    let src = core::ptr::addr_of!(ap_tramp_start) as *const u8;
    let end = core::ptr::addr_of!(ap_tramp_end) as *const u8;
    let len = end as usize - src as usize;
    // SAFETY: src..end is the linked trampoline blob; dst is HHDM over PA
    // TRAMP_PA (RAM, <1MB), len bytes, non-overlapping.
    unsafe { core::ptr::copy_nonoverlapping(src, (hhdm + TRAMP_PA) as *mut u8, len); }
    let _ = len;

    let bsp = ::cpu::smp::boot_cpu_id();
    let entry = crate::smp_x86::oxide_ap_entry_x86 as *const () as u64;
    let mut started = 0usize;
    for i in 0..n {
        let (apic_id, flags) = match ::cpu::get(i as usize) { Some(x) => x, None => continue };
        if apic_id == bsp { continue; }
        if flags & (::cpu::FLAG_ENABLED | ::cpu::FLAG_ONLINE_CAPABLE) == 0 { continue; }

        let stack: Box<[u8]> = alloc::vec![0u8; AP_STACK_BYTES].into_boxed_slice();
        let stack_top = ((Box::leak(stack).as_ptr() as u64) + AP_STACK_BYTES as u64) & !0xfu64;
        let percpu: Box<[u8]> = alloc::vec![0u8; 4096].into_boxed_slice();
        let percpu_base = Box::leak(percpu).as_ptr() as u64;
        let ctx = Box::leak(Box::new(ApContext { percpu_base }));
        let info = Box::leak(Box::new(SmpInfoX86 {
            processor_id: apic_id,
            lapic_id:     apic_id,
            reserved:     0,
            goto_address: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            extra_argument: ctx as *const ApContext as u64,
        }));

        // Write the per-AP boot params into the low param block.
        // SAFETY: HHDM over PA TRAMP_PA+AP_PARAM_OFF; ApBootParams fits; sole
        // writer (serial bring-up), AP only reads after the SIPI below.
        unsafe {
            let p = (hhdm + TRAMP_PA + AP_PARAM_OFF) as *mut ApBootParams;
            core::ptr::write_volatile(p, ApBootParams {
                cr3, stack_top, entry, info: info as *const SmpInfoX86 as u64,
            });
        }

        let before = ::cpu::smp::online_count();
        // INIT, wait 10ms, SIPI, wait 200µs, SIPI (Intel SDM §8.4.4.1).
        // SAFETY: LAPIC enabled; INIT-then-SIPI is the correct sequence; IRQs
        // masked on the boot CPU here so wait_icr_idle's poll is sound.
        unsafe {
            let _ = crate::lapic::write_icr(apic_id, crate::lapic::icr_lo_init_assert());
            busy_wait_ns(10_000_000);
            let _ = crate::lapic::write_icr(apic_id, crate::lapic::icr_lo_sipi(TRAMP_PAGE));
            busy_wait_ns(200_000);
            let _ = crate::lapic::write_icr(apic_id, crate::lapic::icr_lo_sipi(TRAMP_PAGE));
        }
        // Wait up to ~200ms for the AP to mark itself online.
        let deadline_start = { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 };
        loop {
            if ::cpu::smp::online_count() > before {
                started += 1;
                break;
            }
            use hal::TimerOps;
            if hal_x86_64::X86TimerOps::monotonic_ns().0.wrapping_sub(deadline_start) > 200_000_000 {
                break; // AP didn't come up; move on
            }
            core::hint::spin_loop();
        }
    }
    started
}

use hal_x86_64::mmu_ops::X86Mmu;
