// Local APIC bring-up per `22§6` (x86_64 only).
//
// Maps LAPIC's MMIO page (phys typically 0xFEE00000 from MADT) into
// kernel space via the device mapper, asserts IA32_APIC_BASE.E, and
// programs the Spurious Interrupt Vector Register's software-enable
// bit. Reads back the APIC ID + version as a sanity check.
//
// Timer LVT + IRQ wiring rides alongside the IDT vector binding +
// EOI helper that follow this PR.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use core::arch::asm;
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
pub(super) const REG_ID:      usize = 0x020;
#[cfg(target_arch = "x86_64")]
pub(super) const REG_VERSION: usize = 0x030;
#[cfg(target_arch = "x86_64")]
pub(super) const REG_SVR:     usize = 0x0F0;
#[cfg(target_arch = "x86_64")]
pub(super) const REG_LVT_TIMER:  usize = 0x320;
#[cfg(target_arch = "x86_64")]
pub(super) const REG_TIMER_INIT: usize = 0x380;
#[cfg(target_arch = "x86_64")]
pub(super) const REG_TIMER_CUR:  usize = 0x390;
#[cfg(target_arch = "x86_64")]
pub(super) const REG_TIMER_DIV:  usize = 0x3E0;

/// SVR bit 8: APIC software enable.
#[cfg(target_arch = "x86_64")]
pub(super) const SVR_ENABLE:  u32 = 1 << 8;

/// Default spurious-interrupt vector. Lowest 4 bits must be 1 on
/// pre-Pentium-4 hardware; we set 0xFF for compatibility.
#[cfg(target_arch = "x86_64")]
pub(super) const SPURIOUS_VECTOR: u32 = 0xFF;

/// IA32_APIC_BASE MSR (0x1B). Bit 11 = global enable.
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_IA32_APIC_BASE: u32 = 0x1B;
#[cfg(target_arch = "x86_64")]
pub(super) const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
/// IA32_APIC_BASE bit 10 = x2APIC mode (EXTD). When set, the LAPIC is driven
/// entirely through MSRs and the xAPIC MMIO window is DISABLED.
#[cfg(target_arch = "x86_64")]
const APIC_X2_ENABLE: u64 = 1 << 10;
/// x2APIC EOI register MSR (Intel SDM Vol 3 Table 10-6): write 0 to signal EOI.
#[cfg(target_arch = "x86_64")]
const MSR_X2APIC_EOI: u32 = 0x80B;

/// True iff EOI must go through the x2APIC EOI MSR (0x80B) instead of the xAPIC
/// MMIO register at `LAPIC_VA+0xB0`. GAP-2 hardening: an MSR EOI never
/// page-walks the active root, so a stale/clobbered user-root PML4 can't fault
/// the EOI. Set by `enable`/`enable_for_ap` ONLY when firmware already put the
/// CPU in x2APIC mode (see those fns for why we don't flip the mode ourselves).
#[cfg(target_arch = "x86_64")]
static X2APIC_EOI: AtomicBool = AtomicBool::new(false);

/// CPUID.01h:ECX bit 21 — x2APIC supported by this CPU. Detection only; does
/// not imply x2APIC mode is enabled. # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn x2apic_supported() -> bool {
    let ecx: u32;
    // SAFETY: `cpuid` is unprivileged with no memory effects; ebx is preserved
    // across the call (LLVM reserves it), leaf 1 is present on every 64-bit CPU.
    unsafe {
        asm!(
            "push rbx", "cpuid", "pop rbx",
            inout("eax") 1u32 => _,
            out("ecx") ecx,
            out("edx") _,
            options(nostack, preserves_flags),
        );
    }
    (ecx & (1 << 21)) != 0
}

/// Decide the EOI path for this CPU. GAP-2 hardening: if the CPU is ALREADY in
/// x2APIC mode (firmware set IA32_APIC_BASE.EXTD), route EOI through the MSR so
/// it never page-walks. We deliberately do NOT enable x2APIC mode ourselves:
/// this driver drives SVR / ICR (incl. AP INIT-SIPI) / timer / APIC-ID through
/// the xAPIC MMIO window, which x2APIC disables — flipping EXTD here would
/// require a full MSR rewrite of the whole LAPIC + AP-startup path (out of this
/// lane's scope and boot-critical). Under the normal xAPIC boot EXTD is clear,
/// so this leaves EOI on the safe MMIO path; the real GAP-2 fix is the
/// scheduler `active_mm` refcount, which removes the underlying use-after-free.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub(super) fn select_eoi_path() {
    // SAFETY: rdmsr on IA32_APIC_BASE is privileged but legal at CPL=0; pure read.
    let base = unsafe { rdmsr(MSR_IA32_APIC_BASE) };
    if x2apic_supported() && (base & APIC_X2_ENABLE) != 0 {
        X2APIC_EOI.store(true, Ordering::Release);
    }
}

/// Mapped kernel VA after `enable` runs. `0` until then.
#[cfg(target_arch = "x86_64")]
pub static LAPIC_BASE_VA: AtomicU64 = AtomicU64::new(0);

/// Send EOI to the LAPIC. No-op if `enable` hasn't run.
/// # SAFETY: pair with an in-progress IRQ; writes EOI at offset 0xB0.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn eoi() {
    // x2APIC mode (GAP-2 hardening): EOI via MSR 0x80B never page-walks the
    // active root, so a stale/clobbered user-root PML4 can't fault it. Only
    // taken when the CPU is actually in x2APIC mode (see `select_eoi_path`).
    if X2APIC_EOI.load(Ordering::Acquire) {
        // SAFETY: wrmsr on the x2APIC EOI MSR is legal at CPL=0 in x2APIC mode; writing 0 signals EOI per Intel SDM Vol 3.
        unsafe { wrmsr(MSR_X2APIC_EOI, 0); }
        return;
    }
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return; }
    // SAFETY: per fn contract -- `va` is a Device-attr 4 KiB mapping; offset 0xB0 lies within.
    unsafe { core::ptr::write_volatile((va + 0xB0) as *mut u32, 0); }
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub(super) unsafe fn rdmsr(idx: u32) -> u64 {
    let lo: u32; let hi: u32;
    // SAFETY: rdmsr at CPL=0 with valid MSR index; no memory effect.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") idx,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub(super) unsafe fn wrmsr(idx: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: wrmsr at CPL=0 with valid MSR index + caller-validated value; no memory effect.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") idx,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// This CPU's local APIC ID — LAPIC reg 0x20, bits 24-31 (xAPIC).
/// Used by AP bring-up to identify the BSP (skip self) off the MADT.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub fn local_apic_id() -> u32 {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return 0; }
    // SAFETY: LAPIC page mapped Device-attr by `enable`; reg 0x20 (APIC
    // ID) is within the page; volatile read with no side effects.
    let v = unsafe { core::ptr::read_volatile((va + 0x20) as *const u32) };
    v >> 24
}

/// Rough busy-wait (~`us` µs) for the INIT→SIPI→SIPI hand-off delays
/// (Intel SDM Vol 3 §8.4.4.1). Uncalibrated `pause` spin — QEMU is
/// lenient on AP-startup timing and this only runs during bring-up;
/// avoids depending on a running/calibrated timer (which could hang).
/// # C: O(us)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub fn busy_wait_us(us: u64) {
    let iters = us.saturating_mul(100);
    for _ in 0..iters {
        // SAFETY: `pause` is a microarchitectural hint, no side effects.
        unsafe { core::arch::asm!("pause", options(nomem, nostack, preserves_flags)); }
    }
}
