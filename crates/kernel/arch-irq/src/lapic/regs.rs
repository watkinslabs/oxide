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

// Architectural offsets and field encodings live in `crate::apicdef`, ungated
// so the suspend/resume state machine can be tested on the host. Re-exported
// here under the names this module's callers already use.
#[cfg(target_arch = "x86_64")]
pub(super) use crate::apicdef::{
    REG_ID, REG_VERSION, REG_SVR, REG_LVT_TIMER, REG_TIMER_INIT, REG_TIMER_CUR,
    REG_TIMER_DIV, SVR_ENABLE,
};
#[cfg(target_arch = "x86_64")]
use crate::apicdef::{REG_EOI, REG_ICR_LO};

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
/// First x2APIC register MSR. Each 16-byte LAPIC register slot has one MSR.
#[cfg(target_arch = "x86_64")]
const MSR_X2APIC_ICR: u32 = 0x830;
/// xAPIC's ICR-high destination field is only eight bits wide.
#[cfg(target_arch = "x86_64")]
const XAPIC_DESTINATION_MAX: u32 = u8::MAX as u32;

/// Whether an APIC ID can be represented by the active ICR format. # C: O(1)
#[cfg(target_arch = "x86_64")]
const fn icr_destination_fits(x2apic: bool, destination: u32) -> bool {
    x2apic || destination <= XAPIC_DESTINATION_MAX
}


/// True iff EOI must go through the x2APIC EOI MSR (0x80B) instead of the xAPIC
/// MMIO register at `LAPIC_VA+0xB0`. GAP-2 hardening: an MSR EOI never
/// page-walks the active root, so a stale/clobbered user-root PML4 can't fault
/// the EOI. Set by `enable`/`enable_for_ap` ONLY when firmware already put the
/// CPU in x2APIC mode (see those fns for why we don't flip the mode ourselves).
#[cfg(target_arch = "x86_64")]
static X2APIC_EOI: AtomicBool = AtomicBool::new(false);
/// BSP-selected x2APIC mode, consumed by every AP before it programs LAPIC state.
#[cfg(target_arch = "x86_64")]
static X2APIC_REQUESTED: AtomicBool = AtomicBool::new(false);

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

/// Select the full local-APIC register interface for this CPU. Firmware that
/// entered x2APIC mode disables the MMIO aperture, so every register access
/// must use the paired x2APIC MSR instead. This kernel consumes that firmware
/// mode but does not select it itself.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub(super) fn select_eoi_path() {
    // SAFETY: rdmsr on IA32_APIC_BASE is privileged but legal at CPL=0; pure read.
    let base = unsafe { rdmsr(MSR_IA32_APIC_BASE) };
    if x2apic_supported() && (base & APIC_X2_ENABLE) != 0 {
        X2APIC_EOI.store(true, Ordering::Release);
    }
}

/// True when this CPU's local APIC is addressed through MSRs rather than the
/// memory-mapped window. Firmware may leave a CPU in that mode; this kernel
/// never selects it. Every path that touches a local-APIC register has to ask,
/// because the memory-mapped window is DISABLED in that mode and a write
/// through it is silently lost.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub(crate) fn x2apic_active() -> bool { X2APIC_EOI.load(Ordering::Acquire) }

/// Returns whether bare-metal x2APIC transport can be selected.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub(crate) const fn x2apic_permitted(cpu_supports: bool, remap_x2apic: bool) -> bool { cpu_supports && remap_x2apic }

/// Selects x2APIC MSR transport on this CPU after interrupt remapping permits it.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub(crate) fn enable_x2apic_transport(remap_x2apic: bool) -> bool {
    if !x2apic_permitted(x2apic_supported(), remap_x2apic) { return false; }
    // SAFETY: BSP runs this before AP startup; IA32_APIC_BASE permits the architected x2APIC mode transition.
    unsafe { let base = rdmsr(MSR_IA32_APIC_BASE); wrmsr(MSR_IA32_APIC_BASE, base | APIC_GLOBAL_ENABLE | APIC_X2_ENABLE); }
    X2APIC_REQUESTED.store(true, Ordering::Release); select_eoi_path(); true
}

/// Enters the BSP-selected x2APIC mode on an AP before local register access.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub(crate) fn enable_x2apic_for_ap() -> bool {
    if !X2APIC_REQUESTED.load(Ordering::Acquire) { return false; }
    if !x2apic_supported() { return false; }
    // SAFETY: this AP is the sole writer of its IA32_APIC_BASE before LAPIC initialization.
    unsafe { let base = rdmsr(MSR_IA32_APIC_BASE); wrmsr(MSR_IA32_APIC_BASE, base | APIC_GLOBAL_ENABLE | APIC_X2_ENABLE); }
    select_eoi_path(); true
}

/// Mapped kernel VA after `enable` runs. `0` until then.
#[cfg(target_arch = "x86_64")]
pub static LAPIC_BASE_VA: AtomicU64 = AtomicU64::new(0);

/// Read one local-APIC register through the active architectural interface.
/// # SAFETY: caller runs at CPL 0 after LAPIC access was established; `offset`
/// is a valid 16-byte-aligned local-APIC register offset.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub(crate) unsafe fn read_register(offset: usize) -> Option<u32> {
    if offset & 0xf != 0 || offset >= 4096 { return None; }
    if x2apic_active() {
        // SAFETY: x2APIC mode is active, so this offset has the architected MSR address.
        return Some(unsafe { rdmsr(crate::lapic_shutdown::x2apic_msr_for_offset(offset)?) } as u32);
    }
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return None; }
    // SAFETY: the enabled xAPIC page covers the checked local-APIC register offset.
    Some(unsafe { core::ptr::read_volatile((va + offset as u64) as *const u32) })
}

/// Write one local-APIC register through the active architectural interface.
/// # SAFETY: caller runs at CPL 0 after LAPIC access was established, owns the
/// target register transition, and supplies a valid 16-byte-aligned offset.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub(crate) unsafe fn write_register(offset: usize, value: u32) -> bool {
    if offset & 0xf != 0 || offset >= 4096 { return false; }
    if x2apic_active() {
        let Some(msr) = crate::lapic_shutdown::x2apic_msr_for_offset(offset) else { return false; };
        // SAFETY: x2APIC mode is active, so this offset has the architected MSR address.
        unsafe { wrmsr(msr, value as u64); }
        return true;
    }
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return false; }
    // SAFETY: the enabled xAPIC page covers the checked local-APIC register offset.
    unsafe { core::ptr::write_volatile((va + offset as u64) as *mut u32, value); }
    true
}

/// Write an explicit-destination interrupt-command register value.
/// # SAFETY: caller owns ICR serialization and supplies a valid physical APIC ID.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub(crate) unsafe fn write_icr_register(destination: u32, low: u32) -> bool {
    if x2apic_active() {
        let value = ((destination as u64) << 32) | low as u64;
        // SAFETY: x2APIC ICR is MSR 0x830; caller serialized the command transition.
        unsafe { wrmsr(MSR_X2APIC_ICR, value); }
        return true;
    }
    // xAPIC exposes only destination bits 56:63 through ICR-high. Silently
    // shifting a wider MADT APIC ID would target a different CPU; Linux moves
    // to x2APIC before it can use such IDs. Refuse it until this CPU is in
    // the x2APIC backend instead.
    if !icr_destination_fits(false, destination) { return false; }
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return false; }
    // SAFETY: the enabled xAPIC page covers the ICR high and low register words.
    unsafe {
        core::ptr::write_volatile((va + 0x310) as *mut u32, destination << 24);
        core::ptr::write_volatile((va + REG_ICR_LO as u64) as *mut u32, low);
    }
    true
}

/// Read the interrupt-command register, including x2APIC's destination word.
/// # SAFETY: caller runs at CPL 0 after LAPIC access was established.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub(crate) unsafe fn read_icr_register() -> Option<u64> {
    if x2apic_active() {
        // SAFETY: x2APIC ICR is readable through MSR 0x830 while the mode is active.
        return Some(unsafe { rdmsr(MSR_X2APIC_ICR) });
    }
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return None; }
    // SAFETY: the enabled xAPIC page covers the ICR low register word.
    Some(unsafe { core::ptr::read_volatile((va + REG_ICR_LO as u64) as *const u32) } as u64)
}

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
    // SAFETY: IRQ dispatch owns the EOI transition after this LAPIC was enabled.
    let _ = unsafe { write_register(REG_EOI, 0) };
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub(crate) unsafe fn rdmsr(idx: u32) -> u64 {
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
pub(crate) unsafe fn wrmsr(idx: u32, val: u64) {
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
    // SAFETY: callers only ask after the local APIC was enabled during boot.
    let v = unsafe { read_register(REG_ID) }.unwrap_or(0);
    if x2apic_active() { v } else { v >> 24 }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xapic_rejects_wide_apic_ids_but_x2apic_accepts_them() {
        assert!(icr_destination_fits(false, XAPIC_DESTINATION_MAX));
        assert!(!icr_destination_fits(false, XAPIC_DESTINATION_MAX + 1));
        assert!(icr_destination_fits(true, u32::MAX));
    }
    #[test]
    fn bare_metal_x2apic_requires_remapped_destinations() {
        assert!(!x2apic_permitted(false, true)); assert!(!x2apic_permitted(true, false)); assert!(x2apic_permitted(true, true));
    }
}
