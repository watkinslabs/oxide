// Firmware tables per `33`. Owns ACPI RSDP/XSDT/MADT/HPET/MCFG
// parsing. DT (device-tree) bring-up is a follow-up.
//
// Public surface:
//   - try_log_acpi(rsdp_pa, hhdm)   — boot-time table walk + log
//   - set_add_cpu_hook(f)           — install the kernel-side
//                                     cpu_topology callback fired
//                                     for each MADT CPU entry
//
// The kernel installs `set_add_cpu_hook(cpu_topology::add_cpu)`
// once at boot before invoking try_log_acpi. This decouples the
// ACPI walker (here) from the kernel's cpu-topology registry.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::sync::atomic::{AtomicU64, Ordering};

pub mod acpi;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, Io }

pub type KResult<T> = core::result::Result<T, Error>;

/// Boot-time init reporter. Real walk happens via `try_log_acpi`.
/// # SAFETY: caller is the boot path; pre-init; single-CPU.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> KResult<()> { Ok(()) }

/// Add-cpu hook fired for each MADT entry. Kernel installs the
/// cpu_topology::add_cpu callback at boot.
pub type AddCpu = unsafe fn(id: u32, flags: u32) -> bool;

static ADD_CPU_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the per-CPU registration callback. Called once at boot
/// from the kernel before the ACPI walk.
/// # C: O(1)
pub fn set_add_cpu_hook(f: AddCpu) {
    ADD_CPU_HOOK.store(f as u64, Ordering::Release);
}

/// Fire the registered add-cpu callback. No-op when not installed.
/// # SAFETY: forwards to caller-installed hook with the documented signature; only invoked from acpi.rs MADT walk inside an `unsafe { try_log_acpi }`.
/// # C: O(1)
pub unsafe fn fire_add_cpu(id: u32, flags: u32) -> bool {
    let h = ADD_CPU_HOOK.load(Ordering::Acquire);
    if h == 0 { return false; }
    // SAFETY: h was installed by `set_add_cpu_hook` with a matching `unsafe fn(u32,u32)->bool` ABI.
    let f: AddCpu = unsafe { core::mem::transmute(h) };
    // SAFETY: hook ABI matches the documented signature; caller of fire_add_cpu holds the same boot-path preconditions.
    unsafe { f(id, flags) }
}

pub use acpi::try_log_acpi;
pub use acpi::RsdpStatus;

// ---- I/O APIC + legacy-IRQ routing captured from the MADT ----------
// x86 only in practice; arm has no I/O APIC. Populated by decode_madt
// (type 1 = I/O APIC, type 2 = interrupt source override). The kernel
// reads these to program the I/O APIC redirection table for legacy
// device IRQs (e.g. COM1 = IRQ4) — the real interrupt-driven path,
// replacing the timer-tick UART poll.

use core::sync::atomic::AtomicU32;

static IOAPIC_PA: AtomicU64 = AtomicU64::new(0);
static IOAPIC_GSI_BASE: AtomicU32 = AtomicU32::new(0);
// IRQ source override for legacy COM1 IRQ4. Defaults: identity GSI 4,
// flags 0 = ISA bus-default (edge-triggered, active-high). QEMU q35
// leaves IRQ4 un-overridden; we still parse type-2 in case it isn't.
static IRQ4_GSI: AtomicU32 = AtomicU32::new(4);
static IRQ4_FLAGS: AtomicU32 = AtomicU32::new(0);
// ACPI SPCR (Serial Port Console Redirection) — the firmware-elected
// serial console. Absent ⇒ no firmware serial console (a driver may
// still legacy-probe COM1). `addr_space`: 0=SystemMemory (MMIO),
// 1=SystemIO (x86 port). docs/35 / Microsoft SPCR 4.0.
static SPCR_PRESENT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static SPCR_BASE: AtomicU64 = AtomicU64::new(0);
static SPCR_ADDR_SPACE: AtomicU32 = AtomicU32::new(0);
static SPCR_GSI: AtomicU32 = AtomicU32::new(0);

/// Physical base of the first I/O APIC (0 = none found / pre-ACPI).
/// # C: O(1)
pub fn ioapic_pa() -> u64 { IOAPIC_PA.load(Ordering::Acquire) }
/// GSI base of the first I/O APIC. # C: O(1)
pub fn ioapic_gsi_base() -> u32 { IOAPIC_GSI_BASE.load(Ordering::Acquire) }
/// GSI that legacy COM1 IRQ4 is routed to (after source overrides).
/// # C: O(1)
pub fn irq4_gsi() -> u32 { IRQ4_GSI.load(Ordering::Acquire) }
/// MADT flags (polarity/trigger) for the COM1 IRQ4 routing. # C: O(1)
pub fn irq4_flags() -> u32 { IRQ4_FLAGS.load(Ordering::Acquire) }
/// True if firmware published an SPCR serial console. # C: O(1)
pub fn spcr_present() -> bool { SPCR_PRESENT.load(Ordering::Acquire) }
/// SPCR console UART base (MMIO PA or x86 I/O port per `spcr_addr_space`). # C: O(1)
pub fn spcr_base() -> u64 { SPCR_BASE.load(Ordering::Acquire) }
/// SPCR address space: 0=SystemMemory (MMIO), 1=SystemIO (port). # C: O(1)
pub fn spcr_addr_space() -> u32 { SPCR_ADDR_SPACE.load(Ordering::Acquire) }
/// SPCR console interrupt GSI (0 = none / poll-only). # C: O(1)
pub fn spcr_gsi() -> u32 { SPCR_GSI.load(Ordering::Acquire) }
/// Record the firmware-elected SPCR serial console (first wins). # C: O(1)
pub(crate) fn set_spcr(base: u64, addr_space: u8, gsi: u32) {
    if SPCR_PRESENT.swap(true, Ordering::AcqRel) { return; }
    SPCR_BASE.store(base, Ordering::Release);
    SPCR_ADDR_SPACE.store(addr_space as u32, Ordering::Release);
    SPCR_GSI.store(gsi, Ordering::Release);
}

/// Record the first I/O APIC from the MADT (first wins). # C: O(1)
pub(crate) fn set_ioapic(pa: u32, gsi_base: u32) {
    if IOAPIC_PA.compare_exchange(0, pa as u64,
        Ordering::AcqRel, Ordering::Acquire).is_ok()
    {
        IOAPIC_GSI_BASE.store(gsi_base, Ordering::Release);
    }
}

/// Record a legacy-IRQ source override (MADT type 2). Only IRQ4
/// (COM1) is tracked today. # C: O(1)
pub(crate) fn set_irq_override(source_irq: u8, gsi: u32, flags: u16) {
    if source_irq == 4 {
        IRQ4_GSI.store(gsi, Ordering::Release);
        IRQ4_FLAGS.store(flags as u32, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // SAFETY: hosted-test path; init has no side effects.
    #[test] fn init_ok() { unsafe { assert!(init().is_ok()); } }
}
