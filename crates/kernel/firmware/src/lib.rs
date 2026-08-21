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

extern crate alloc;

pub mod acpi;
pub mod driver_blob;
pub mod fdt;
pub mod psci;
pub mod memreserve;
pub mod smbios;

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
pub type AddCpu = unsafe fn(id: u64, flags: u32, acpi_uid: u32) -> bool;

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
pub unsafe fn fire_add_cpu(id: u64, flags: u32, acpi_uid: u32) -> bool {
    let h = ADD_CPU_HOOK.load(Ordering::Acquire);
    if h == 0 { return false; }
    // SAFETY: h was installed by `set_add_cpu_hook` with the matching CPU hook ABI.
    let f: AddCpu = unsafe { core::mem::transmute(h) };
    // SAFETY: hook ABI matches the documented signature; caller of fire_add_cpu holds the same boot-path preconditions.
    unsafe { f(id, flags, acpi_uid) }
}

pub use acpi::try_log_acpi;
pub use acpi::RsdpStatus;
pub use acpi::poweroff_action;

// ---- I/O APIC + legacy-IRQ routing captured from the MADT ----------
// x86 only in practice; arm has no I/O APIC. Populated by decode_madt
// (type 1 = I/O APIC, type 2 = interrupt source override). The kernel
// reads these to program the I/O APIC redirection table for legacy
// device IRQs (e.g. PS/2 IRQ1, COM1 IRQ4) from the owning driver's probe.

use core::sync::atomic::AtomicU32;

static IOAPIC_PA: AtomicU64 = AtomicU64::new(0);
static IOAPIC_GSI_BASE: AtomicU32 = AtomicU32::new(0);
static IOAPIC_ID: AtomicU32 = AtomicU32::new(u32::MAX);
const MAX_IOAPICS: usize = 8;
/// One MADT-declared I/O APIC. The GSI range upper bound is discovered from
/// the controller version after its MMIO window is mapped.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IoApic { pub id: u8, pub pa: u64, pub gsi_base: u32 }
static IOAPIC_COUNT: AtomicU32 = AtomicU32::new(0);
static IOAPIC_ALL_PA: [AtomicU64; MAX_IOAPICS] = [const { AtomicU64::new(0) }; MAX_IOAPICS];
static IOAPIC_ALL_GSI: [AtomicU32; MAX_IOAPICS] = [const { AtomicU32::new(0) }; MAX_IOAPICS];
static IOAPIC_ALL_ID: [AtomicU32; MAX_IOAPICS] = [const { AtomicU32::new(u32::MAX) }; MAX_IOAPICS];
static HPET_PA: AtomicU64 = AtomicU64::new(0);
static HPET_ID: AtomicU32 = AtomicU32::new(u32::MAX);
const ISA_IRQS: usize = 16;
// Legacy ISA IRQ routing defaults to identity GSI N with ACPI flags 0
// (bus default: edge-triggered, active-high). MADT type-2 source overrides
// replace the relevant slot.
static LEGACY_IRQ_GSI: [AtomicU32; ISA_IRQS] = [
    AtomicU32::new(0),
    AtomicU32::new(1),
    AtomicU32::new(2),
    AtomicU32::new(3),
    AtomicU32::new(4),
    AtomicU32::new(5),
    AtomicU32::new(6),
    AtomicU32::new(7),
    AtomicU32::new(8),
    AtomicU32::new(9),
    AtomicU32::new(10),
    AtomicU32::new(11),
    AtomicU32::new(12),
    AtomicU32::new(13),
    AtomicU32::new(14),
    AtomicU32::new(15),
];
static LEGACY_IRQ_FLAGS: [AtomicU32; ISA_IRQS] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
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
/// MADT APIC ID of the first I/O APIC, if firmware published one. # C: O(1)
pub fn ioapic_id() -> Option<u8> {
    u8::try_from(IOAPIC_ID.load(Ordering::Acquire)).ok()
}
/// Number of complete MADT I/O-APIC records retained at boot. # C: O(1)
pub fn ioapic_count() -> usize { (IOAPIC_COUNT.load(Ordering::Acquire) as usize).min(MAX_IOAPICS) }
/// Return one MADT I/O-APIC record by enumeration order. # C: O(1)
pub fn ioapic(index: usize) -> Option<IoApic> {
    if index >= ioapic_count() { return None; }
    Some(IoApic {
        id: u8::try_from(IOAPIC_ALL_ID[index].load(Ordering::Relaxed)).ok()?,
        pa: IOAPIC_ALL_PA[index].load(Ordering::Relaxed),
        gsi_base: IOAPIC_ALL_GSI[index].load(Ordering::Acquire),
    })
}
/// Physical base of the firmware HPET block (0 = absent or non-MMIO). # C: O(1)
pub fn hpet_pa() -> u64 { HPET_PA.load(Ordering::Acquire) }
/// Firmware HPET block number used to match a DMAR HPET scope. # C: O(1)
pub fn hpet_id() -> Option<u8> { u8::try_from(HPET_ID.load(Ordering::Acquire)).ok() }
/// GSI that legacy ISA IRQ `irq` is routed to after MADT source overrides.
/// Returns `None` for non-ISA IRQ numbers. # C: O(1)
pub fn legacy_irq_gsi(irq: u8) -> Option<u32> {
    let idx = irq as usize;
    if idx < ISA_IRQS {
        Some(LEGACY_IRQ_GSI[idx].load(Ordering::Acquire))
    } else {
        None
    }
}
/// MADT polarity/trigger flags for legacy ISA IRQ `irq`.
/// Returns `None` for non-ISA IRQ numbers. # C: O(1)
pub fn legacy_irq_flags(irq: u8) -> Option<u32> {
    let idx = irq as usize;
    if idx < ISA_IRQS {
        Some(LEGACY_IRQ_FLAGS[idx].load(Ordering::Acquire))
    } else {
        None
    }
}
/// Decode an SCI source override as ACPI does: each compatible field defaults
/// independently to level-triggered and active-low, rather than to the ISA
/// bus defaults used by ordinary legacy IRQs. # C: O(1)
pub fn acpi_sci_characteristics(flags: u32) -> (bool, bool) {
    const FIELD_MASK: u32 = 3;
    const TRIGGER_SHIFT: u32 = 2;
    const LEVEL: u32 = 3;
    const ACTIVE_LOW: u32 = 3;
    let trigger = (flags >> TRIGGER_SHIFT) & FIELD_MASK;
    let polarity = flags & FIELD_MASK;
    (trigger == 0 || trigger == LEVEL, polarity == 0 || polarity == ACTIVE_LOW)
}
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

// ---- FADT reset register ------------------------------------------------
// Only the DERIVED action is latched, never the raw register block: a stored
// descriptor nothing reads is indistinguishable from a bug. `power` is the
// sole consumer, through `reset_action()`.

static RESET_KIND: AtomicU32 = AtomicU32::new(RESET_KIND_NONE);
static RESET_ADDR: AtomicU64 = AtomicU64::new(0);
static RESET_VALUE: AtomicU32 = AtomicU32::new(0);

const RESET_KIND_NONE: u32 = 0;
const RESET_KIND_PORT: u32 = 1;
const RESET_KIND_MMIO: u32 = 2;
const RESET_KIND_PCI: u32 = 3;

/// The reset the FADT authorised, or `None` when firmware published no
/// usable reset register. Reads are safe at any time; the value is written
/// once during the boot-time table walk.
/// # C: O(1)
pub fn reset_action() -> Option<acpi::ResetAction> {
    let value = RESET_VALUE.load(Ordering::Acquire) as u8;
    let addr = RESET_ADDR.load(Ordering::Acquire);
    match RESET_KIND.load(Ordering::Acquire) {
        RESET_KIND_PORT => Some(acpi::ResetAction::PortIo { port: addr as u16, value }),
        RESET_KIND_MMIO => Some(acpi::ResetAction::Mmio { pa: addr, value }),
        RESET_KIND_PCI => Some(acpi::ResetAction::PciConfig {
            device: (addr >> 32) as u8,
            function: (addr >> 40) as u8,
            offset: addr as u16,
            value,
        }),
        _ => None,
    }
}

/// Latch the reset action the FADT decode derived (first wins).
/// # C: O(1)
pub(crate) fn set_reset_action(a: acpi::ResetAction) {
    let (kind, addr, value) = match a {
        acpi::ResetAction::PortIo { port, value } => (RESET_KIND_PORT, port as u64, value),
        acpi::ResetAction::Mmio { pa, value } => (RESET_KIND_MMIO, pa, value),
        acpi::ResetAction::PciConfig { device, function, offset, value } =>
            (RESET_KIND_PCI, ((device as u64) << 32) | ((function as u64) << 40) | offset as u64, value),
    };
    if RESET_KIND.compare_exchange(RESET_KIND_NONE, kind, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        RESET_ADDR.store(addr, Ordering::Release);
        RESET_VALUE.store(value as u32, Ordering::Release);
    }
}

/// Retain the validated FADT registers used to build the terminal S5 action. # C: O(1)
pub(crate) fn set_power_registers(registers: acpi::PowerRegisters) { acpi::set_power_registers(registers); }

/// Record one I/O APIC from the MADT in firmware enumeration order. # C: O(1)
pub(crate) fn set_ioapic(id: u8, pa: u32, gsi_base: u32) {
    if pa == 0 { return; }
    let index = IOAPIC_COUNT.fetch_add(1, Ordering::AcqRel) as usize;
    if index < MAX_IOAPICS {
        IOAPIC_ALL_PA[index].store(pa as u64, Ordering::Relaxed);
        IOAPIC_ALL_GSI[index].store(gsi_base, Ordering::Relaxed);
        IOAPIC_ALL_ID[index].store(id as u32, Ordering::Relaxed);
        IOAPIC_COUNT.store((index + 1) as u32, Ordering::Release);
    } else {
        IOAPIC_COUNT.store(MAX_IOAPICS as u32, Ordering::Release);
    }
    if IOAPIC_PA.compare_exchange(0, pa as u64,
        Ordering::AcqRel, Ordering::Acquire).is_ok()
    {
        IOAPIC_ID.store(id as u32, Ordering::Release);
        IOAPIC_GSI_BASE.store(gsi_base, Ordering::Release);
    }
}

/// Record the first system-memory HPET block (first wins). # C: O(1)
pub(crate) fn set_hpet(id: u8, pa: u64) {
    if pa == 0 { return; }
    if HPET_PA.compare_exchange(0, pa, Ordering::AcqRel, Ordering::Acquire).is_ok() {
        HPET_ID.store(id as u32, Ordering::Release);
    }
}

/// Record a legacy-IRQ source override (MADT type 2). # C: O(1)
pub(crate) fn set_irq_override(source_irq: u8, gsi: u32, flags: u16) {
    let idx = source_irq as usize;
    if idx < ISA_IRQS {
        LEGACY_IRQ_GSI[idx].store(gsi, Ordering::Release);
        LEGACY_IRQ_FLAGS[idx].store(flags as u32, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // SAFETY: hosted-test path; init has no side effects.
    #[test] fn init_ok() { unsafe { assert!(init().is_ok()); } }

    #[test]
    fn sci_compatible_trigger_and_polarity_default_independently() {
        assert_eq!(acpi_sci_characteristics(0), (true, true));
        assert_eq!(acpi_sci_characteristics(3 << 2), (true, true));
        assert_eq!(acpi_sci_characteristics(3), (true, true));
        assert_eq!(acpi_sci_characteristics((1 << 2) | 3), (false, true));
        assert_eq!(acpi_sci_characteristics((3 << 2) | 1), (true, false));
    }
}
