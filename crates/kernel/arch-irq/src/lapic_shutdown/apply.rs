// The privileged half of the shutdown: the actual register writes.
//
// Thin on purpose. Every value written here is computed by the ungated
// functions in the parent module, which is where the encoding is checked;
// this file only decides WHERE each word goes — the memory-mapped window or
// the MSR range, depending on the mode this CPU's local APIC is in.

#![cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]

use core::sync::atomic::Ordering;

use super::*;
use crate::lapic::regs::{rdmsr, wrmsr, x2apic_active, LAPIC_BASE_VA};

/// First MSR of the local APIC's register range. A register at memory-mapped
/// offset `off` is at `MSR_BASE + (off >> 4)`.
const MSR_BASE: u32 = 0x800;

/// Read one local-APIC register.
/// # SAFETY: the caller runs at CPL 0 and either the memory-mapped window is
/// live or this CPU is in the MSR-addressed mode; `off` names a register.
unsafe fn read(off: usize) -> u32 {
    if x2apic_active() {
        // SAFETY: per fn contract — an MSR read of a local-APIC register at CPL 0 on a CPU in the MSR-addressed mode.
        return unsafe { rdmsr(MSR_BASE + (off >> 4) as u32) } as u32;
    }
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    // SAFETY: per fn contract — `va` is the device-attribute mapping of the local APIC page and `off` lies inside it.
    unsafe { core::ptr::read_volatile((va + off as u64) as *const u32) }
}

/// Write one local-APIC register.
/// # SAFETY: as [`read`], and the caller owns the state being replaced.
unsafe fn write(off: usize, val: u32) {
    if x2apic_active() {
        // SAFETY: per fn contract — an MSR write of a local-APIC register at CPL 0 on a CPU in the MSR-addressed mode.
        unsafe { wrmsr(MSR_BASE + (off >> 4) as u32, val as u64) };
        return;
    }
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    // SAFETY: per fn contract — `va` is the device-attribute mapping of the local APIC page and `off` lies inside it.
    unsafe { core::ptr::write_volatile((va + off as u64) as *mut u32, val) };
}

/// Can this CPU's local APIC be reached at all? A machine whose window was
/// never mapped and which is not in the MSR-addressed mode has no APIC to
/// take down, and touching either path would fault.
/// # C: O(1)
fn reachable() -> bool {
    x2apic_active() || LAPIC_BASE_VA.load(Ordering::Acquire) != 0
}

/// Mask every local-vector-table entry and software-disable the local APIC.
///
/// After this the local APIC asserts nothing. Interrupts must already be
/// masked on this CPU: an entry masked while a delivery is in flight is a
/// delivery into whatever is left of the handler table.
/// # SAFETY: irreversible for this boot; the caller is leaving this kernel.
/// # C: O(1)
pub unsafe fn shutdown() {
    if !reachable() { return; }
    // SAFETY: the register range is reachable per `reachable`; every value below is computed by the parent module's checked encoders.
    unsafe {
        let maxlvt = max_lvt(read(REG_VERSION));
        for (reg, min) in LVT_MASK_ORDER {
            if !lvt_present(maxlvt, min) { continue; }
            write(reg, lvt_masked(read(reg)));
        }
        for (reg, min) in LVT_CLEAN_ORDER {
            if !lvt_present(maxlvt, min) { continue; }
            write(reg, LVT_MASKED);
        }
        // Clearing the error status twice is how the status is actually
        // discarded: the first write arms the update, the read retires it.
        if maxlvt > 3 { write(REG_ERROR_STATUS, 0); }
        let _ = read(REG_ERROR_STATUS);
        write(REG_SPURIOUS, spurious_disabled(read(REG_SPURIOUS)));
    }
}

/// Leave the local APIC in the interrupt mode a machine powers on in: enabled
/// on the low spurious vector, the legacy pin delivering ExtINT and the NMI
/// pin delivering NMI.
///
/// Runs AFTER [`shutdown`], never instead of it. Shutdown is what guarantees
/// no other entry is left asserting; this only re-arms the two pins whatever
/// runs next is entitled to find armed.
/// # SAFETY: as [`shutdown`].
/// # C: O(1)
pub unsafe fn restore_boot_irq_mode() {
    if !reachable() { return; }
    // SAFETY: as `shutdown` — reachable register range, values from the parent module's encoders.
    unsafe {
        write(REG_SPURIOUS, spurious_boot_mode(read(REG_SPURIOUS)));
        write(REG_LVT0, lvt0_boot_mode(read(REG_LVT0)));
        write(REG_LVT1, lvt1_boot_mode(read(REG_LVT1)));
    }
}
