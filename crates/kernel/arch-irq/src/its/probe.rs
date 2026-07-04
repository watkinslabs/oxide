use core::sync::atomic::Ordering;

use super::regs::{GITS_BASER0, GITS_CTLR, GITS_IIDR, GITS_TRANSLATER, GITS_TYPER, ITS_VA};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ItsStatus {
    /// MADT reported no ITS (GICv2m or non-ARM). Caller should
    /// fall back to v2m or ISR-poll.
    Absent,
    /// Already brought up earlier in this boot.
    AlreadyOn,
    /// First-time discovery. `typer` and `ctlr` are the raw
    /// post-map register reads (pre-enable).
    Discovered { typer: u64, ctlr: u32, iidr: u32, baser0: u64 },
}

/// Map+probe the ITS control frame. Reads GITS_TYPER/CTLR/BASER0 so
/// callers can size the device + collection tables in a follow-up PR.
/// Does NOT enable the ITS yet (GITS_CTLR.Enabled remains as-is).
///
/// # SAFETY: caller asserts `its_va` is freshly Device-attr-mapped
/// covering at least the first 64 KiB of the ITS control frame; runs
/// single-CPU pre-init, IRQ-off.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn enable(its_va: u64) -> ItsStatus {
    if its_va == 0 {
        return ItsStatus::Absent;
    }
    if ITS_VA.load(Ordering::Acquire) != 0 {
        return ItsStatus::AlreadyOn;
    }
    // SAFETY: VA freshly Device-nGnRnE mapped; offsets stay within the 64 KiB control frame.
    let (typer, ctlr, iidr, baser0) = unsafe {
        (
            core::ptr::read_volatile((its_va + GITS_TYPER  as u64) as *const u64),
            core::ptr::read_volatile((its_va + GITS_CTLR   as u64) as *const u32),
            core::ptr::read_volatile((its_va + GITS_IIDR   as u64) as *const u32),
            core::ptr::read_volatile((its_va + GITS_BASER0 as u64) as *const u64),
        )
    };
    ITS_VA.store(its_va, Ordering::Release);
    ItsStatus::Discovered { typer, ctlr, iidr, baser0 }
}

/// PA of the GITS_TRANSLATER doorbell, computed from the discovered
/// ITS_BASE (MADT type-15). Returns 0 if no ITS was reported.
///
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn translater_pa() -> u64 {
    let base = firmware::acpi::GIC_ITS_PA.load(Ordering::Acquire);
    if base == 0 { 0 } else { base + GITS_TRANSLATER as u64 }
}
