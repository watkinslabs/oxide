// GICv3 ITS bring-up per `22§5` (aarch64).
//
// The ITS (Interrupt Translation Service) is the GICv3 unit that
// turns PCI MSI/MSI-X writes into LPIs delivered through the
// Redistributor. Devices write 32 bits of EventID to the
// `GITS_TRANSLATER` doorbell (PA = ITS_BASE + 0x0040); the ITS
// looks up `(DeviceID, EventID)` in its device + interrupt-translation
// tables and forwards the resulting LPI INTID to the per-PE pending
// table.
//
// Scope (F56-01): discovery + map + log GITS_TYPER/CTLR. Subsequent
// PRs add command queue, device/collection tables, LPI prop/pend
// tables, GITS_CTLR.Enabled, and the MAPD/MAPC/MAPTI sequence.

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicU64, Ordering};

// ---- GITS register offsets (control frame, first 64 KiB) ------------------

/// GITS_CTLR — bit 0 = Enabled.
#[cfg(target_arch = "aarch64")]
const GITS_CTLR:    usize = 0x0000;
/// GITS_IIDR — implementer/revision.
#[cfg(target_arch = "aarch64")]
const GITS_IIDR:    usize = 0x0004;
/// GITS_TYPER — sized fields for ITT entry, DeviceID/EventID/CIL bits, etc.
#[cfg(target_arch = "aarch64")]
const GITS_TYPER:   usize = 0x0008;
/// GITS_CBASER — command queue base + size.
#[cfg(target_arch = "aarch64")]
const GITS_CBASER:  usize = 0x0080;
/// GITS_CWRITER — driver write index.
#[cfg(target_arch = "aarch64")]
const GITS_CWRITER: usize = 0x0088;
/// GITS_CREADR — ITS read index.
#[cfg(target_arch = "aarch64")]
const GITS_CREADR:  usize = 0x0090;
/// GITS_BASER<n> — device/collection/etc. table descriptors. 8 entries.
#[cfg(target_arch = "aarch64")]
const GITS_BASER0:  usize = 0x0100;

/// GITS_TRANSLATER doorbell offset within the ITS frame. Devices
/// write 32-bit EventID here; the ITS routes the resulting LPI.
#[cfg(target_arch = "aarch64")]
pub const GITS_TRANSLATER: usize = 0x0040;

/// Stash the ITS control-frame VA so MSI-binding code can compute the
/// `GITS_TRANSLATER` PA + ITS commands can post.
#[cfg(target_arch = "aarch64")]
static ITS_VA: AtomicU64 = AtomicU64::new(0);

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
    let base = crate::acpi::GIC_ITS_PA.load(Ordering::Acquire);
    if base == 0 { 0 } else { base + GITS_TRANSLATER as u64 }
}

/// EventID-bits field of GITS_TYPER, [12:8] (ARM IHI 0069 §11.5.13).
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn typer_id_bits(typer: u64) -> u32 { ((typer >> 8) & 0x1f) as u32 + 1 }
/// DeviceID-bits field of GITS_TYPER, [17:13].
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn typer_devbits(typer: u64) -> u32 { ((typer >> 13) & 0x1f) as u32 + 1 }
/// ITT entry-size in bytes, [7:4] (raw value + 1).
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn typer_itt_entry_size(typer: u64) -> u32 { ((typer >> 4) & 0xf) as u32 + 1 }
/// Whether the ITS supports physical LPIs ([0]; always 1 on real GICv3 ITS).
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn typer_phys_lpi(typer: u64) -> bool { (typer & 1) != 0 }
/// Whether the ITS supports virtual LPIs ([1]).
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn typer_virt_lpi(typer: u64) -> bool { (typer & (1 << 1)) != 0 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typer_field_decoders_zero_extend() {
        // typer=0 implies the smallest legal encoding: 1-bit IDs,
        // 1-byte ITT entries, 1-bit DeviceID space.
        assert_eq!(typer_id_bits(0), 1);
        assert_eq!(typer_devbits(0), 1);
        assert_eq!(typer_itt_entry_size(0), 1);
        assert!(!typer_phys_lpi(0));
        assert!(!typer_virt_lpi(0));
    }

    #[test]
    fn typer_field_decoders_qemu_virt() {
        // QEMU virt + GICv3 ITS reports typer=0x000001f0001efb1:
        //   bit0=1 (physical), [7:4]=b=12-byte ITT entry,
        //   [12:8]=15→16 EventID bits, [17:13]=15→16 DeviceID bits.
        let t = 0x000001f0001efb1u64;
        assert!(typer_phys_lpi(t));
        assert!(!typer_virt_lpi(t));
        assert_eq!(typer_itt_entry_size(t), 12);
        assert_eq!(typer_id_bits(t), 16);
        assert_eq!(typer_devbits(t), 16);
    }

    #[test]
    fn status_distinct() {
        let a = ItsStatus::Absent;
        let b = ItsStatus::AlreadyOn;
        let c = ItsStatus::Discovered { typer: 0, ctlr: 0, iidr: 0, baser0: 0 };
        assert_ne!(a, b);
        assert_ne!(b, c);
    }
}
