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
/// GITS_CBASER — command queue base + size (64-bit).
#[cfg(target_arch = "aarch64")]
const GITS_CBASER:  usize = 0x0080;
/// GITS_CWRITER — driver write index (64-bit).
#[cfg(target_arch = "aarch64")]
const GITS_CWRITER: usize = 0x0088;
/// GITS_CREADR — ITS read index (64-bit).
#[cfg(target_arch = "aarch64")]
const GITS_CREADR:  usize = 0x0090;

// CBASER bit composition (ARM IHI 0069 §11.5.4):
//   [63]   Valid
//   [58:56] InnerCache  — 0b001 = Normal Inner Non-Cacheable
//   [55:53] OuterCache  — 0b000 = same-as-Inner
//   [47:12] PA bits 47..12 (4 KiB-aligned)
//   [11:10] Shareability — 0b01 = Inner-Shareable
//   [9:8]  PageSize     — 0b00 = 4 KiB
//   [7:0]  Size         — number of 4 KiB pages minus one
#[cfg(target_arch = "aarch64")]
const CBASER_VALID:    u64 = 1 << 63;
#[cfg(target_arch = "aarch64")]
const CBASER_IC_NC:    u64 = 1 << 56;       // Normal Inner Non-Cacheable
#[cfg(target_arch = "aarch64")]
const CBASER_INNER_SH: u64 = 1 << 10;       // Inner-Shareable
#[cfg(target_arch = "aarch64")]
const CBASER_PS_4K:    u64 = 0;             // PageSize=4 KiB
#[cfg(target_arch = "aarch64")]
const CBASER_SIZE_1PG: u64 = 0;             // 1 page (N-1 = 0)
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

/// PA of the 4 KiB command-queue frame, once allocated.
#[cfg(target_arch = "aarch64")]
static CMDQ_PA: AtomicU64 = AtomicU64::new(0);

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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CmdqStatus {
    /// `enable` has not been called yet, or no ITS is present.
    NoIts,
    /// PMM declined the 4 KiB frame.
    AllocFailed,
    /// Already programmed earlier in this boot.
    AlreadyOn,
    /// Programmed. `cbaser_rd` reflects the value the ITS latched
    /// after the write (some bits are RO/RES0). `creadr` should be
    /// 0 immediately after init.
    Ready { cmdq_pa: u64, cbaser_wr: u64, cbaser_rd: u64, creadr: u64 },
}

/// Allocate a 4 KiB command-queue frame, zero it, and program
/// GITS_CBASER + zero CWRITER. Reads back CBASER + CREADR for
/// observation. Does NOT enable the ITS yet (GITS_CTLR untouched).
///
/// Composition follows ARM IHI 0069 §11.5.4: Valid=1, Inner-NC,
/// Inner-Shareable, 4 KiB page, Size=0 (1 page = 128 commands).
///
/// # SAFETY: caller asserts `enable` already published `ITS_VA`,
/// runs single-CPU pre-init IRQ-off, and that PMM is up. The cmd
/// queue frame is owned by the ITS until poweroff (never freed).
/// # C: O(page-zero) ≈ O(4096B)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn cmdq_setup(hhdm: u64) -> CmdqStatus {
    let its_va = ITS_VA.load(Ordering::Acquire);
    if its_va == 0 {
        return CmdqStatus::NoIts;
    }
    if CMDQ_PA.load(Ordering::Acquire) != 0 {
        return CmdqStatus::AlreadyOn;
    }
    let pa = match crate::pmm_setup::alloc_one_frame() {
        Some(p) => p,
        None    => return CmdqStatus::AllocFailed,
    };
    // Zero the frame via HHDM — PMM does not guarantee zero-init,
    // and the ITS treats stale bytes as legitimate command opcodes
    // once GITS_CTLR.Enabled flips on in F56-04.
    if hhdm != 0 {
        let va = hhdm.wrapping_add(pa) as *mut u64;
        // SAFETY: HHDM covers freshly-allocated PMM frame; aligned u64 stores within the 4 KiB page.
        unsafe {
            for i in 0..(0x1000 / 8) {
                core::ptr::write_volatile(va.add(i), 0);
            }
        }
    }
    let cbaser_wr = CBASER_VALID
        | CBASER_IC_NC
        | CBASER_INNER_SH
        | CBASER_PS_4K
        | CBASER_SIZE_1PG
        | (pa & 0x0000_FFFF_FFFF_F000);
    // SAFETY: ITS control frame Device-attr mapped; offsets within the 64 KiB region; 64-bit access widths per spec.
    let (cbaser_rd, creadr) = unsafe {
        core::ptr::write_volatile((its_va + GITS_CBASER  as u64) as *mut u64, cbaser_wr);
        core::ptr::write_volatile((its_va + GITS_CWRITER as u64) as *mut u64, 0);
        (
            core::ptr::read_volatile((its_va + GITS_CBASER as u64) as *const u64),
            core::ptr::read_volatile((its_va + GITS_CREADR as u64) as *const u64),
        )
    };
    CMDQ_PA.store(pa, Ordering::Release);
    CmdqStatus::Ready { cmdq_pa: pa, cbaser_wr, cbaser_rd, creadr }
}

/// PA of the command queue, or 0 if `cmdq_setup` has not run.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn cmdq_pa() -> u64 { CMDQ_PA.load(Ordering::Acquire) }

// ---- GITS_BASER<n> ---------------------------------------------------------

/// Number of GITS_BASER<n> table descriptors (ARM IHI 0069 §11.5.2).
#[cfg(target_arch = "aarch64")]
pub const GITS_BASER_COUNT: usize = 8;

/// `GITS_BASER0` is at +0x100, stride 8 bytes per descriptor.
#[cfg(target_arch = "aarch64")]
const fn baser_off(n: usize) -> u64 { (GITS_BASER0 + n * 8) as u64 }

// BASER bit layout (per IHI 0069 §11.5.2):
//   [63]    Valid
//   [62]    Indirect (0 = flat table)
//   [61:59] InnerCache
//   [58:56] Type     (RO — implementation-defined)
//   [55:48] EntrySize-1 (RO)
//   [47:12] Physical_Address[47:12]
//   [11:10] Shareability
//   [9:8]   PageSize (00=4KB, 01=16KB, 10=64KB)
//   [7:0]   Size (pages-1)
#[cfg(target_arch = "aarch64")]
const BASER_VALID:    u64 = 1 << 63;
#[cfg(target_arch = "aarch64")]
const BASER_IC_NC:    u64 = 1 << 56;
#[cfg(target_arch = "aarch64")]
const BASER_INNER_SH: u64 = 1 << 10;
#[cfg(target_arch = "aarch64")]
const BASER_PS_4K:    u64 = 0;
#[cfg(target_arch = "aarch64")]
const BASER_SIZE_1PG: u64 = 0;
/// PA mask is bits[47:12] = 36 bits.
#[cfg(target_arch = "aarch64")]
const BASER_PA_MASK: u64 = 0x0000_FFFF_FFFF_F000;
/// Mask of fields we OR in (everything except RO Type and EntrySize).
#[cfg(target_arch = "aarch64")]
const BASER_RW_MASK: u64 = BASER_VALID | (1 << 62) | (0x7 << 59) | BASER_PA_MASK | 0xFFF;

/// Programmatic BASER descriptor (Type field).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BaserType {
    Unimplemented = 0,
    Devices       = 1,
    Vpes          = 2,
    Interrupt     = 3,
    Collections   = 4,
}

#[cfg(target_arch = "aarch64")]
fn decode_type(raw: u64) -> BaserType {
    match (raw >> 56) & 0x7 {
        1 => BaserType::Devices,
        2 => BaserType::Vpes,
        3 => BaserType::Interrupt,
        4 => BaserType::Collections,
        _ => BaserType::Unimplemented,
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BaserSlot {
    pub idx: u8,
    pub ty: BaserType,
    pub raw_pre: u64,
    /// 0 if we did not program this slot (Type=Unimplemented).
    pub raw_post: u64,
    /// PA of the table page we allocated (0 if not programmed).
    pub table_pa: u64,
}

/// Program every implemented `GITS_BASER<n>` with a 4 KiB flat
/// table. Skips slots with Type=Unimplemented. PMM-allocates one
/// 4 KiB frame per slot, zeros it via HHDM, and OR-writes the
/// driver-controlled fields (Valid + Inner-NC + Inner-Sh + PageSize=4K
/// + Size=0=1page + PA[47:12]); the read-only Type/EntrySize bits
/// from the register stay intact.
///
/// # SAFETY: caller asserts `cmdq_setup` ran (so `ITS_VA` is set),
/// PMM is up, single-CPU pre-init IRQ-off.
/// # C: O(GITS_BASER_COUNT × page-zero)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn baser_setup(hhdm: u64, slots_out: &mut [BaserSlot; GITS_BASER_COUNT]) -> usize {
    let its_va = ITS_VA.load(Ordering::Acquire);
    let mut programmed = 0usize;
    for i in 0..GITS_BASER_COUNT {
        // SAFETY: ITS control frame Device-attr mapped; offset within 64 KiB region; 64-bit access width.
        let raw = unsafe {
            core::ptr::read_volatile((its_va + baser_off(i)) as *const u64)
        };
        let ty = decode_type(raw);
        let mut slot = BaserSlot { idx: i as u8, ty, raw_pre: raw, raw_post: 0, table_pa: 0 };
        if ty == BaserType::Unimplemented {
            slots_out[i] = slot;
            continue;
        }
        let pa = match crate::pmm_setup::alloc_one_frame() {
            Some(p) => p,
            None    => { slots_out[i] = slot; continue; }
        };
        if hhdm != 0 {
            let va = hhdm.wrapping_add(pa) as *mut u64;
            // SAFETY: HHDM-mapped freshly-allocated PMM frame; aligned u64 stores within 4 KiB.
            unsafe {
                for j in 0..(0x1000 / 8) {
                    core::ptr::write_volatile(va.add(j), 0);
                }
            }
        }
        // Preserve Type + EntrySize (RO); OR in driver-controlled fields.
        let new_raw = (raw & !BASER_RW_MASK)
                    | BASER_VALID
                    | BASER_IC_NC
                    | BASER_INNER_SH
                    | BASER_PS_4K
                    | BASER_SIZE_1PG
                    | (pa & BASER_PA_MASK);
        // SAFETY: mirror of read above; ITS frame Device-attr mapped; 64-bit write.
        let post = unsafe {
            core::ptr::write_volatile((its_va + baser_off(i)) as *mut u64, new_raw);
            core::ptr::read_volatile((its_va + baser_off(i)) as *const u64)
        };
        slot.raw_post = post;
        slot.table_pa = pa;
        slots_out[i] = slot;
        programmed += 1;
    }
    programmed
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

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn cbaser_compose_layout() {
        // Sample PA = 0x4_0000_1000 (4 KiB-aligned). Composition
        // should set Valid+IC+Sh, place PA in [47:12], and leave
        // Size/PageSize=0.
        let pa: u64 = 0x4_0000_1000;
        let v = CBASER_VALID
              | CBASER_IC_NC
              | CBASER_INNER_SH
              | CBASER_PS_4K
              | CBASER_SIZE_1PG
              | (pa & 0x0000_FFFF_FFFF_F000);
        assert!(v & (1 << 63) != 0);            // Valid
        assert!(v & (1 << 56) != 0);            // Inner-NC
        assert!(v & (1 << 10) != 0);            // Inner-Sh
        assert_eq!(v & 0xFF, 0);                // Size=0
        assert_eq!(v & 0x300, 0);               // PageSize=0
        assert_eq!(v & 0x0000_FFFF_FFFF_F000, pa);
    }
}
