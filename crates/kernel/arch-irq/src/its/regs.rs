// GICv3 ITS bring-up per `22§5` (aarch64).
//
// The ITS (Interrupt Translation Service) is the GICv3 unit that
// turns PCI MSI/MSI-X writes into LPIs delivered through the
// Redistributor. Devices write 32 bits of EventID to the
// `GITS_TRANSLATER` doorbell (PA = ITS_BASE + 0x10040); the ITS
// looks up `(DeviceID, EventID)` in its device + interrupt-translation
// tables and forwards the resulting LPI INTID to the per-PE pending
// table.
//
// Scope (F56-01): discovery + map + log GITS_TYPER/CTLR. Subsequent
// PRs add command queue, device/collection tables, LPI prop/pend
// tables, GITS_CTLR.Enabled, and the MAPD/MAPC/MAPTI sequence.

/// ARM GITS command/table allocation granule mandated by `CBASER.PS_4K`.
pub(crate) const GITS_TABLE_PAGE_BYTES: usize = 0x1000;

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::AtomicU64;

// ---- GITS register offsets (control frame, first 64 KiB) ------------------

/// GITS_CTLR — bit 0 = Enabled.
#[cfg(target_arch = "aarch64")]
pub(super) const GITS_CTLR:    usize = 0x0000;
/// GITS_IIDR — implementer/revision.
#[cfg(target_arch = "aarch64")]
pub(super) const GITS_IIDR:    usize = 0x0004;
/// GITS_TYPER — sized fields for ITT entry, DeviceID/EventID/CIL bits, etc.
#[cfg(target_arch = "aarch64")]
pub(super) const GITS_TYPER:   usize = 0x0008;
/// GITS_CBASER — command queue base + size (64-bit).
#[cfg(target_arch = "aarch64")]
pub(super) const GITS_CBASER:  usize = 0x0080;
/// GITS_CWRITER — driver write index (64-bit).
#[cfg(target_arch = "aarch64")]
pub(super) const GITS_CWRITER: usize = 0x0088;
/// GITS_CREADR — ITS read index (64-bit).
#[cfg(target_arch = "aarch64")]
pub(super) const GITS_CREADR:  usize = 0x0090;

// CBASER bit composition (ARM IHI 0069 §11.5.4):
//   [63]   Valid
//   [61:59] InnerCache  — 0b001 = Normal Inner Non-Cacheable
//   [58:56] OuterCache  — 0b000 = same-as-Inner
//   [47:12] PA bits 47..12 (4 KiB-aligned)
//   [11:10] Shareability — 0b01 = Inner-Shareable
//   [9:8]  PageSize     — 0b00 = 4 KiB
//   [7:0]  Size         — number of 4 KiB pages minus one
#[cfg(target_arch = "aarch64")]
pub(super) const CBASER_VALID:    u64 = 1 << 63;
#[cfg(target_arch = "aarch64")]
pub(super) const CBASER_IC_NC:    u64 = 1 << 59;       // Normal Inner Non-Cacheable
#[cfg(target_arch = "aarch64")]
pub(super) const CBASER_INNER_SH: u64 = 1 << 10;       // Inner-Shareable
#[cfg(target_arch = "aarch64")]
pub(super) const CBASER_PS_4K:    u64 = 0;             // PageSize=4 KiB
#[cfg(target_arch = "aarch64")]
pub(super) const CBASER_SIZE_1PG: u64 = 0;             // 1 page (N-1 = 0)
/// GITS_BASER<n> — device/collection/etc. table descriptors. 8 entries.
#[cfg(target_arch = "aarch64")]
pub(super) const GITS_BASER0:  usize = 0x0100;

/// GITS_TRANSLATER doorbell offset within the ITS translation frame. Devices
/// write 32-bit EventID here; the ITS routes the resulting LPI.
#[cfg(target_arch = "aarch64")]
pub const GITS_TRANSLATER: usize = 0x10040;

/// Stash the ITS control-frame VA so MSI-binding code can compute the
/// `GITS_TRANSLATER` PA + ITS commands can post.
#[cfg(target_arch = "aarch64")]
pub(super) static ITS_VA: AtomicU64 = AtomicU64::new(0);

/// PA of the 4 KiB command-queue frame, once allocated.
#[cfg(target_arch = "aarch64")]
pub(super) static CMDQ_PA: AtomicU64 = AtomicU64::new(0);
