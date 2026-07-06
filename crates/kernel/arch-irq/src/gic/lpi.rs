use core::sync::atomic::{AtomicU64, Ordering};

use super::regs::{GICR_CTLR, GICR_PENDBASER, GICR_PROPBASER, GICR_VA};

// ---- LPI bring-up (F56-04) ------------------------------------------------

/// Number of LPI ID bits we configure. The minimum legal value is
/// 14 on QEMU (LPIs 8192..(1<<14)-1=16383); going lower than the
/// hardware-reported support floor causes GICR_PROPBASER.IDbits to
/// be RAZ/WI. 14 → 16 KiB config table, 2 KiB pending bitmap (but
/// allocation is rounded up to the 64 KiB minimum the architecture
/// mandates for the pending region).
#[cfg(target_arch = "aarch64")]
const LPI_ID_BITS: u32 = 14;

/// PROPBASER bit composition (ARM IHI 0069 §11.4.10):
///   [47:12] PA — alignment ≥ 4 KiB
///   [11:10] Shareability — 0b01 = Inner-Shareable
///   [9:7]   InnerCache  — 0b001 = Normal Inner Non-Cacheable
///   [4:0]   IDbits-1
#[cfg(target_arch = "aarch64")]
const PROPBASER_IC_NC:    u64 = 1 << 7;
#[cfg(target_arch = "aarch64")]
const PROPBASER_INNER_SH: u64 = 1 << 10;

/// PENDBASER bit composition (ARM IHI 0069 §11.4.9):
///   [62]    PTZ — Pending-Table Zero
///   [47:16] PA — 64 KiB aligned
///   [11:10] Shareability
///   [9:7]   InnerCache
#[cfg(target_arch = "aarch64")]
const PENDBASER_PTZ:      u64 = 1 << 62;
#[cfg(target_arch = "aarch64")]
const PENDBASER_IC_NC:    u64 = 1 << 7;
#[cfg(target_arch = "aarch64")]
const PENDBASER_INNER_SH: u64 = 1 << 10;

/// GICR_CTLR.EnableLPI = bit 0. Latched: once set, GICR_PROPBASER and
/// GICR_PENDBASER are RO and the RD begins consuming LPI deliveries.
#[cfg(target_arch = "aarch64")]
const GICR_CTLR_ENABLE_LPI: u32 = 1 << 0;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LpisStatus {
    AlreadyOn,
    AllocFailed,
    Ready {
        prop_pa:        u64,
        pend_pa:        u64,
        propbaser_rd:   u64,
        pendbaser_rd:   u64,
        ctlr_post:      u32,
    },
}

/// Track whether LPIs were enabled on the boot CPU's RD already.
#[cfg(target_arch = "aarch64")]
static LPIS_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// PA of the global LPI configuration table (one byte per LPI).
/// Written by `lpi_set_config` after `lpis_enable` publishes it.
#[cfg(target_arch = "aarch64")]
static LPI_PROP_PA: AtomicU64 = AtomicU64::new(0);

/// First LPI INTID (per ARM ARM, LPIs occupy [8192, 8192 + N)).
#[cfg(target_arch = "aarch64")]
pub const LPI_BASE: u32 = 8192;

/// Default LPI configuration byte: priority 0xA0 + Group1 RES1 +
/// Enable=1. ARM IHI 0069 §11.2.1 byte layout: [7:2] priority,
/// [1] RES1, [0] Enable.
#[cfg(target_arch = "aarch64")]
pub const LPI_PROP_DEFAULT: u8 = 0xA0 | 0x02 | 0x01;

/// Bring up LPIs on the boot CPU's redistributor: allocate +
/// zero the global LPI configuration table (16 KiB) and the per-RD
/// pending table (64 KiB; the architecture-required minimum), program
/// `GICR_PROPBASER` + `GICR_PENDBASER`, then set `GICR_CTLR.EnableLPI`.
///
/// LPI configuration writes after this point require an INV/INVALL
/// command via the ITS to take effect (handled in F56-06+).
///
/// # SAFETY: caller asserts `enable` already published `GICR_VA`,
/// PMM is up, single-CPU pre-init IRQ-off.
/// # C: O(prop_zero + pend_zero) ≈ 80 KiB writes
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn lpis_enable(hhdm: u64) -> LpisStatus {
    use core::sync::atomic::Ordering as O;
    if LPIS_ENABLED.load(O::Acquire) {
        return LpisStatus::AlreadyOn;
    }
    let gicr = GICR_VA.load(Ordering::Acquire);
    if gicr == 0 {
        return LpisStatus::AllocFailed;
    }
    // LPI configuration table size = (1 << ID_BITS) bytes, one
    // priority+enable byte per LPI. ID_BITS=14 → 16 KiB → Order 2.
    // Pending table architecturally requires ≥ 64 KiB → Order 4.
    let prop_pa = match pmm::setup::alloc_contig(pmm::Order(2)) {
        Some(p) => p,
        None    => return LpisStatus::AllocFailed,
    };
    let pend_pa = match pmm::setup::alloc_contig(pmm::Order(4)) {
        Some(p) => p,
        None    => return LpisStatus::AllocFailed,
    };
    if hhdm != 0 {
        // SAFETY: HHDM-mapped contig PMM regions; aligned u64 stores within the region bounds.
        unsafe {
            let prop_va = hhdm.wrapping_add(prop_pa) as *mut u64;
            for i in 0..(0x4000 / 8) {
                core::ptr::write_volatile(prop_va.add(i), 0);
            }
            let pend_va = hhdm.wrapping_add(pend_pa) as *mut u64;
            for i in 0..(0x10000 / 8) {
                core::ptr::write_volatile(pend_va.add(i), 0);
            }
        }
        crate::cache::clean_to_poc(hhdm.wrapping_add(prop_pa), 0x4000);
        crate::cache::clean_to_poc(hhdm.wrapping_add(pend_pa), 0x10000);
    }
    let propbaser = PROPBASER_IC_NC
                  | PROPBASER_INNER_SH
                  | (prop_pa & 0x0000_FFFF_FFFF_F000)
                  | ((LPI_ID_BITS - 1) as u64 & 0x1f);
    let pendbaser = PENDBASER_PTZ
                  | PENDBASER_IC_NC
                  | PENDBASER_INNER_SH
                  | (pend_pa & 0x0000_FFFF_FFFF_0000);
    // SAFETY: GICR RD frame Device-attr mapped via smoke_device_map_arm; offsets within first 4 KiB.
    let (propbaser_rd, pendbaser_rd, ctlr_post) = unsafe {
        core::ptr::write_volatile((gicr + GICR_PROPBASER as u64) as *mut u64, propbaser);
        core::ptr::write_volatile((gicr + GICR_PENDBASER as u64) as *mut u64, pendbaser);
        let p_rd = core::ptr::read_volatile((gicr + GICR_PROPBASER as u64) as *const u64);
        let e_rd = core::ptr::read_volatile((gicr + GICR_PENDBASER as u64) as *const u64);
        let cur = core::ptr::read_volatile((gicr + GICR_CTLR as u64) as *mut u32);
        core::ptr::write_volatile((gicr + GICR_CTLR as u64) as *mut u32, cur | GICR_CTLR_ENABLE_LPI);
        let post = core::ptr::read_volatile((gicr + GICR_CTLR as u64) as *const u32);
        (p_rd, e_rd, post)
    };
    LPI_PROP_PA.store(prop_pa, Ordering::Release);
    LPIS_ENABLED.store(true, O::Release);
    LpisStatus::Ready { prop_pa, pend_pa, propbaser_rd, pendbaser_rd, ctlr_post }
}

/// Write one byte of the LPI configuration table for `lpi_id`. The
/// caller MUST follow with an ITS `INV` (or `INVALL`) command so the
/// ITS reloads the cached entry.
///
/// # SAFETY: `lpis_enable` must have published `LPI_PROP_PA`; HHDM
/// must cover the table; runs single-CPU pre-init.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn lpi_set_config(hhdm: u64, lpi_id: u32, byte: u8) -> bool {
    if lpi_id < LPI_BASE { return false; }
    let prop_pa = LPI_PROP_PA.load(Ordering::Acquire);
    if prop_pa == 0 || hhdm == 0 { return false; }
    let off = (lpi_id - LPI_BASE) as u64;
    // SAFETY: HHDM-mapped LPI prop table; offset within (1 << ID_BITS) bytes.
    unsafe {
        core::ptr::write_volatile(
            hhdm.wrapping_add(prop_pa + off) as *mut u8,
            byte,
        );
    }
    crate::cache::clean_to_poc(hhdm.wrapping_add(prop_pa + off), core::mem::size_of::<u8>());
    true
}
