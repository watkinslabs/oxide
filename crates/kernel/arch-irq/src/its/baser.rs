use core::sync::atomic::Ordering;

use super::regs::{GITS_BASER0, GITS_TABLE_PAGE_BYTES, ITS_VA};

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
const BASER_IC_NC:    u64 = 1 << 59;
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
        let pa = match pmm::setup::alloc_raw_frame() {
            Some(p) => p,
            None    => { slots_out[i] = slot; continue; }
        };
        if hhdm != 0 {
            let va = hhdm.wrapping_add(pa) as *mut u64;
            // SAFETY: HHDM-mapped freshly-allocated PMM frame; aligned u64 stores within 4 KiB.
            unsafe {
                for j in 0..(GITS_TABLE_PAGE_BYTES / 8) {
                    core::ptr::write_volatile(va.add(j), 0);
                }
            }
            crate::cache::clean_to_poc(hhdm.wrapping_add(pa), GITS_TABLE_PAGE_BYTES);
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
