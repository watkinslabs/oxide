// VT-d interrupt-remapping table ownership and MSI message encoding.

use crate::vtd_hw::VtdQiDesc;

const IRTE_BYTES: usize = 16;
const IRTE_COUNT: usize = 65536;
const IRTE_TABLE_BYTES: usize = IRTE_BYTES * IRTE_COUNT;
const IRTE_TABLE_ORDER: pmm::Order = pmm::Order(8);
const IRTA_SIZE_64K: u64 = 0xf;
const IRTA_X2APIC_MODE: u64 = 1 << 11;
const MSI_REMAP_ADDRESS: u64 = 0xFEE0_0000;
const MSI_REMAP_FORMAT: u64 = 1 << 4;
const MSI_REMAP_HANDLE_SHIFT: u32 = 5;

/// Hardware-format 16-byte remapped-mode VT-d interrupt entry.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VtdIrte { words: [u64; 2] }

impl VtdIrte {
    /// Build a present MSI IRTE with exact requester-ID verification. # C: O(1)
    pub const fn msi(vector: u8, destination_apic_id: u32, requester_id: u16,
        extended_mode: bool) -> Self {
        let destination = if extended_mode { destination_apic_id } else { destination_apic_id << 8 };
        let low = 1 | (1 << 3) | ((vector as u64) << 16) | ((destination as u64) << 32);
        let high = requester_id as u64 | (2 << 18);
        Self { words: [low, high] }
    }

    /// Return raw hardware words for layout tests. # C: O(1)
    #[cfg(test)]
    pub const fn words(self) -> [u64; 2] { self.words }
}

/// Allocated VT-d interrupt-remapping table.  A 64K-entry table is the
/// architected maximum and matches the IRTA size encoding used by Linux.
pub struct VtdIrTable { pa: u64, hhdm_offset: u64, used: [u64; IRTE_COUNT / 64], extended_mode: bool }

impl VtdIrTable {
    /// Allocate a zeroed 64K-entry table in physically contiguous memory.
    /// # C: O(table bytes)
    pub fn new(hhdm_offset: u64, extended_mode: bool) -> Option<Self> {
        if hhdm_offset == 0 { return None; }
        let pa = pmm::setup::alloc_contig(IRTE_TABLE_ORDER)?;
        // SAFETY: the allocated 1MiB block is exclusively owned by this table.
        unsafe { core::ptr::write_bytes(hhdm_offset.checked_add(pa)? as *mut u8, 0, IRTE_TABLE_BYTES); }
        Some(Self { pa, hhdm_offset, used: [0; IRTE_COUNT / 64], extended_mode })
    }

    /// IRTA register value including table size and EIM selection. # C: O(1)
    pub const fn irta(&self) -> u64 { self.pa | IRTA_SIZE_64K | if self.extended_mode { IRTA_X2APIC_MODE } else { 0 } }

    /// Allocate and publish one MSI IRTE. # C: O(entries)
    pub fn allocate_msi(&mut self, vector: u8, destination_apic_id: u32, requester_id: u16) -> Option<u16> {
        self.allocate(vector, destination_apic_id, requester_id)
    }

    /// Allocate one source-verified IOAPIC IRTE.  IOAPIC pins are encoded in
    /// their remappable RTE subhandle, so the IRTE itself has the same fixed,
    /// edge-delivery form as an MSI entry. # C: O(entries)
    pub fn allocate_ioapic(&mut self, vector: u8, destination_apic_id: u32, source_id: u16) -> Option<u16> {
        self.allocate(vector, destination_apic_id, source_id)
    }

    fn allocate(&mut self, vector: u8, destination_apic_id: u32, requester_id: u16) -> Option<u16> {
        for (word_index, word) in self.used.iter_mut().enumerate() {
            if *word == u64::MAX { continue; }
            let bit = (!*word).trailing_zeros() as usize;
            let index = word_index * 64 + bit;
            *word |= 1u64 << bit;
            let entry = VtdIrte::msi(vector, destination_apic_id, requester_id, self.extended_mode);
            let va = self.hhdm_offset.checked_add(self.pa)?.checked_add((index * IRTE_BYTES) as u64)? as *mut VtdIrte;
            // SAFETY: index is newly reserved and lies within the exclusively owned table.
            unsafe { core::ptr::write_volatile(va, entry); }
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            return u16::try_from(index).ok();
        }
        None
    }

    /// Release an unused IRTE after its interrupt-entry cache has been invalidated.
    /// # C: O(1)
    pub fn release_after_invalidate(&mut self, index: u16) -> bool {
        let index = usize::from(index);
        let word = index / 64;
        let bit = index % 64;
        if self.used[word] & (1u64 << bit) == 0 { return false; }
        let va = match self.hhdm_offset.checked_add(self.pa).and_then(|base| base.checked_add((index * IRTE_BYTES) as u64)) {
            Some(va) => va as *mut VtdIrte,
            None => return false,
        };
        // SAFETY: index belongs to this table and is not reused until this clear completes.
        unsafe { core::ptr::write_volatile(va, VtdIrte { words: [0, 0] }); }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.used[word] &= !(1u64 << bit);
        true
    }
}

/// Remappable MSI address/data for one IRTE. # C: O(1)
pub const fn remapped_msi(index: u16, subhandle: u16) -> (u64, u32) {
    let address = MSI_REMAP_ADDRESS | MSI_REMAP_FORMAT | ((index as u64) << MSI_REMAP_HANDLE_SHIFT);
    (address, subhandle as u32)
}

/// Interrupt-entry-cache invalidation descriptor for one IRTE. # C: O(1)
pub const fn invalidate_irte(index: u16) -> VtdQiDesc {
    VtdQiDesc::interrupt_entry(index, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irte_layout_pins_destination_and_source_verification() {
        let entry = VtdIrte::msi(0x51, 0x1234, 0x9abc, true);
        assert_eq!(core::mem::size_of::<VtdIrte>(), 16);
        assert_eq!(entry.words(), [0x0000_1234_0051_0009, 0x0000_0000_0008_9abc]);
    }

    #[test]
    fn remappable_msi_encodes_the_irte_handle_not_an_apic_destination() {
        assert_eq!(remapped_msi(0x1234, 7), (0xFEE2_4690, 7));
    }
}
