use core::sync::atomic::{fence, Ordering};

const ENTRIES: u16 = 512;
const PAGE_BYTES: u64 = 4096;
const IRTE_VALID: u32 = 1;
const IRTE_DEST_SHIFT: u32 = 8;
const IRTE_VECTOR_SHIFT: u32 = 16;
const LEGACY_IRTE_BYTES: u64 = 4;
const EXTENDED_IRTE_BYTES: u64 = 16;
const EXTENDED_DEST_LO_MASK: u64 = 0x00ff_ffff;
const EXTENDED_DEST_LO_SHIFT: u32 = 8;
const EXTENDED_DEST_HI_SHIFT: u32 = 56;

/// AMD-Vi interrupt-table encoding selected from one unit's extended features.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AmdViIrMode { Legacy, Extended, ExtendedXt }
impl AmdViIrMode {
    /// Decode GA and XT support from the unit extended-feature register. # C: O(1)
    pub const fn from_extended_features(features: u64) -> Self {
        if features & (1 << 7) == 0 { Self::Legacy }
        else if features & (1 << 2) == 0 { Self::Extended }
        else { Self::ExtendedXt }
    }
    /// Whether this format can retain a full x2APIC destination ID. # C: O(1)
    pub const fn x2apic_capable(self) -> bool { matches!(self, Self::ExtendedXt) }
    const fn entry_bytes(self) -> u64 { match self { Self::Legacy => LEGACY_IRTE_BYTES, Self::Extended | Self::ExtendedXt => EXTENDED_IRTE_BYTES } }
    const fn allocation_order(self) -> pmm::Order { match self { Self::Legacy => pmm::Order(0), Self::Extended | Self::ExtendedXt => pmm::Order(1) } }
}

/// One DMA-visible legacy-format AMD-Vi interrupt table for a requester.
/// Entries are selected by the device-local MSI/MSI-X event number.
pub struct AmdViIrTable { requester: u16, pa: u64, hhdm_offset: u64, mode: AmdViIrMode }
impl AmdViIrTable {
    /// Allocate one zeroed, page-aligned interrupt table. # C: O(table bytes)
    pub fn new(requester: u16, hhdm_offset: u64, mode: AmdViIrMode) -> Option<Self> {
        if hhdm_offset == 0 { return None; }
        let pa = pmm::setup::alloc_contig(mode.allocation_order())?;
        // SAFETY: the new PMM frame is exclusively owned and covered by the direct map.
        unsafe { core::ptr::write_bytes(hhdm_offset.wrapping_add(pa) as *mut u8, 0, (PAGE_BYTES << mode.allocation_order().0) as usize); }
        Some(Self { requester, pa, hhdm_offset, mode })
    }

    /// Requester ID whose DTE points at this table. # C: O(1)
    pub const fn requester(&self) -> u16 { self.requester }
    /// Physical address passed to DTE word 2. # C: O(1)
    pub const fn pa(&self) -> u64 { self.pa }
    /// Encoding installed in this table. # C: O(1)
    pub const fn mode(&self) -> AmdViIrMode { self.mode }

    /// Publish one fixed-delivery IRTE before invalidating the IRT cache.
    /// # C: O(1)
    pub fn publish(&self, event_id: u32, vector: u8, destination_apic_id: u32) -> Option<u16> {
        let index = u16::try_from(event_id).ok()?;
        if index >= ENTRIES { return None; }
        let va = self.hhdm_offset.wrapping_add(self.pa).wrapping_add(u64::from(index) * self.mode.entry_bytes());
        match self.mode {
            AmdViIrMode::Legacy => {
                let destination = u8::try_from(destination_apic_id).ok()?;
                let value = IRTE_VALID | (u32::from(destination) << IRTE_DEST_SHIFT)
                    | (u32::from(vector) << IRTE_VECTOR_SHIFT);
                // SAFETY: index is in this table's 512-entry allocation and the caller owns its route update.
                unsafe { core::ptr::write_volatile(va as *mut u32, value); }
                fence(Ordering::Release);
            }
            AmdViIrMode::Extended | AmdViIrMode::ExtendedXt => {
                let low = (u64::from(destination_apic_id) & EXTENDED_DEST_LO_MASK) << EXTENDED_DEST_LO_SHIFT;
                let high = u64::from(vector) | (u64::from(destination_apic_id >> 24) << EXTENDED_DEST_HI_SHIFT);
                // SAFETY: the 16-byte entry is in this table; high is visible before low marks it valid.
                unsafe { core::ptr::write_volatile((va + 8) as *mut u64, high); }
                fence(Ordering::Release);
                // SAFETY: the same exclusive entry is now published with its valid bit last.
                unsafe { core::ptr::write_volatile(va as *mut u64, low | u64::from(IRTE_VALID)); }
                fence(Ordering::Release);
            }
        }
        Some(index)
    }
}

#[cfg(test)] mod tests {
    use super::*;

    #[test]
    fn legacy_irte_places_destination_and_vector_in_hardware_fields() {
        let value = IRTE_VALID | (0x2au32 << IRTE_DEST_SHIFT) | (0x71u32 << IRTE_VECTOR_SHIFT);
        assert_eq!(value, 0x0071_2a01);
        assert_eq!(ENTRIES * LEGACY_IRTE_BYTES as u16, 2048);
        assert_eq!(u64::from(ENTRIES) * EXTENDED_IRTE_BYTES, 8192);
    }

    #[test]
    fn extended_mode_tracks_ga_and_xt_capabilities_independently() {
        assert_eq!(AmdViIrMode::from_extended_features(0), AmdViIrMode::Legacy);
        assert_eq!(AmdViIrMode::from_extended_features(1 << 7), AmdViIrMode::Extended);
        assert_eq!(AmdViIrMode::from_extended_features((1 << 7) | (1 << 2)), AmdViIrMode::ExtendedXt);
        assert!(!AmdViIrMode::Legacy.x2apic_capable());
        assert!(!AmdViIrMode::Extended.x2apic_capable());
        assert!(AmdViIrMode::ExtendedXt.x2apic_capable());
    }

    #[test]
    fn extended_irte_splits_a_wide_destination_across_both_words() {
        let destination = 0xab12_3456u32;
        let low = (u64::from(destination) & EXTENDED_DEST_LO_MASK) << EXTENDED_DEST_LO_SHIFT | u64::from(IRTE_VALID);
        let high = u64::from(0x71u8) | (u64::from(destination >> 24) << EXTENDED_DEST_HI_SHIFT);
        assert_eq!(low, 0x0000_0000_1234_5601);
        assert_eq!(high, 0xab00_0000_0000_0071);
    }
}
