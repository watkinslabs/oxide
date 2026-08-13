//! AQC113 action-resolver transaction owned jointly with resident firmware.

use crate::atl2_mailbox::FilterCaps;

const ART_TOTAL: u8 = 128;
const ART_SECTION_SIZE: u8 = 8;
const ART_L2_PROMISC_OFF: u8 = 0;
const ART_VLAN_PROMISC_OFF: u8 = 1;
const ART_PCP_TO_TC: u8 = 56;
const ART_RECORD_BASE: u64 = 0x14000;
const ART_RECORD_STRIDE: u64 = 0x10;
const ART_SECTIONS: u64 = 0x6ff0;
const CPU_SEMAPHORE: u64 = 0x3ac;
const FILTER_ENABLE: u64 = 0x5104;
const L3_V6_V4_SELECT: u64 = 0x6500;
const L3_V6_V4_SELECT_BIT: u32 = 1 << 23;
const SEMAPHORE_TIMEOUT_NS: u64 = 10_000;
const UNICAST_AND_MULTICAST_MASK: u32 = 0x7f;
const VLAN_AND_UNTAGGED_MASK: u32 = 0x7c00;
const PCP_MASK: u32 = 0xe000_0000;
const ACTION_DROP: u32 = 1;
const ACTION_ASSIGN_TC_ZERO: u32 = 0x181;

pub trait Access { fn read32(&mut self, offset: u64) -> u32; fn write32(&mut self, offset: u64, value: u32); fn now_ns(&mut self) -> u64; fn relax(&mut self); }
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { NoResolverSlots, SemaphoreTimeout }

/// Publishes the firmware-reserved resolver sections and the one-TC receive policy.
/// # C: O(1)
pub fn initialize(access: &mut impl Access, caps: FilterCaps) -> Result<(), Error> {
    let last = caps.art_base.saturating_add(caps.art_count).min(ART_TOTAL);
    if caps.art_base.saturating_add(ART_PCP_TO_TC).saturating_add(8) > last { return Err(Error::NoResolverSlots); }
    let first_section = (caps.art_base / ART_SECTION_SIZE).min(16); let last_section = (last / ART_SECTION_SIZE).min(16);
    let range = section_mask(first_section, last_section); let current = access.read32(ART_SECTIONS); access.write32(ART_SECTIONS, current | range);
    let current = access.read32(L3_V6_V4_SELECT); access.write32(L3_V6_V4_SELECT, current | L3_V6_V4_SELECT_BIT);
    write_record(access, caps.art_base + ART_L2_PROMISC_OFF, 0, UNICAST_AND_MULTICAST_MASK, ACTION_DROP)?;
    write_record(access, caps.art_base + ART_VLAN_PROMISC_OFF, 0, VLAN_AND_UNTAGGED_MASK, ACTION_DROP)?;
    for priority in 0..8 { write_record(access, caps.art_base + ART_PCP_TO_TC + priority, u32::from(priority) << 29, PCP_MASK, ACTION_ASSIGN_TC_ZERO)?; }
    let control = access.read32(FILTER_ENABLE); access.write32(FILTER_ENABLE, control | 1 << 11); Ok(())
}
fn section_mask(first: u8, last: u8) -> u32 { let before_last = if last == 0 { 0 } else { (1u32 << last) - 1 }; let before_first = if first == 0 { 0 } else { (1u32 << first) - 1 }; let mask = before_last & !before_first; if mask == 0 { 0xffff } else { mask } }
fn write_record(access: &mut impl Access, index: u8, tag: u32, mask: u32, action: u32) -> Result<(), Error> {
    let deadline = access.now_ns().saturating_add(SEMAPHORE_TIMEOUT_NS);
    while access.read32(CPU_SEMAPHORE) != 1 { if access.now_ns() >= deadline { return Err(Error::SemaphoreTimeout); } access.relax(); }
    let base = ART_RECORD_BASE + u64::from(index) * ART_RECORD_STRIDE;
    access.write32(base, tag); access.write32(base + 4, mask); access.write32(base + 8, action); access.write32(CPU_SEMAPHORE, 1); Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake { writes: [(u64, u32); 64], count: usize, time: u64 }
    impl Access for Fake { fn read32(&mut self, offset: u64) -> u32 { if offset == CPU_SEMAPHORE { 1 } else if offset == ART_SECTIONS { 0x8000_0000 } else { 0 } } fn write32(&mut self, offset: u64, value: u32) { self.writes[self.count] = (offset, value); self.count += 1; } fn now_ns(&mut self) -> u64 { self.time } fn relax(&mut self) { self.time += 1; } }
    #[test] fn resolver_uses_firmware_range_and_serializes_each_record() {
        let mut fake = Fake { writes: [(0, 0); 64], count: 0, time: 0 }; let caps = FilterCaps { l2_filter_slot: 0, l2_filter_count: 1, art_base: 40, art_count: 64 };
        assert_eq!(initialize(&mut fake, caps), Ok(())); assert_eq!(fake.writes[0], (ART_SECTIONS, 0x8000_1fe0)); assert_eq!(fake.writes[1], (L3_V6_V4_SELECT, L3_V6_V4_SELECT_BIT)); assert_eq!(fake.writes[2..6], [(0x14280, 0), (0x14284, UNICAST_AND_MULTICAST_MASK), (0x14288, ACTION_DROP), (CPU_SEMAPHORE, 1)]); assert_eq!(fake.writes[38..42], [(0x14670, 7 << 29), (0x14674, PCP_MASK), (0x14678, ACTION_ASSIGN_TC_ZERO), (CPU_SEMAPHORE, 1)]); assert_eq!(fake.writes[42], (FILTER_ENABLE, 1 << 11));
    }
    #[test] fn resolver_refuses_a_firmware_range_without_all_required_records() { let mut fake = Fake { writes: [(0, 0); 64], count: 0, time: 0 }; assert_eq!(initialize(&mut fake, FilterCaps { l2_filter_slot: 0, l2_filter_count: 1, art_base: 120, art_count: 8 }), Err(Error::NoResolverSlots)); }
}
