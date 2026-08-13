//! AQC113 queue-register programming order.

use crate::{atl2_queue::QueuePlan, atl2_regs as regs};

const RX_BUFFER_SIZE: u64 = 0x18;
const RX_BUFFER_SIZE_MASK: u32 = 0x1f;
const RX_BUFFER_SIZE_KIB: u32 = 2;
const TX_PATH_CONTROL: u64 = 0x7900;
const TX_LSO_FLAGS_FIRST_MID: u64 = 0x7820;
const TX_LSO_FLAGS_LAST: u64 = 0x7824;
const TX_WRITEBACK_IRQ: u64 = 0x7b40;
const TX_DCA: u64 = 0x8480;
const RX_PATH_CONTROL: u64 = 0x5700;
const RX_RSS_CONTROL: u64 = 0x54c0;
const RX_RSS_HASH_TYPES: u64 = 0x54c8;
const RX_WRITEBACK_IRQ: u64 = 0x5a30;
const RX_DCA: u64 = 0x6180;
const RX_MULTICAST_FILTER: u64 = 0x5250;
const RX_MULTICAST_MASK: u64 = 0x5270;
const RX_VLAN_CONTROL: u64 = 0x5280;
const RX_VLAN_TPID: u64 = 0x5284;
const RX_BROADCAST_CONTROL: u64 = 0x5100;
const L2_FILTER_BASE: u64 = 0x5110;
const L2_FILTER_STRIDE: u64 = 8;
const L2_FILTER_COUNT: u64 = 38;
const L2_FILTER_ENABLE: u32 = 1 << 31;
const L2_FILTER_ACTION_MASK: u32 = 0x0007_0000;
const L2_FILTER_ACTION_HOST: u32 = 1 << 16;
const VLAN_TPID_MASK: u32 = u32::MAX;
const VLAN_TPID_OUTER: u32 = 0x88a8_0000;
const VLAN_TPID_INNER: u32 = 0x0000_8100;
const VLAN_PROMISC: u32 = 1 << 1;
const VLAN_ACCEPT_UNTAGGED: u32 = 1 << 2;
const VLAN_UNTAGGED_ACTION_MASK: u32 = 0x38;
const VLAN_UNTAGGED_ACTION_HOST: u32 = 1 << 3;
const BROADCAST_THRESHOLD_MASK: u32 = 0xffff_0000;
const BROADCAST_ACTION_MASK: u32 = 0x0000_7000;
const BROADCAST_ACTION_HOST: u32 = 1 << 12;
const BROADCAST_THRESHOLD: u32 = 0xffff_0000;
const MULTICAST_TO_HOST: u32 = 0x0001_0fff;

pub trait Access { fn read32(&mut self, offset: u64) -> u32; fn write32(&mut self, offset: u64, value: u32); }

/// Programs the one-traffic-class baseline required before queue zero can carry traffic.
/// # C: O(L2_FILTER_COUNT)
pub fn initialize_paths(access: &mut impl Access) {
    write_bits(access, TX_PATH_CONTROL, 1 << 8, 0); write_bits(access, TX_PATH_CONTROL, 1 << 2, 1 << 2);
    write_bits(access, TX_LSO_FLAGS_FIRST_MID, 0x0fff, 0x0ff6); write_bits(access, TX_LSO_FLAGS_FIRST_MID, 0x0fff_0000, 0x0ff6 << 16); write_bits(access, TX_LSO_FLAGS_LAST, 0x0fff, 0x0f7f);
    write_bits(access, TX_WRITEBACK_IRQ, 1 << 1, 1 << 1); write_bits(access, TX_DCA, 0x8000_000f, 0);
    write_bits(access, RX_PATH_CONTROL, 1 << 8, 0); write_bits(access, RX_PATH_CONTROL, 0x30, 0x10);
    access.write32(RX_RSS_CONTROL, 0); write_bits(access, RX_RSS_HASH_TYPES, 0x1ff, 0x1ff);
    access.write32(RX_MULTICAST_MASK, 0); access.write32(RX_MULTICAST_FILTER, MULTICAST_TO_HOST);
    write_bits(access, RX_VLAN_TPID, VLAN_TPID_MASK, VLAN_TPID_OUTER | VLAN_TPID_INNER);
    write_bits(access, RX_VLAN_CONTROL, VLAN_PROMISC | VLAN_ACCEPT_UNTAGGED | VLAN_UNTAGGED_ACTION_MASK, VLAN_PROMISC | VLAN_ACCEPT_UNTAGGED | VLAN_UNTAGGED_ACTION_HOST);
    write_bits(access, RX_WRITEBACK_IRQ, 1 << 2, 1 << 2); write_bits(access, RX_DCA, 0x8000_000f, 0);
    write_bits(access, RX_BROADCAST_CONTROL, BROADCAST_THRESHOLD_MASK | BROADCAST_ACTION_MASK, BROADCAST_THRESHOLD | BROADCAST_ACTION_HOST);
    for index in 0..L2_FILTER_COUNT { let control = L2_FILTER_BASE + index * L2_FILTER_STRIDE + 4; write_bits(access, control, L2_FILTER_ENABLE | L2_FILTER_ACTION_MASK, L2_FILTER_ACTION_HOST); }
}
fn write_bits(access: &mut impl Access, offset: u64, mask: u32, value: u32) { let current = access.read32(offset); access.write32(offset, current & !mask | value & mask); }

/// Disables queue zero and publishes its descriptor-ring IOVAs and geometry.
/// # C: O(1)
pub fn prepare(access: &mut impl Access, plan: QueuePlan, rx_tail: u32) {
    let rx_control = regs::rx_queue_offset(0) + regs::QUEUE_CONTROL;
    let tx_control = regs::tx_queue_offset(0) + regs::QUEUE_CONTROL;
    let rx_current = access.read32(rx_control); let tx_current = access.read32(tx_control);
    access.write32(rx_control, plan.rx_control(rx_current, false));
    access.write32(tx_control, plan.tx_control(tx_current, false));
    let (rx_low, rx_high) = regs::split_dma(plan.rx_dma); let (tx_low, tx_high) = regs::split_dma(plan.tx_dma);
    access.write32(regs::rx_queue_offset(0) + regs::QUEUE_BASE_LO, rx_low); access.write32(regs::rx_queue_offset(0) + regs::QUEUE_BASE_HI, rx_high);
    access.write32(regs::tx_queue_offset(0) + regs::QUEUE_BASE_LO, tx_low); access.write32(regs::tx_queue_offset(0) + regs::QUEUE_BASE_HI, tx_high);
    let buffer = regs::rx_queue_offset(0) + RX_BUFFER_SIZE;
    let buffer_current = access.read32(buffer);
    access.write32(buffer, buffer_current & !RX_BUFFER_SIZE_MASK | RX_BUFFER_SIZE_KIB);
    access.write32(regs::tx_queue_offset(0) + regs::QUEUE_TAIL, 0);
    access.write32(regs::rx_queue_offset(0) + regs::QUEUE_TAIL, rx_tail);
}

/// Enables queue zero only after descriptor ownership is published to hardware.
/// # C: O(1)
pub fn start(access: &mut impl Access, plan: QueuePlan) {
    let rx_control = regs::rx_queue_offset(0) + regs::QUEUE_CONTROL;
    let tx_control = regs::tx_queue_offset(0) + regs::QUEUE_CONTROL;
    let rx_current = access.read32(rx_control); let tx_current = access.read32(tx_control);
    access.write32(rx_control, plan.rx_control(rx_current, true));
    access.write32(tx_control, plan.tx_control(tx_current, true));
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake { reads: [u32; 64], index: usize, writes: [(u64, u32); 9], count: usize }
    impl Access for Fake {
        fn read32(&mut self, _: u64) -> u32 { let value = self.reads[self.index]; self.index += 1; value }
        fn write32(&mut self, offset: u64, value: u32) { self.writes[self.count] = (offset, value); self.count += 1; }
    }
    fn plan() -> QueuePlan { QueuePlan::new(0x1234_5678_0000, 0x9abc_def0_0000, 2048, 4096).unwrap() }
    #[test] fn prepare_disables_before_iova_publication_and_preserves_controls() {
        let mut fake = Fake { reads: [0; 64], index: 0, writes: [(0, 0); 9], count: 0 }; fake.reads[..3].copy_from_slice(&[0x9000_0000, 0xa000_0000, 0x1000_0000]);
        prepare(&mut fake, plan(), 2047);
        assert_eq!(fake.writes, [(0x5b08, 0x1000_0800), (0x7c08, 0x2000_1000), (0x5b00, 0x5678_0000), (0x5b04, 0x1234), (0x7c00, 0xdef0_0000), (0x7c04, 0x9abc), (0x5b18, 0x1000_0002), (0x7c10, 0), (0x5b10, 2047)]);
    }
    #[test] fn start_enables_only_after_prepare_and_posts_receive_tail() {
        let mut fake = Fake { reads: [0; 64], index: 0, writes: [(0, 0); 9], count: 0 }; fake.reads[..2].copy_from_slice(&[0x1000_0800, 0x2000_1000]);
        start(&mut fake, plan());
        assert_eq!(fake.writes[..2], [(0x5b08, 0x9000_0800), (0x7c08, 0xa000_1000)]);
    }
    #[test] fn baseline_enables_writeback_and_new_receive_filtering_without_rss() {
        struct Paths { writes: [(u64, u32); 64], count: usize }
        impl Access for Paths { fn read32(&mut self, _: u64) -> u32 { 0 } fn write32(&mut self, offset: u64, value: u32) { self.writes[self.count] = (offset, value); self.count += 1; } }
        let mut paths = Paths { writes: [(0, 0); 64], count: 0 }; initialize_paths(&mut paths);
        assert_eq!(paths.count, 56); assert_eq!(paths.writes[0], (TX_PATH_CONTROL, 0)); assert_eq!(paths.writes[1], (TX_PATH_CONTROL, 4)); assert_eq!(paths.writes[7], (RX_PATH_CONTROL, 0)); assert_eq!(paths.writes[9], (RX_RSS_CONTROL, 0)); assert_eq!(paths.writes[11], (RX_MULTICAST_MASK, 0)); assert_eq!(paths.writes[12], (RX_MULTICAST_FILTER, MULTICAST_TO_HOST)); assert_eq!(paths.writes[13], (RX_VLAN_TPID, VLAN_TPID_OUTER | VLAN_TPID_INNER)); assert_eq!(paths.writes[14], (RX_VLAN_CONTROL, VLAN_PROMISC | VLAN_ACCEPT_UNTAGGED | VLAN_UNTAGGED_ACTION_HOST)); assert_eq!(paths.writes[17], (RX_BROADCAST_CONTROL, BROADCAST_THRESHOLD | BROADCAST_ACTION_HOST)); assert_eq!(paths.writes[18], (L2_FILTER_BASE + 4, L2_FILTER_ACTION_HOST)); assert_eq!(paths.writes[55], (L2_FILTER_BASE + 37 * L2_FILTER_STRIDE + 4, L2_FILTER_ACTION_HOST));
    }
}
