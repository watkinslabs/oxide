//! IGC queue geometry and MMIO programming contract.

use crate::regs;

pub const RING_COUNT: usize = 256;
pub const RING_MIN: usize = 64;
pub const RING_MAX: usize = 4096;
pub const RING_MULTIPLE: usize = 8;
pub const BUFFER_BYTES: usize = 2048;
pub const ETH_MIN_FRAME: usize = 14;
pub const ETH_MAX_FRAME: usize = 1518;
const RX_HEADER_BYTES: usize = 256;
const SRRCTL_BSIZEPKT_MASK: u32 = 0x7f;
const SRRCTL_BSIZEHDR_MASK: u32 = 0x3f << 8;
const SRRCTL_DESCTYPE_MASK: u32 = 0x7 << 25;
const SRRCTL_DESCTYPE_ADV_ONEBUF: u32 = 1 << 25;
const RXDCTL_PTHRESH: u32 = 8;
const RXDCTL_HTHRESH: u32 = 8 << 8;
const RXDCTL_WTHRESH: u32 = 4 << 16;
const RXDCTL_QUEUE_ENABLE: u32 = 1 << 25;
const TXDCTL_PTHRESH: u32 = 8;
const TXDCTL_HTHRESH: u32 = 1 << 8;
const TXDCTL_WTHRESH: u32 = 16 << 16;
const TXDCTL_QUEUE_ENABLE: u32 = 1 << 25;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct QueuePlan { pub rx_dma: u64, pub tx_dma: u64, pub descriptors: usize }

impl QueuePlan {
    /// Builds a queue plan only for hardware-supported descriptor geometry.
    /// # C: O(1)
    pub const fn new(rx_dma: u64, tx_dma: u64, descriptors: usize) -> Option<Self> {
        if descriptors < RING_MIN || descriptors > RING_MAX || descriptors % RING_MULTIPLE != 0 { return None; }
        Some(Self { rx_dma, tx_dma, descriptors })
    }
    /// Returns RX descriptor-ring bytes for this queue.
    /// # C: O(1)
    pub const fn rx_bytes(self) -> u32 { (self.descriptors * core::mem::size_of::<regs::AdvRxDesc>()) as u32 }
    /// Returns TX descriptor-ring bytes for this queue.
    /// # C: O(1)
    pub const fn tx_bytes(self) -> u32 { (self.descriptors * core::mem::size_of::<regs::AdvTxDesc>()) as u32 }
    /// Returns the SRRCTL value preserving unrelated hardware-owned bits.
    /// # C: O(1)
    pub const fn srrctl(self, current: u32) -> u32 {
        let cleared = current & !(SRRCTL_BSIZEPKT_MASK | SRRCTL_BSIZEHDR_MASK | SRRCTL_DESCTYPE_MASK);
        cleared | (BUFFER_BYTES as u32 / 1024) | ((RX_HEADER_BYTES as u32 / 64) << 8) | SRRCTL_DESCTYPE_ADV_ONEBUF
    }
    /// Returns RXDCTL with the queue-fetch thresholds and enable bit set.
    /// # C: O(1)
    pub const fn rxdctl(self) -> u32 { RXDCTL_PTHRESH | RXDCTL_HTHRESH | RXDCTL_WTHRESH | RXDCTL_QUEUE_ENABLE }
    /// Returns TXDCTL with the queue-fetch thresholds and enable bit set.
    /// # C: O(1)
    pub const fn txdctl(self) -> u32 { TXDCTL_PTHRESH | TXDCTL_HTHRESH | TXDCTL_WTHRESH | TXDCTL_QUEUE_ENABLE }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn queue_geometry_is_bounded_and_multiple_of_eight() {
        assert!(QueuePlan::new(0, 0, 63).is_none()); assert!(QueuePlan::new(0, 0, 64).is_some());
        assert!(QueuePlan::new(0, 0, 65).is_none()); assert!(QueuePlan::new(0, 0, 4096).is_some()); assert!(QueuePlan::new(0, 0, 4104).is_none());
    }
    #[test] fn queue_plan_uses_advanced_descriptor_lengths() {
        let p = QueuePlan::new(0x1234_5678_0000, 0x5678_9abc_0000, RING_COUNT).unwrap();
        assert_eq!(p.rx_bytes(), 4096); assert_eq!(p.tx_bytes(), 4096);
    }
    #[test] fn receive_plan_preserves_unowned_srrctl_bits() {
        let p = QueuePlan::new(0, 0, RING_COUNT).unwrap(); let current = 0x4000_0000 | SRRCTL_BSIZEPKT_MASK | SRRCTL_BSIZEHDR_MASK | SRRCTL_DESCTYPE_MASK;
        assert_eq!(p.srrctl(current), 0x4200_0402); assert_eq!(p.rxdctl(), 0x0204_0808); assert_eq!(p.txdctl(), 0x0210_0108);
    }
}
