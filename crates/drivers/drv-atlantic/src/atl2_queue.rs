//! AQC113 queue geometry and descriptor-count contract.

use crate::atl2_regs;

pub const QUEUE_COUNT: usize = 4;
pub const RING_MULTIPLE: usize = 8;
pub const RING_MIN: usize = 40;
pub const RING_MAX: usize = 8184;
pub const RX_RING_DEFAULT: usize = 2048;
pub const TX_RING_DEFAULT: usize = 4096;
pub const RX_BUFFER_BYTES: usize = 2048;
pub const ETH_MIN_FRAME: usize = 14;
pub const ETH_MAX_FRAME: usize = 1518;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct QueuePlan { pub rx_dma: u64, pub tx_dma: u64, pub rx_descriptors: usize, pub tx_descriptors: usize }

impl QueuePlan {
    /// Creates an AQC113 queue plan only for supported descriptor geometry.
    /// # C: O(1)
    pub const fn new(rx_dma: u64, tx_dma: u64, rx_descriptors: usize, tx_descriptors: usize) -> Option<Self> {
        if !ring_valid(rx_descriptors) || !ring_valid(tx_descriptors) { return None; }
        Some(Self { rx_dma, tx_dma, rx_descriptors, tx_descriptors })
    }
    /// Encodes RX queue control including its descriptor count and enable state.
    /// # C: O(1)
    pub const fn rx_control(self, current: u32, enable: bool) -> u32 { match atl2_regs::queue_control(current, self.rx_descriptors, enable) { Some(value) => value, None => 0 } }
    /// Encodes TX queue control including its descriptor count and enable state.
    /// # C: O(1)
    pub const fn tx_control(self, current: u32, enable: bool) -> u32 { match atl2_regs::queue_control(current, self.tx_descriptors, enable) { Some(value) => value, None => 0 } }
    /// Returns RX ring allocation bytes.
    /// # C: O(1)
    pub const fn rx_ring_bytes(self) -> usize { self.rx_descriptors * core::mem::size_of::<atl2_regs::RxDesc>() }
    /// Returns TX ring allocation bytes.
    /// # C: O(1)
    pub const fn tx_ring_bytes(self) -> usize { self.tx_descriptors * core::mem::size_of::<atl2_regs::TxDesc>() }
    /// Returns RX backing-buffer allocation bytes.
    /// # C: O(1)
    pub const fn rx_buffer_bytes(self) -> usize { self.rx_descriptors * RX_BUFFER_BYTES }
}

/// Tests whether a ring count is supported by this controller.
/// # C: O(1)
pub const fn ring_valid(descriptors: usize) -> bool { descriptors >= RING_MIN && descriptors <= RING_MAX && descriptors % RING_MULTIPLE == 0 }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn ring_geometry_is_bounded_in_eight_descriptor_units() { assert!(!ring_valid(32)); assert!(ring_valid(40)); assert!(!ring_valid(41)); assert!(ring_valid(8184)); assert!(!ring_valid(8192)); }
    #[test] fn defaults_encode_descriptor_counts_not_ring_bytes() {
        let p = QueuePlan::new(0x1000, 0x2000, RX_RING_DEFAULT, TX_RING_DEFAULT).unwrap();
        assert_eq!(p.rx_control(0x1000_0000, true), 0x9000_0800); assert_eq!(p.tx_control(0x1000_0000, true), 0x9000_1000);
        assert_eq!(p.rx_ring_bytes(), 32768); assert_eq!(p.tx_ring_bytes(), 65536); assert_eq!(p.rx_buffer_bytes(), 4 * 1024 * 1024);
    }
}
