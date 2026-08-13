//! AQC113 descriptor and queue-register ABI.

pub const RX_QUEUE_BASE: u64 = 0x5b00;
pub const RX_QUEUE_STRIDE: u64 = 0x20;
pub const TX_QUEUE_BASE: u64 = 0x7c00;
pub const TX_QUEUE_STRIDE: u64 = 0x40;
pub const QUEUE_BASE_LO: u64 = 0x00;
pub const QUEUE_BASE_HI: u64 = 0x04;
pub const QUEUE_CONTROL: u64 = 0x08;
pub const QUEUE_TAIL: u64 = 0x10;
pub const IRQ_STATUS: u64 = 0x2000;
pub const IRQ_STATUS_CLEAR: u64 = 0x2050;
pub const IRQ_MASK_SET: u64 = 0x2060;
pub const IRQ_MASK_CLEAR: u64 = 0x2070;
pub const IRQ_AUTO_MASK: u64 = 0x2090;
pub const IRQ_MAP0: u64 = 0x2100;
pub const IRQ_GLOBAL_CONTROL: u64 = 0x2300;
pub const IRQ_MASK_ALL: u32 = u32::MAX;
pub const IRQ_GLOBAL_MSI_SINGLE: u32 = 0x2000_0021;
pub const IRQ_GLOBAL_MSIX_SINGLE: u32 = 0x2000_0022;
pub const IRQ_GLOBAL_INTX_SINGLE: u32 = 0x2000_0080;
pub const L2_FILTER_BASE: u64 = 0x5110;
pub const L2_FILTER_STRIDE: u64 = 8;
pub const L2_FILTER_ACTION_MASK: u32 = 0x0007_0000;
pub const L2_FILTER_ACTION_HOST: u32 = 1 << 16;
pub const L2_FILTER_TAG_MASK: u32 = 0x0fc0_0000;
pub const L2_FILTER_TAG_UNICAST: u32 = 1 << 22;
pub const L2_FILTER_ENABLE: u32 = 1 << 31;
pub const QUEUE_ENABLE: u32 = 1 << 31;
pub const QUEUE_LENGTH_MASK: u32 = 0x0000_1ff8;
pub const TX_DESC_DATA: u32 = 1;
pub const TX_DESC_DONE: u32 = 1 << 20;
pub const TX_DESC_EOP: u32 = 1 << 21;
pub const TX_DESC_WRITEBACK: u32 = 1 << 27;
pub const TX_DESC_BUFFER_LENGTH_MASK: u32 = 0x000f_fff0;
pub const TX_DESC_PAYLOAD_LENGTH_MASK: u32 = 0xffff_c000;
pub const RX_DESC_DONE: u16 = 1;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct TxDesc { pub buffer_dma: u64, pub control: u32, pub control2: u32 }

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct RxDesc { pub buffer_dma: u64, pub header_dma: u64 }

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct RxWriteback { pub packet_type: u32, pub rss_hash: u32, pub status: u16, pub length: u16, pub next: u16, pub vlan: u16 }

pub const fn rx_queue_offset(index: u32) -> u64 { RX_QUEUE_BASE + index as u64 * RX_QUEUE_STRIDE }
pub const fn tx_queue_offset(index: u32) -> u64 { TX_QUEUE_BASE + index as u64 * TX_QUEUE_STRIDE }
pub const fn split_dma(dma: u64) -> (u32, u32) { (dma as u32, (dma >> 32) as u32) }
/// Queue-zero RX and TX interrupt-map enable bits, both targeting vector zero.
/// # C: O(1)
pub const fn queue_zero_irq_map() -> u32 { (1 << 15) | (1 << 31) }
/// Encodes Linux Atlantic's unicast filter address words from a MAC address.
/// # C: O(1)
pub const fn l2_filter_mac_words(mac: [u8; 6]) -> (u32, u32) {
    (
        (mac[2] as u32) << 24 | (mac[3] as u32) << 16 | (mac[4] as u32) << 8 | mac[5] as u32,
        (mac[0] as u32) << 8 | mac[1] as u32,
    )
}
pub const fn queue_control(current: u32, descriptors: usize, enable: bool) -> Option<u32> {
    if descriptors == 0 || descriptors % 8 != 0 || descriptors > QUEUE_LENGTH_MASK as usize { return None; }
    Some(current & !(QUEUE_LENGTH_MASK | QUEUE_ENABLE) | descriptors as u32 | if enable { QUEUE_ENABLE } else { 0 })
}
pub const fn tx_data_control(bytes: usize) -> Option<u32> {
    if bytes == 0 || bytes > (TX_DESC_BUFFER_LENGTH_MASK >> 4) as usize { return None; }
    Some(TX_DESC_DATA | ((bytes as u32) << 4) | TX_DESC_EOP | TX_DESC_WRITEBACK)
}
pub const fn tx_payload_control(bytes: usize) -> Option<u32> {
    if bytes > (TX_DESC_PAYLOAD_LENGTH_MASK >> 14) as usize { return None; }
    Some((bytes as u32) << 14)
}
pub const fn rx_done(desc: &RxWriteback) -> bool { desc.status & RX_DESC_DONE != 0 }
pub const fn tx_done(desc: &TxDesc) -> bool { desc.control & TX_DESC_DONE != 0 }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn descriptor_layouts_are_hardware_sized() { assert_eq!(core::mem::size_of::<TxDesc>(), 16); assert_eq!(core::mem::size_of::<RxDesc>(), 16); assert_eq!(core::mem::size_of::<RxWriteback>(), 16); }
    #[test] fn queue_zero_windows_are_not_interchanged() { assert_eq!(rx_queue_offset(0), 0x5b00); assert_eq!(tx_queue_offset(0), 0x7c00); assert_eq!(rx_queue_offset(1), 0x5b20); assert_eq!(tx_queue_offset(1), 0x7c40); }
    #[test] fn descriptor_count_is_divided_then_shifted_by_hardware() { assert_eq!(queue_control(0x1000_0000, 4096, true), Some(0x9000_1000)); assert_eq!(queue_control(0, 4095, true), None); assert_eq!(queue_control(0, 8192, true), None); }
    #[test] fn plain_tx_requests_end_of_packet_and_writeback() { assert_eq!(tx_data_control(1500), Some(0x0820_5dc1)); assert_eq!(tx_payload_control(1500), Some(0x0177_0000)); }
    #[test] fn queue_zero_interrupt_map_enables_rx_and_tx_on_vector_zero() { assert_eq!(queue_zero_irq_map(), 0x8000_8000); assert_eq!(IRQ_STATUS, 0x2000); assert_eq!(IRQ_MASK_SET, 0x2060); assert_eq!(IRQ_GLOBAL_CONTROL, 0x2300); assert_eq!(IRQ_GLOBAL_MSI_SINGLE, 0x2000_0021); assert_eq!(IRQ_GLOBAL_MSIX_SINGLE, 0x2000_0022); assert_eq!(IRQ_GLOBAL_INTX_SINGLE, 0x2000_0080); }
    #[test] fn filter_address_words_follow_the_linux_byte_order() { assert_eq!(l2_filter_mac_words([0x02, 0x4f, 0x58, 0, 0, 1]), (0x5800_0001, 0x024f)); }
    #[test] fn primary_filter_preserves_no_stale_request_tag() { assert_eq!(L2_FILTER_TAG_MASK, 0x0fc0_0000); assert_eq!(L2_FILTER_TAG_UNICAST, 0x0040_0000); }
}
