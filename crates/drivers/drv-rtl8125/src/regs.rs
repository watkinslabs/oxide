//! RTL8125 register and descriptor ABI, transcribed from Linux r8169.

pub const VENDOR_REALTEK: u16 = 0x10ec;
pub const DEVICE_RTL8125: u16 = 0x8125;
pub const MAC0: u64 = 0x00;
pub const TX_DESC_LOW: u64 = 0x20;
pub const TX_DESC_HIGH: u64 = 0x24;
pub const CHIP_CMD: u64 = 0x37;
pub const TX_POLL: u64 = 0x90;
pub const INTR_MASK: u64 = 0x38;
pub const INTR_STATUS: u64 = 0x3c;
pub const TX_CONFIG: u64 = 0x40;
pub const RX_CONFIG: u64 = 0x44;
pub const RX_DESC_LOW: u64 = 0xe4;
pub const RX_DESC_HIGH: u64 = 0xe8;

pub const CMD_RESET: u8 = 0x10;
pub const CMD_RX_ENABLE: u8 = 0x08;
pub const CMD_TX_ENABLE: u8 = 0x04;
pub const TX_POLL_NORMAL: u8 = 0x40;
pub const INTR_RX_OK: u16 = 0x0001;
pub const INTR_TX_OK: u16 = 0x0004;
pub const INTR_RX_ERROR: u16 = 0x0002;
pub const INTR_TX_ERROR: u16 = 0x0008;
pub const INTR_LINK_CHANGE: u16 = 0x0020;
pub const INTR_DEFAULT: u16 = INTR_RX_OK | INTR_TX_OK | INTR_RX_ERROR | INTR_TX_ERROR | INTR_LINK_CHANGE;
pub const RX_ACCEPT_MY_PHYS: u32 = 0x02;
pub const RX_ACCEPT_BROADCAST: u32 = 0x08;
pub const RX_DMA_BURST: u32 = 7 << 8;
pub const RX_FETCH_8125: u32 = 8 << 27;
pub const DESC_OWN: u32 = 1 << 31;
pub const DESC_RING_END: u32 = 1 << 30;
pub const DESC_FIRST: u32 = 1 << 29;
pub const DESC_LAST: u32 = 1 << 28;
pub const RX_ERROR: u32 = 1 << 21;
pub const DESC_LENGTH: u32 = 0x3fff;
pub const RING_COUNT: usize = 256;
pub const BUFFER_BYTES: usize = 2048;
pub const ETH_MAX_FRAME: usize = 1518;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct TxDesc { pub opts1: u32, pub opts2: u32, pub addr: u64 }
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct RxDesc { pub opts1: u32, pub opts2: u32, pub addr: u64 }

/// Construct one device-owned receive descriptor. # C: O(1)
pub const fn rx_descriptor(pa: u64, last: bool) -> RxDesc {
    RxDesc { opts1: DESC_OWN | BUFFER_BYTES as u32 | if last { DESC_RING_END } else { 0 }, opts2: 0, addr: pa }
}
/// Construct one completed transmit descriptor. # C: O(1)
pub const fn tx_descriptor(pa: u64, len: usize, last: bool) -> TxDesc {
    TxDesc { opts1: DESC_OWN | DESC_FIRST | DESC_LAST | len as u32 | if last { DESC_RING_END } else { 0 }, opts2: 0, addr: pa }
}
/// Return whether a received descriptor is complete and error-free. # C: O(1)
pub const fn rx_complete(opts1: u32) -> bool { opts1 & (DESC_OWN | RX_ERROR) == 0 && opts1 & DESC_LENGTH >= 14 }
/// Decode the factory station address from the MAC0 byte window. # C: O(1)
pub fn mac_valid(mac: [u8; 6]) -> bool { mac != [0; 6] && mac != [0xff; 6] }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn linux_r8169_descriptor_abi_is_preserved() {
        assert_eq!(core::mem::size_of::<TxDesc>(), 16);
        assert_eq!(core::mem::size_of::<RxDesc>(), 16);
        assert_eq!(rx_descriptor(0x2000, true).opts1, DESC_OWN | DESC_RING_END | BUFFER_BYTES as u32);
        assert!(rx_complete(64)); assert!(!rx_complete(DESC_OWN | 64)); assert!(!rx_complete(RX_ERROR | 64));
    }
}
