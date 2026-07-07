use crate::linux_device::types::LinuxDevice;
use core::ffi::{c_char, c_void};
use core::sync::atomic::AtomicU32;

pub(super) type NdoOpen = unsafe extern "C" fn(*mut LinuxNetDevice) -> i32;
pub(super) type NdoStop = unsafe extern "C" fn(*mut LinuxNetDevice) -> i32;
pub(super) type NdoStartXmit = unsafe extern "C" fn(*mut LinuxSkBuff, *mut LinuxNetDevice) -> i32;
pub(super) type NetdevSetup = unsafe extern "C" fn(*mut LinuxNetDevice);

pub(super) const IFNAMSIZ: usize = 16;
pub(super) const ETH_ALEN: usize = 6;
pub(super) const ETH_HLEN: usize = 14;
pub(super) const ETH_DATA_LEN: u32 = 1500;
pub(super) const SKB_CB_LEN: usize = 48;
pub(super) const NET_NAME_UNKNOWN: u8 = 0;
pub(super) const NETDEV_TX_OK: i32 = 0;
pub(super) const NETDEV_TX_BUSY: i32 = 1;
pub(super) const NET_RX_SUCCESS: i32 = 0;
pub(super) const NET_RX_DROP: i32 = 1;
pub(super) const LINUX_OK: i32 = 0;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const IFF_UP: u32 = 0x0001;
pub(super) const IFF_BROADCAST: u32 = 0x0002;
pub(super) const IFF_RUNNING: u32 = 0x0040;
pub(super) const IFF_MULTICAST: u32 = 0x1000;

#[repr(C)]
pub(super) struct LinuxNetDeviceOps {
    pub(super) ndo_open: Option<NdoOpen>,
    pub(super) ndo_stop: Option<NdoStop>,
    pub(super) ndo_start_xmit: Option<NdoStartXmit>,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(super) struct LinuxRtnlLinkStats64 {
    pub(super) rx_packets: u64,
    pub(super) tx_packets: u64,
    pub(super) rx_bytes: u64,
    pub(super) tx_bytes: u64,
    pub(super) rx_errors: u64,
    pub(super) tx_errors: u64,
    pub(super) rx_dropped: u64,
    pub(super) tx_dropped: u64,
}

#[repr(C)]
pub(super) struct LinuxNetDevice {
    pub(super) dev: LinuxDevice,
    pub(super) name: [c_char; IFNAMSIZ],
    pub(super) netdev_ops: *const LinuxNetDeviceOps,
    pub(super) mtu: u32,
    pub(super) flags: u32,
    pub(super) priv_data: *mut c_void,
    pub(super) dev_addr: [u8; ETH_ALEN],
    pub(super) addr_len: u8,
    pub(super) ifindex: u32,
    pub(super) state: AtomicU32,
    pub(super) stats: LinuxRtnlLinkStats64,
}

#[repr(C)]
pub(super) struct LinuxSkBuff {
    pub(super) head: *mut u8,
    pub(super) data: *mut u8,
    pub(super) tail: *mut u8,
    pub(super) end: *mut u8,
    pub(super) len: u32,
    pub(super) protocol: u16,
    pub(super) dev: *mut LinuxNetDevice,
    pub(super) cb: [u8; SKB_CB_LEN],
    pub(super) owner: *mut c_void,
}
