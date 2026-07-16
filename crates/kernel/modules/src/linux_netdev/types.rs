use crate::linux_device::types::LinuxDevice;
use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicU32, AtomicU64};

pub(super) type NdoOpen = unsafe extern "C" fn(*mut LinuxNetDevice) -> i32;
pub(super) type NdoStop = unsafe extern "C" fn(*mut LinuxNetDevice) -> i32;
pub(super) type NdoStartXmit = unsafe extern "C" fn(*mut LinuxSkBuff, *mut LinuxNetDevice) -> i32;
pub(super) type NdoSetRxMode = unsafe extern "C" fn(*mut LinuxNetDevice);
pub(super) type NdoChangeMtu = unsafe extern "C" fn(*mut LinuxNetDevice, u32) -> i32;
pub(super) type NetdevSetup = unsafe extern "C" fn(*mut LinuxNetDevice);
pub(super) type NapiPoll = unsafe extern "C" fn(*mut LinuxNapiStruct, i32) -> i32;
pub(super) type PhyLinkChange = unsafe extern "C" fn(*mut LinuxNetDevice);

pub(super) const IFNAMSIZ: usize = 16;
pub(super) const ETH_ALEN: usize = 6;
pub(super) const ETH_HLEN: usize = 14;
pub(super) const ETH_DATA_LEN: u32 = 1500;
pub(super) const MAX_ADDR_LEN: usize = net::PACKET_LINK_ADDRESS_MAX;
pub(super) const SKB_CB_LEN: usize = 48;
pub(super) const NET_NAME_UNKNOWN: u8 = 0;
pub(super) const NETDEV_TX_OK: i32 = 0;
pub(super) const NETDEV_TX_BUSY: i32 = 1;
pub(super) const NET_RX_SUCCESS: i32 = 0;
pub(super) const NET_RX_DROP: i32 = 1;
pub(super) const LINUX_OK: i32 = 0;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const LINUX_ENODEV: i32 = 19;
pub(super) const LINUX_ENOMEM: i32 = 12;
pub(super) const IFF_UP: u32 = 0x0001;
pub(super) const IFF_BROADCAST: u32 = 0x0002;
pub(super) const IFF_RUNNING: u32 = 0x0040;
pub(super) const IFF_PROMISC: u32 = 0x0100;
pub(super) const IFF_ALLMULTI: u32 = 0x0200;
pub(super) const IFF_MULTICAST: u32 = 0x1000;
pub(super) const CHECKSUM_NONE: u8 = 0;
pub(super) const CHECKSUM_UNNECESSARY: u8 = 1;
pub(super) const CHECKSUM_PARTIAL: u8 = 3;
pub(super) const DUPLEX_FULL: i32 = 1;
pub(super) const SPEED_1000: i32 = 1000;
pub(super) const AUTONEG_ENABLE: u8 = 1;

#[repr(C)]
pub(super) struct LinuxNetDeviceOps {
    pub(super) ndo_open: Option<NdoOpen>,
    pub(super) ndo_stop: Option<NdoStop>,
    pub(super) ndo_start_xmit: Option<NdoStartXmit>,
    pub(super) ndo_set_rx_mode: Option<NdoSetRxMode>,
    pub(super) ndo_change_mtu: Option<NdoChangeMtu>,
}

#[repr(C)]
pub(super) struct LinuxNetDevHwAddr {
    pub(super) next: usize,
    pub(super) addr: [u8; MAX_ADDR_LEN],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(super) struct LinuxNetDevHwAddrList {
    pub(super) head: usize,
    pub(super) count: u32,
}

#[repr(C)]
pub(super) struct LinuxEtHToolOps {
    pub(super) get_link: *const c_void,
    pub(super) get_ts_info: *const c_void,
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
    pub(super) ethtool_ops: *const LinuxEtHToolOps,
    pub(super) phydev: *mut LinuxPhyDevice,
    pub(super) num_tx_queues: u32,
    pub(super) real_num_tx_queues: u32,
    pub(super) real_num_rx_queues: u32,
    pub(super) tso_max_size: u32,
    pub(super) tso_max_segs: u16,
    pub(super) uc: LinuxNetDevHwAddrList,
    pub(super) mc: LinuxNetDevHwAddrList,
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
    pub(super) ip_summed: u8,
    pub(super) csum_start: u16,
    pub(super) csum_offset: u16,
    pub(super) queue_mapping: u16,
    pub(super) nr_frags: u8,
    pub(super) tstamp: i64,
    pub(super) hwtstamp: i64,
    pub(super) cb: [u8; SKB_CB_LEN],
    pub(super) owner: *mut c_void,
}

#[repr(C)]
pub(super) struct LinuxNapiStruct {
    pub(super) dev: *mut LinuxNetDevice,
    pub(super) poll: Option<NapiPoll>,
    pub(super) weight: i32,
    pub(super) state: AtomicU32,
    pub(super) rxq: u32,
    pub(super) txq: u32,
    pub(super) scheduled: AtomicU32,
    pub(super) ingress_generation: AtomicU64,
}

#[repr(C)]
pub(super) struct LinuxSockAddr {
    pub(super) sa_family: u16,
    pub(super) sa_data: [u8; 14],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(super) struct LinuxPhyDevice {
    pub(super) attached_dev: *mut LinuxNetDevice,
    pub(super) speed: i32,
    pub(super) duplex: i32,
    pub(super) link: u8,
    pub(super) autoneg: u8,
    pub(super) pause: u8,
    pub(super) asym_pause: u8,
    pub(super) interface: u32,
    pub(super) irq: i32,
    pub(super) page: i32,
    pub(super) regs: [u16; 32],
    pub(super) mmd_regs: [[u16; 32]; 8],
    pub(super) link_change: Option<PhyLinkChange>,
}
