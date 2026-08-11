use crate::linux_device::types::LinuxDevice;
use core::ffi::{c_char, c_void};
use core::sync::atomic::AtomicU64;

pub(super) type NdoOpen = unsafe extern "C" fn(*mut LinuxNetDevice) -> i32;
pub(super) type NdoStop = unsafe extern "C" fn(*mut LinuxNetDevice) -> i32;
pub(super) type NdoStartXmit = unsafe extern "C" fn(*mut LinuxSkBuff, *mut LinuxNetDevice) -> i32;
pub(super) type NdoSetRxMode = unsafe extern "C" fn(*mut LinuxNetDevice);
pub(super) type NdoChangeMtu = unsafe extern "C" fn(*mut LinuxNetDevice, u32) -> i32;
pub(super) type NdoSetMacAddress = unsafe extern "C" fn(*mut LinuxNetDevice, *mut c_void) -> i32;
pub(super) type NdoSetConfig = unsafe extern "C" fn(*mut LinuxNetDevice, *mut LinuxIfMap) -> i32;
pub(super) type NetdevSetup = unsafe extern "C" fn(*mut LinuxNetDevice);
pub(super) type NapiPoll = unsafe extern "C" fn(*mut LinuxNapiStruct, i32) -> i32;
pub(super) type PhyLinkChange = unsafe extern "C" fn(*mut LinuxNetDevice);
pub(super) type MdioRead = unsafe extern "C" fn(*mut LinuxMiiBus, i32, i32) -> i32;
pub(super) type MdioWrite = unsafe extern "C" fn(*mut LinuxMiiBus, i32, i32, u16) -> i32;

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
#[cfg(any(test, feature = "hosted"))]
pub(super) const CHECKSUM_NONE: u8 = 0;
pub(super) const CHECKSUM_UNNECESSARY: u8 = 1;
pub(super) const CHECKSUM_PARTIAL: u8 = 3;
pub(super) const DUPLEX_FULL: i32 = 1;
pub(super) const SPEED_1000: i32 = 1000;
pub(super) const AUTONEG_ENABLE: u8 = 1;
pub(super) const PHY_MAX_ADDR: usize = 32;

#[repr(C)]
pub(super) struct LinuxNetDeviceOps {
    pub(super) ndo_init: Option<NdoOpen>,
    pub(super) ndo_uninit: Option<NdoSetRxMode>,
    pub(super) ndo_open: Option<NdoOpen>,
    pub(super) ndo_stop: Option<NdoStop>,
    pub(super) ndo_start_xmit: Option<NdoStartXmit>,
    pub(super) ndo_features_check: usize,
    pub(super) ndo_select_queue: usize,
    pub(super) ndo_change_rx_flags: usize,
    pub(super) ndo_set_rx_mode: Option<NdoSetRxMode>,
    pub(super) ndo_set_mac_address: Option<NdoSetMacAddress>,
    pub(super) ndo_validate_addr: usize,
    pub(super) ndo_do_ioctl: usize,
    pub(super) ndo_eth_ioctl: usize,
    pub(super) ndo_siocbond: usize,
    pub(super) ndo_siocwandev: usize,
    pub(super) ndo_siocdevprivate: usize,
    pub(super) ndo_set_config: Option<NdoSetConfig>,
    pub(super) ndo_change_mtu: Option<NdoChangeMtu>,
    pub(super) _tail: [u8; 600],
}

impl LinuxNetDeviceOps {
    #[cfg(any(test, feature = "hosted"))]
    /// # C: O(1)
    pub(super) const fn new() -> Self {
        Self { ndo_init: None, ndo_uninit: None, ndo_open: None, ndo_stop: None, ndo_start_xmit: None,
               ndo_features_check: 0, ndo_select_queue: 0, ndo_change_rx_flags: 0,
               ndo_set_rx_mode: None, ndo_set_mac_address: None, ndo_validate_addr: 0,
               ndo_do_ioctl: 0, ndo_eth_ioctl: 0, ndo_siocbond: 0,
               ndo_siocwandev: 0, ndo_siocdevprivate: 0, ndo_set_config: None, ndo_change_mtu: None, _tail: [0; 600] }
    }
}

#[repr(C)]
pub(super) struct LinuxIfMap {
    pub(super) mem_start: u64,
    pub(super) mem_end: u64,
    pub(super) base_addr: u16,
    pub(super) irq: u8,
    pub(super) dma: u8,
    pub(super) port: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(super) struct LinuxListHead {
    pub(super) next: usize,
    pub(super) prev: usize,
}

#[repr(C)]
pub(super) struct LinuxNetDevHwAddr {
    pub(super) list: LinuxListHead,
    pub(super) node: [usize; 3],
    pub(super) addr: [u8; MAX_ADDR_LEN],
    pub(super) addr_type: u8,
    pub(super) global_use: u8,
    pub(super) _to_sync_cnt: [u8; 2],
    pub(super) sync_cnt: i32,
    pub(super) refcount: i32,
    pub(super) synced: i32,
    pub(super) callback_head: [usize; 2],
}

#[repr(C)]
pub(super) struct LinuxNetDevHwAddrList {
    pub(super) list: LinuxListHead,
    pub(super) count: i32,
    pub(super) _to_tree: [u8; 4],
    pub(super) tree: usize,
}

impl LinuxNetDevHwAddrList {
    pub(super) fn empty() -> Self { Self { list: LinuxListHead::default(), count: 0, _to_tree: [0; 4], tree: 0 } }
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

#[repr(C, align(32))]
pub(super) struct LinuxPcpuSwNetStats {
    pub(super) rx_packets: u64,
    pub(super) rx_bytes: u64,
    pub(super) tx_packets: u64,
    pub(super) tx_bytes: u64,
    pub(super) _sync: [u8; 32],
}

/* Host ABI: struct dql is split across cache lines; limit starts at byte 64. */
#[repr(C, align(64))]
pub(super) struct LinuxDql {
    pub(super) num_queued: u32,
    pub(super) adj_limit: u32,
    pub(super) last_obj_cnt: u32,
    pub(super) stall_thrs: u16,
    pub(super) _to_history_head: [u8; 2],
    pub(super) history_head: usize,
    pub(super) history: [usize; 4],
    pub(super) _to_limit: [u8; 8],
    pub(super) limit: u32,
    pub(super) num_completed: u32,
    pub(super) prev_ovlimit: u32,
    pub(super) prev_num_queued: u32,
    pub(super) prev_last_obj_cnt: u32,
    pub(super) lowest_slack: u32,
    pub(super) slack_start_time: usize,
    pub(super) max_limit: u32,
    pub(super) min_limit: u32,
    pub(super) slack_hold_time: u32,
    pub(super) stall_max: u16,
    pub(super) _to_last_reap: [u8; 2],
    pub(super) last_reap: usize,
    pub(super) stall_cnt: usize,
}

#[repr(C, align(64))]
pub(super) struct LinuxNetdevQueue {
    pub(super) dev: *mut LinuxNetDevice,
    pub(super) qdisc: *mut c_void,
    pub(super) qdisc_sleeping: *mut c_void,
    pub(super) kobj: [u8; 64],
    pub(super) groups: *const *const c_void,
    pub(super) tx_maxrate: usize,
    pub(super) trans_timeout: isize,
    pub(super) sb_dev: *mut LinuxNetDevice,
    pub(super) pool: *mut c_void,
    pub(super) dql: LinuxDql,
    pub(super) xmit_lock: u32,
    pub(super) xmit_lock_owner: i32,
    pub(super) trans_start: usize,
    pub(super) state: usize,
    pub(super) napi: *mut LinuxNapiStruct,
    pub(super) numa_node: i32,
    pub(super) _tail: [u8; 28],
}

#[repr(C)]
pub(super) struct LinuxNetDeviceStats {
    pub(super) compat: LinuxRtnlLinkStats64,
    pub(super) _tail: [u8; 120],
}

/* This is the host ABI layout, including fields native drivers address directly.
 * Unimplemented contract fields stay as exact padding, never as an alternate
 * public object.  The trailing private allocation begins after this object. */
#[repr(C)]
pub(super) struct LinuxNetDevice {
    pub(super) _to_netdev_ops: [u8; 8],
    pub(super) netdev_ops: *const LinuxNetDeviceOps,
    pub(super) _to_tx: [u8; 8],
    pub(super) _tx: *mut LinuxNetdevQueue,
    pub(super) _to_real_tx: [u8; 8],
    pub(super) real_num_tx_queues: u32,
    pub(super) _to_mtu: [u8; 12],
    pub(super) mtu: u32,
    pub(super) _to_tstats: [u8; 100],
    pub(super) tstats: *mut LinuxPcpuSwNetStats,
    pub(super) state: AtomicU64,
    pub(super) flags: u32,
    pub(super) _to_features: [u8; 4],
    pub(super) features: u64,
    pub(super) _to_ifindex: [u8; 32],
    pub(super) ifindex: u32,
    pub(super) real_num_rx_queues: u32,
    pub(super) _to_name: [u8; 56],
    pub(super) name: [c_char; IFNAMSIZ],
    pub(super) _to_stats: [u8; 248],
    pub(super) stats: LinuxNetDeviceStats,
    pub(super) _to_ethtool: [u8; 16],
    pub(super) ethtool_ops: *const LinuxEtHToolOps,
    pub(super) _to_perm_addr: [u8; 39],
    pub(super) perm_addr: [u8; MAX_ADDR_LEN],
    pub(super) _to_addr_len: [u8; 1],
    pub(super) addr_len: u8,
    pub(super) _to_uc: [u8; 23],
    pub(super) uc: LinuxNetDevHwAddrList,
    pub(super) mc: LinuxNetDevHwAddrList,
    pub(super) _to_dev_addr: [u8; 152],
    pub(super) dev_addr: *const u8,
    pub(super) num_rx_queues: u32,
    pub(super) _to_broadcast: [u8; 20],
    pub(super) broadcast: [u8; MAX_ADDR_LEN],
    pub(super) _to_num_tx: [u8; 24],
    pub(super) num_tx_queues: u32,
    pub(super) _to_tx_queue_len: [u8; 12],
    pub(super) tx_queue_len: u32,
    pub(super) _to_dev: [u8; 284],
    pub(super) dev: LinuxDevice,
    pub(super) _to_tso: [u8; 72],
    pub(super) tso_max_size: u32,
    pub(super) tso_max_segs: u16,
    pub(super) _to_phydev: [u8; 48],
    pub(super) phydev: *mut LinuxPhyDevice,
    pub(super) _tail: [u8; 312],
}

#[repr(C, packed(4))]
pub(super) struct LinuxSkBuffRaw {
    pub(super) next: *mut LinuxSkBuff,
    pub(super) prev: *mut LinuxSkBuff,
    pub(super) dev: *mut LinuxNetDevice,
    pub(super) sk: *mut c_void,
    pub(super) tstamp: i64,
    pub(super) cb: [u8; SKB_CB_LEN],
    pub(super) refdst: usize,
    pub(super) destructor: *mut c_void,
    pub(super) nfct: usize,
    pub(super) len: u32,
    pub(super) data_len: u32,
    pub(super) mac_len: u16,
    pub(super) hdr_len: u16,
    pub(super) queue_mapping: u16,
    pub(super) flags: u8,
    pub(super) active_extensions: u8,
    pub(super) _headers_prefix: [u8; 8],
    pub(super) csum_start: u16,
    pub(super) csum_offset: u16,
    pub(super) _headers_middle: [u8; 36],
    pub(super) protocol: u16,
    pub(super) _headers_suffix: [u8; 10],
    pub(super) tail: u32,
    pub(super) end: u32,
    pub(super) _tail_pad: [u8; 4],
    pub(super) head: *mut u8,
    pub(super) data: *mut u8,
    pub(super) truesize: u32,
    pub(super) users: u32,
    pub(super) extensions: *mut c_void,
}

/* The target C ABI aligns the enclosing object to eight bytes while its tail
 * pointer group begins at a four-byte boundary.  Keep that exact split rather
 * than silently changing the pointer offsets to Rust's native layout. */
#[repr(C, align(8))]
pub(super) struct LinuxSkBuff {
    pub(super) raw: LinuxSkBuffRaw,
}

impl core::ops::Deref for LinuxSkBuff {
    type Target = LinuxSkBuffRaw;
    fn deref(&self) -> &Self::Target { &self.raw }
}

impl core::ops::DerefMut for LinuxSkBuff {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.raw }
}

/// Read the two-bit checksum state at its ABI bit position.
/// # C: O(1)
pub(super) unsafe fn skb_ip_summed(skb: *const LinuxSkBuff) -> u8 {
    // SAFETY: caller supplies a live sk_buff; byte 128 contains the checksum bits.
    unsafe { (core::ptr::read_unaligned((skb as *const u8).add(128)) >> 5) & 0x3 }
}

/// Write the two-bit checksum state without disturbing adjacent header flags.
/// # C: O(1)
pub(super) unsafe fn skb_set_ip_summed(skb: *mut LinuxSkBuff, state: u8) {
    // SAFETY: caller supplies a live sk_buff; byte 128 contains the checksum bits.
    unsafe {
        let p = (skb as *mut u8).add(128);
        let old = core::ptr::read_unaligned(p);
        core::ptr::write_unaligned(p, (old & !0x60) | ((state & 0x3) << 5));
    }
}

#[repr(C)]
pub(super) struct LinuxNapiStruct {
    pub(super) state: AtomicU64,
    pub(super) _to_weight: [u8; 16],
    pub(super) weight: i32,
    pub(super) _to_poll: [u8; 4],
    pub(super) poll: Option<NapiPoll>,
    pub(super) _to_dev: [u8; 8],
    pub(super) dev: *mut LinuxNetDevice,
    pub(super) _to_irq: [u8; 360],
    pub(super) irq: i32,
    pub(super) _tail: [u8; 76],
}

#[repr(C)]
pub(super) struct LinuxSockAddr {
    pub(super) sa_family: u16,
    pub(super) sa_data: [u8; 14],
}

#[repr(C)]
pub(super) struct LinuxPhyDevice {
    pub(super) mdio: LinuxMdioDevice,
    pub(super) _to_flags: [u8; 160],
    pub(super) _flags: [u8; 4],
    pub(super) _to_interface: [u8; 12],
    pub(super) interface: u32,
    pub(super) _to_speed: [u8; 12],
    pub(super) speed: i32,
    pub(super) duplex: i32,
    pub(super) _to_irq: [u8; 192],
    pub(super) irq: i32,
    pub(super) _to_attached: [u8; 188],
    pub(super) attached_dev: *mut LinuxNetDevice,
    pub(super) _to_link_change: [u8; 32],
    pub(super) link_change: Option<PhyLinkChange>,
    pub(super) _tail: [u8; 32],
}

/// Read one single-bit PHY state flag at its ABI location.
/// # C: O(1)
pub(super) unsafe fn phy_flag(phy: *const LinuxPhyDevice, byte: usize, bit: u8) -> bool {
    // SAFETY: caller supplies a live phy_device and the fixed byte is in its ABI extent.
    unsafe { (core::ptr::read((phy as *const u8).add(byte)) & (1 << bit)) != 0 }
}

/// Update one single-bit PHY state flag without changing adjacent ABI flags.
/// # C: O(1)
pub(super) unsafe fn phy_set_flag(phy: *mut LinuxPhyDevice, byte: usize, bit: u8, value: bool) {
    // SAFETY: caller supplies a live phy_device and the fixed byte is in its ABI extent.
    unsafe {
        let p = (phy as *mut u8).add(byte); let old = core::ptr::read(p);
        core::ptr::write(p, if value { old | (1 << bit) } else { old & !(1 << bit) });
    }
}

#[repr(C)]
pub(super) struct LinuxMiiBus {
    pub(super) owner: *mut c_void,
    pub(super) name: *const c_char,
    pub(super) id: [c_char; 20],
    pub(super) _id_pad: [u8; 44],
    pub(super) priv_data: *mut c_void,
    pub(super) read: Option<MdioRead>,
    pub(super) write: Option<MdioWrite>,
    pub(super) read_c45: usize,
    pub(super) write_c45: usize,
    pub(super) reset: usize,
    pub(super) _stats: [u8; 1024],
    pub(super) _mdio_lock: [u8; 32],
    pub(super) parent: *mut LinuxDevice,
    pub(super) state: u32,
    pub(super) _state_pad: [u8; 4],
    pub(super) dev: LinuxDevice,
    pub(super) mdio_map: [*mut LinuxPhyDevice; PHY_MAX_ADDR],
    pub(super) phy_mask: u32,
    pub(super) phy_ignore_ta_mask: u32,
    pub(super) irq: [i32; PHY_MAX_ADDR],
    pub(super) reset_delay_us: i32,
    pub(super) reset_post_delay_us: i32,
    pub(super) reset_gpiod: *mut c_void,
    pub(super) _shared_lock: [u8; 32],
    pub(super) shared: [*mut c_void; PHY_MAX_ADDR],
}

#[repr(C)]
pub(super) struct LinuxMdioDevice {
    pub(super) dev: LinuxDevice,
    pub(super) bus: *mut LinuxMiiBus,
    pub(super) modalias: [c_char; 32],
    pub(super) bus_match: usize,
    pub(super) device_free: usize,
    pub(super) device_remove: usize,
    pub(super) addr: i32,
    pub(super) flags: u32,
    pub(super) reset_state: u32,
    pub(super) reset_gpio: *mut c_void,
    pub(super) reset_ctrl: *mut c_void,
    pub(super) reset_assert_delay: u32,
    pub(super) reset_deassert_delay: u32,
}
