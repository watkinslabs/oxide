use super::*;
use crate::resolve;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

const SAMPLE_PRIV: i32 = 32;
const SAMPLE_FRAME_LEN: usize = ETH_HLEN + 20;
const SAMPLE_MAC: [u8; ETH_ALEN] = [0x02, 0x4f, 0x58, 0, 0, 1];
static TX_COUNT: AtomicUsize = AtomicUsize::new(0);
static TX_LEN: AtomicUsize = AtomicUsize::new(0);
static RX_MODE_COUNT: AtomicUsize = AtomicUsize::new(0);
static RX_MODE_FLAGS: AtomicU32 = AtomicU32::new(0);
static RX_MODE_MC_COUNT: AtomicU32 = AtomicU32::new(0);
static RX_MODE_UC_COUNT: AtomicU32 = AtomicU32::new(0);
static RX_MODE_MC_ADDRESS: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn sample_xmit(skb: *mut LinuxSkBuff, _dev: *mut LinuxNetDevice) -> i32 {
    if !skb.is_null() {
        // SAFETY: test callback receives an skb allocated by the facade.
        unsafe {
            TX_LEN.store((*skb).len as usize, Ordering::Release);
            skb::kfree_skb(skb);
        }
    }
    TX_COUNT.fetch_add(1, Ordering::AcqRel);
    NETDEV_TX_OK
}

unsafe extern "C" fn sample_set_rx_mode(dev: *mut LinuxNetDevice) {
    if dev.is_null() { return; }
    // SAFETY: facade callback supplies its live LinuxNetDevice pointer.
    // SAFETY: lists and nodes remain stable through the synchronous callback.
    unsafe {
        RX_MODE_FLAGS.store((*dev).flags, Ordering::Release);
        RX_MODE_MC_COUNT.store((*dev).mc.count, Ordering::Release);
        RX_MODE_UC_COUNT.store((*dev).uc.count, Ordering::Release);
        if (*dev).mc.head != 0 {
            let row = &*((*dev).mc.head as *const LinuxNetDevHwAddr);
            let mut packed = [0u8; 8];
            packed[..6].copy_from_slice(&row.addr[..6]);
            RX_MODE_MC_ADDRESS.store(u64::from_ne_bytes(packed), Ordering::Release);
        }
    }
    RX_MODE_COUNT.fetch_add(1, Ordering::AcqRel);
}

static OPS: LinuxNetDeviceOps = LinuxNetDeviceOps {
    ndo_open: None,
    ndo_stop: None,
    ndo_start_xmit: Some(sample_xmit),
    ndo_set_rx_mode: None,
    ndo_change_mtu: None,
    ndo_set_mac_address: None,
    ndo_set_config: None,
};

static RX_MODE_OPS: LinuxNetDeviceOps = LinuxNetDeviceOps {
    ndo_open: None,
    ndo_stop: None,
    ndo_start_xmit: Some(sample_xmit),
    ndo_set_rx_mode: Some(sample_set_rx_mode),
    ndo_change_mtu: None,
    ndo_set_mac_address: None,
    ndo_set_config: None,
};

#[test]
fn export_symbols_registers_netdev_surface() {
    crate::linux_netdev::export_symbols();
    assert!(resolve("alloc_etherdev", false).is_ok());
    assert!(resolve("register_netdev", false).is_ok());
    assert!(resolve("netif_rx", false).is_ok());
    assert!(resolve("dev_alloc_skb", false).is_ok());
    assert!(resolve("eth_type_trans", false).is_ok());
}

#[test]
fn register_netdev_exposes_adapter_and_xmit() {
    TX_COUNT.store(0, Ordering::Release);
    TX_LEN.store(0, Ordering::Release);
    // SAFETY: test owns the net_device allocation through free_netdev.
    let dev = unsafe { netalloc::alloc_etherdev(SAMPLE_PRIV) };
    assert!(!dev.is_null());
    // SAFETY: dev is a valid LinuxNetDevice from alloc_etherdev.
    unsafe {
        (*dev).netdev_ops = &OPS;
        netalloc::eth_hw_addr_set(dev, SAMPLE_MAC.as_ptr());
        assert!(!netalloc::netdev_priv(dev).is_null());
        assert_eq!(register_netdev(dev), LINUX_OK);
    }
    let name = linux_name(dev);
    let (id, adapter) = HOST_IFACES.lookup_name(&name).expect("registered adapter");
    assert_ne!(id.raw(), 0);
    assert_eq!(adapter.mac(), MacAddr(SAMPLE_MAC));
    assert_eq!(adapter.address_len(), ETH_ALEN as u8);
    let frame = [0xa5u8; SAMPLE_FRAME_LEN];
    adapter.xmit_raw(&frame).expect("xmit through ndo_start_xmit");
    assert_eq!(TX_COUNT.load(Ordering::Acquire), 1);
    assert_eq!(TX_LEN.load(Ordering::Acquire), SAMPLE_FRAME_LEN);
    // SAFETY: test unregisters then frees its allocation.
    unsafe {
        unregister_netdev(dev);
        netalloc::free_netdev(dev);
    }
}

#[test]
fn packet_receive_mode_updates_flags_before_driver_callback() {
    RX_MODE_COUNT.store(0, Ordering::Release);
    RX_MODE_FLAGS.store(0, Ordering::Release);
    RX_MODE_MC_COUNT.store(0, Ordering::Release);
    RX_MODE_UC_COUNT.store(0, Ordering::Release);
    RX_MODE_MC_ADDRESS.store(0, Ordering::Release);
    // SAFETY: test owns the net_device allocation through free_netdev.
    let dev = unsafe { netalloc::alloc_etherdev(0) };
    assert!(!dev.is_null());
    // SAFETY: test owns the allocated device and installs static operations.
    unsafe { (*dev).netdev_ops = &RX_MODE_OPS; }
    let adapter = LinuxNetAdapter {
        dev: dev as usize, name: String::from("rxmode0"),
        rx_addresses: Spinlock::new(LinuxRxAddressStorage::new()),
    };
    let mut multicast = [0u8; net::PACKET_LINK_ADDRESS_MAX];
    multicast[..6].copy_from_slice(&[1, 0, 94, 0, 0, 7]);
    let mut unicast = [0u8; net::PACKET_LINK_ADDRESS_MAX];
    unicast[..6].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
    adapter.packet_rx_mode_changed(&net::PacketRxMode {
        promiscuous: true, all_multicast: true,
        multicast: alloc::vec![net::PacketLinkAddress { len: 6, bytes: multicast }],
        unicast: alloc::vec![net::PacketLinkAddress { len: 6, bytes: unicast }],
    });
    assert_eq!(RX_MODE_COUNT.load(Ordering::Acquire), 1);
    assert_eq!(RX_MODE_FLAGS.load(Ordering::Acquire) & (IFF_PROMISC | IFF_ALLMULTI),
        IFF_PROMISC | IFF_ALLMULTI);
    assert_eq!(RX_MODE_MC_COUNT.load(Ordering::Acquire), 1);
    assert_eq!(RX_MODE_UC_COUNT.load(Ordering::Acquire), 1);
    let mut packed = [0u8; 8]; packed[..6].copy_from_slice(&multicast[..6]);
    assert_eq!(RX_MODE_MC_ADDRESS.load(Ordering::Acquire), u64::from_ne_bytes(packed));
    adapter.packet_rx_mode_changed(&net::PacketRxMode::default());
    assert_eq!(RX_MODE_COUNT.load(Ordering::Acquire), 2);
    assert_eq!(RX_MODE_FLAGS.load(Ordering::Acquire) & (IFF_PROMISC | IFF_ALLMULTI), 0);
    assert_eq!(RX_MODE_MC_COUNT.load(Ordering::Acquire), 0);
    assert_eq!(RX_MODE_UC_COUNT.load(Ordering::Acquire), 0);
    // SAFETY: test frees its unregistered device allocation.
    unsafe { netalloc::free_netdev(dev); }
}

#[test]
fn skb_put_reserve_pull_and_free_round_trip() {
    let skb = skb::dev_alloc_skb(SAMPLE_FRAME_LEN as u32);
    assert!(!skb.is_null());
    // SAFETY: test owns skb until kfree_skb.
    unsafe {
        skb::skb_reserve(skb, ETH_HLEN as u32);
        let data = skb::skb_put(skb, (SAMPLE_FRAME_LEN - ETH_HLEN) as u32);
        assert!(!data.is_null());
        assert_eq!((*skb).len as usize, SAMPLE_FRAME_LEN - ETH_HLEN);
        assert_eq!(skb::skb_pull(skb, 4), data.add(4));
        assert_eq!((*skb).len as usize, SAMPLE_FRAME_LEN - ETH_HLEN - 4);
        skb::kfree_skb(skb);
    }
}

#[test]
fn rx_views_handle_l2_and_l3_skb_data() {
    let mut l2 = [0u8; SAMPLE_FRAME_LEN];
    l2[ETHERTYPE_OFFSET] = (net::addr::eth_p::IPV4 >> u8::BITS) as u8;
    l2[ETHERTYPE_OFFSET + 1] = net::addr::eth_p::IPV4 as u8;
    assert_eq!(resolved_protocol(&l2, 0), net::addr::eth_p::IPV4);
    assert!(l2_frame(&l2, net::addr::eth_p::IPV4).is_some());
    assert_eq!(l3_payload(&l2, net::addr::eth_p::IPV4).len(), SAMPLE_FRAME_LEN - ETH_HLEN);

    let l3 = &l2[ETH_HLEN..];
    assert_eq!(resolved_protocol(l3, net::addr::eth_p::IPV4), net::addr::eth_p::IPV4);
    assert!(l2_frame(l3, net::addr::eth_p::IPV4).is_none());
    assert_eq!(l3_payload(l3, net::addr::eth_p::IPV4).len(), SAMPLE_FRAME_LEN - ETH_HLEN);
}
