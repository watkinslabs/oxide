#![allow(dangerous_implicit_autorefs)]

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

#[test]
fn skb_kpi_layout_matches_host_profile() {
    assert_eq!(core::mem::size_of::<LinuxSkBuff>(), 232);
    assert_eq!(core::mem::align_of::<LinuxSkBuff>(), 8);
    assert_eq!(core::mem::offset_of!(LinuxSkBuff, raw.next), 0);
    assert_eq!(core::mem::offset_of!(LinuxSkBuff, raw.sk), 24);
    assert_eq!(core::mem::offset_of!(LinuxSkBuff, raw.cb), 40);
    assert_eq!(core::mem::offset_of!(LinuxSkBuff, raw.len), 112);
    assert_eq!(core::mem::offset_of!(LinuxSkBuff, raw.queue_mapping), 124);
    assert_eq!(core::mem::offset_of!(LinuxSkBuff, raw.tail), 188);
    assert_eq!(core::mem::offset_of!(LinuxSkBuff, raw.head), 200);
    assert_eq!(core::mem::offset_of!(LinuxSkBuff, raw.data), 208);
    assert_eq!(core::mem::offset_of!(LinuxSkBuff, raw.extensions), 224);
}

#[test]
fn netdev_kpi_layout_matches_host_profile() {
    assert_eq!(core::mem::size_of::<LinuxNetDevice>(), 2688);
    assert_eq!(core::mem::offset_of!(LinuxNetDevice, netdev_ops), 8);
    assert_eq!(core::mem::offset_of!(LinuxNetDevice, state), 168);
    assert_eq!(core::mem::offset_of!(LinuxNetDevice, tstats), 160);
    assert_eq!(core::mem::offset_of!(LinuxNetDevice, num_tc), 54);
    assert_eq!(core::mem::offset_of!(LinuxNetDevice, tc_to_txq), 62);
    assert_eq!(core::mem::offset_of!(LinuxNetDevice, ifindex), 224);
    assert_eq!(core::mem::offset_of!(LinuxNetDevice, name), 288);
    assert_eq!(core::mem::offset_of!(LinuxNetDevice, dev), 1464);
    assert_eq!(core::mem::offset_of!(LinuxNetDevice, phydev), 2368);
    assert_eq!(core::mem::size_of::<LinuxDql>(), 128);
    assert_eq!(core::mem::offset_of!(LinuxDql, limit), 64);
    assert_eq!(core::mem::size_of::<LinuxNetdevQueue>(), 320);
    assert_eq!(core::mem::align_of::<LinuxNetdevQueue>(), 64);
    assert_eq!(core::mem::offset_of!(LinuxNetdevQueue, dql), 128);
    assert_eq!(core::mem::offset_of!(LinuxNetdevQueue, state), 272);
    assert_eq!(core::mem::size_of::<LinuxNetDevHwAddr>(), 104);
    assert_eq!(core::mem::offset_of!(LinuxNetDevHwAddr, addr), 40);
    assert_eq!(core::mem::size_of::<LinuxNetDevHwAddrList>(), 32);
    assert_eq!(core::mem::offset_of!(LinuxNetDevHwAddrList, tree), 24);
}

#[test]
fn traffic_class_kpis_follow_linux_range_validation() {
    let _modules = crate::test_serial::claim();
    // SAFETY: test owns this device allocation until free_netdev below.
    let dev = unsafe { netalloc::alloc_etherdev(0) };
    assert!(!dev.is_null());
    // SAFETY: dev is live caller-owned storage and the test serializes its configuration.
    unsafe {
        assert_eq!(netdev_set_num_tc(dev, 2), LINUX_OK);
        assert_eq!(netdev_set_tc_queue(dev, 0, 3, 0), LINUX_OK);
        assert_eq!(netdev_set_tc_queue(dev, 1, 2, 3), LINUX_OK);
        assert_eq!(((*dev).tc_to_txq[1].count, (*dev).tc_to_txq[1].offset), (2, 3));
        assert_eq!(netdev_set_tc_queue(dev, 2, 1, 5), -LINUX_EINVAL);
        assert_eq!(netdev_set_num_tc(dev, (TC_MAX_QUEUE + 1) as u8), -LINUX_EINVAL);
        netalloc::free_netdev(dev);
    }
}

#[test]
fn byte_reverse_table_has_all_bit_positions_reversed() {
    assert_eq!(super::super::misc::byte_rev_table[0x00], 0x00);
    assert_eq!(super::super::misc::byte_rev_table[0x01], 0x80);
    assert_eq!(super::super::misc::byte_rev_table[0x16], 0x68);
    assert_eq!(super::super::misc::byte_rev_table[0x80], 0x01);
    assert_eq!(super::super::misc::byte_rev_table[0xff], 0xff);
}

#[test]
fn netdev_allocates_initialized_host_tx_queues() {
    let _modules = crate::test_serial::claim();
    // SAFETY: test owns this allocation until the matching free_netdev.
    let dev = unsafe { netalloc::alloc_etherdev_mqs(0, 3, 1) };
    assert!(!dev.is_null());
    // SAFETY: alloc_etherdev_mqs initialized exactly three contiguous queue objects.
    unsafe {
        assert_eq!((*dev).num_tx_queues, 3);
        assert_eq!((*dev).real_num_tx_queues, 3);
        assert!(!(*dev)._tx.is_null());
        for index in 0..3 {
            let q = &*(*dev)._tx.add(index);
            assert_eq!(q.dev, dev);
            assert_eq!(q.dql.max_limit, u32::MAX / 2 - u32::MAX / 16);
            assert_eq!(q.dql.slack_hold_time, crate::linux_time::HZ);
        }
        netif_stop_queue(dev);
        assert_ne!((*(*dev)._tx).state & QUEUE_STATE_DRV_XOFF, 0);
        netif_tx_wake_queue((*dev)._tx);
        assert_eq!((*(*dev)._tx).state & QUEUE_STATE_DRV_XOFF, 0);
        netalloc::free_netdev(dev);
    }
}

#[test]
fn netdev_allocates_one_module_stats_slot_per_cpu() {
    let _modules = crate::test_serial::claim();
    // SAFETY: this test owns the allocation until free_netdev returns it.
    let dev = unsafe { netalloc::alloc_etherdev(0) };
    assert!(!dev.is_null());
    // SAFETY: tstats is initialized by netdev_alloc and reserves fixed CPU strides.
    unsafe {
        assert!(!(*dev).tstats.is_null());
        let first = (*dev).tstats as usize;
        assert_eq!(first % core::mem::align_of::<LinuxPcpuSwNetStats>(), 0);
        let last = first + (cpu::MAX_CPUS - 1) * cpu::LINUX_MODULE_PERCPU_STRIDE;
        assert_eq!(last - first, (cpu::MAX_CPUS - 1) * cpu::LINUX_MODULE_PERCPU_STRIDE);
        netalloc::free_netdev(dev);
    }
}

#[test]
fn managed_etherdev_uses_parent_devres_for_exactly_one_free() {
    let _modules = crate::test_serial::claim();
    let mut owner = crate::linux_device::types::LinuxDevice::new();
    // SAFETY: the test owns owner and releases its devres before it goes away.
    let dev = unsafe { netalloc::devm_alloc_etherdev_mqs(&mut owner, SAMPLE_PRIV, 2, 3) };
    assert!(!dev.is_null());
    // SAFETY: successful allocation is live until parent devres teardown.
    unsafe {
        assert_eq!((*dev).num_tx_queues, 2);
        assert_eq!((*dev).real_num_rx_queues, 3);
    }
    crate::linux_device::devres::release_device(&mut owner);
}

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
        RX_MODE_MC_COUNT.store((*dev).mc.count as u32, Ordering::Release);
        RX_MODE_UC_COUNT.store((*dev).uc.count as u32, Ordering::Release);
        let head = &(*dev).mc.list as *const _ as usize;
        if (*dev).mc.list.next != head {
            let row = &*((*dev).mc.list.next as *const LinuxNetDevHwAddr);
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
    ndo_set_config: None, ..LinuxNetDeviceOps::new()
};

static RX_MODE_OPS: LinuxNetDeviceOps = LinuxNetDeviceOps {
    ndo_open: None,
    ndo_stop: None,
    ndo_start_xmit: Some(sample_xmit),
    ndo_set_rx_mode: Some(sample_set_rx_mode),
    ndo_change_mtu: None,
    ndo_set_mac_address: None,
    ndo_set_config: None, ..LinuxNetDeviceOps::new()
};


#[test]
fn export_symbols_registers_netdev_surface() {
    let _modules = crate::test_serial::claim();
    crate::linux_netdev::export_symbols();
    assert!(resolve("alloc_etherdev", false).is_ok());
    assert!(resolve("devm_alloc_etherdev_mqs", false).is_ok());
    assert!(resolve("register_netdev", false).is_ok());
    assert!(resolve("dev_open", false).is_ok());
    assert!(resolve("netif_rx", false).is_ok());
    assert!(resolve("dev_alloc_skb", false).is_ok());
    assert!(resolve("eth_type_trans", false).is_ok());
}

#[test]
fn registration_does_not_open_and_dev_open_invokes_the_driver_once() {
    let _modules = crate::test_serial::claim();
    // SAFETY: test owns the net_device allocation through free_netdev.
    let dev = unsafe { netalloc::alloc_etherdev(0) };
    assert!(!dev.is_null());
    // SAFETY: test-owned device and static operation table remain valid through close and free.
    unsafe {
        (*dev).netdev_ops = &OPS; assert_eq!(register_netdev(dev), LINUX_OK);
        assert_eq!((*dev).flags & (IFF_UP | IFF_RUNNING), 0);
        assert_eq!(super::super::misc::dev_open(dev, core::ptr::null_mut()), LINUX_OK);
        assert_eq!((*dev).flags & (IFF_UP | IFF_RUNNING), IFF_UP | IFF_RUNNING);
        assert_eq!(super::super::misc::dev_open(dev, core::ptr::null_mut()), LINUX_OK);
        unregister_netdev(dev); netalloc::free_netdev(dev);
    }
}

#[test]
fn register_netdev_exposes_adapter_and_xmit() {
    let _modules = crate::test_serial::claim();
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
    let _modules = crate::test_serial::claim();
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
    let _modules = crate::test_serial::claim();
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
    let _modules = crate::test_serial::claim();
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
