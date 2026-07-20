mod assignment_generation;
mod packet_observation;
mod uninstall;
mod support;
    use super::*;
    use super::netdev::set_test_unregister_netdev;
    use support::{install_test_rx, set_test_rx};
    use net::NetDev;
use core::sync::atomic::Ordering;
    static TEST_STATE_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());

    const fn key(raw: u32) -> DeviceKey {
        DeviceKey::from_raw(raw)
    }

    fn state(raw: u32) -> ModernNetState {
        ModernNetState {
            device_key: key(raw),
            cfg_va: 0,
            hhdm: 0,
            rxq: virtio::VirtQueueResource {
                index: 0,
                size: 256,
                desc_pa: 0,
                driver_pa: 0,
                device_pa: 0,
                notify_va: 0,
                notify_off: 0,
            },
            txq: virtio::VirtQueueResource {
                index: 1,
                size: 256,
                desc_pa: 0,
                driver_pa: 0,
                device_pa: 0,
                notify_va: 0,
                notify_off: 0,
            },
            rx_bufs: alloc::vec![virtio::VirtioNetRxBuffer {
                desc_id: 0,
                pa: 0x9000 + raw as u64,
                len: 2048,
            }],
            mac: [0x02, 0, 0, 0, 0, raw as u8],
            tx0_buf_pa: 0,
            tx_last_used: 0,
            tx_next_avail: 0,
            rx_last_used: 0,
            rx_next_avail: 1,
        }
    }

    fn clear_test_state() {
        MODERN_DEVS.lock().clear();
        REGISTERED_NETDEVS.lock().clear();
        NET_RUNTIMES.lock().clear();
        clear_rx_runtime();
        state::clear_test_released_frames();
        uninstall_rx_softirq_handler();
        set_test_unregister_netdev(true);
    }

    fn resources_with_mac(mac: &'static [u8; 6]) -> virtio::VirtioResources {
        let mut resources = virtio::VirtioResources::new(1, 1);
        resources.set_queue(virtio::VirtQueueResource {
            index: 0,
            size: 256,
            desc_pa: 1,
            driver_pa: 2,
            device_pa: 3,
            notify_va: 4,
            notify_off: 0,
        });
        resources.set_queue(virtio::VirtQueueResource {
            index: 1,
            size: 256,
            desc_pa: 5,
            driver_pa: 6,
            device_pa: 7,
            notify_va: 8,
            notify_off: 0,
        });
        resources.with_device_cfg_va(mac.as_ptr() as u64)
    }

    #[test]
    fn init_modern_accepts_distinct_devices_and_rejects_duplicate_key() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        static MAC1: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
        static MAC2: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
        assert!(init_modern(
            key(1),
            resources_with_mac(&MAC1),
            9,
            2048,
            10
        ));
        assert!(is_modern_present_for(key(1)));
        assert_eq!(mac_for(key(1)), Some(MAC1));
        assert!(init_modern(
            key(2),
            resources_with_mac(&MAC2),
            9,
            2048,
            10
        ));
        assert_eq!(mac_for(key(2)), Some(MAC2));
        assert_eq!(modern_state_for(key(1)).unwrap().device_key, key(1));
        assert_eq!(modern_state_for(key(2)).unwrap().device_key, key(2));
        assert!(!init_modern(
            key(2),
            resources_with_mac(&MAC2),
            9,
            2048,
            10
        ));
        MODERN_DEVS.lock().clear();
        assert!(!is_modern_present());
    }

    #[test]
    fn init_modern_with_rx_pool_records_pool_and_rejects_duplicate_desc() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        static MAC1: [u8; 6] = [0x02, 0, 0, 0, 0, 3];
        static MAC2: [u8; 6] = [0x02, 0, 0, 0, 0, 4];

        assert!(init_modern_with_rx_pool(
            key(3),
            resources_with_mac(&MAC1),
            alloc::vec![
                virtio::VirtioNetRxBuffer {
                    desc_id: 0,
                    pa: 0x9000,
                    len: 2048,
                },
                virtio::VirtioNetRxBuffer {
                    desc_id: 1,
                    pa: 0xa000,
                    len: 2048,
                },
            ],
            0xb000,
        ));
        let state = modern_state_for(key(3)).unwrap();
        assert_eq!(state.rx_bufs.len(), 2);
        assert_eq!(state.rx_bufs[0].desc_id, 0);
        assert_eq!(state.rx_bufs[1].desc_id, 1);
        assert_eq!(state.rx_next_avail, 2);
        clear_test_state();

        assert!(!init_modern_with_rx_pool(
            key(4),
            resources_with_mac(&MAC2),
            alloc::vec![
                virtio::VirtioNetRxBuffer {
                    desc_id: 0,
                    pa: 0x9000,
                    len: 2048,
                },
                virtio::VirtioNetRxBuffer {
                    desc_id: 0,
                    pa: 0xa000,
                    len: 2048,
                },
            ],
            0xb000,
        ));
        assert!(!is_modern_present_for(key(4)));
    }

    #[test]
    fn init_modern_unwinds_state_on_late_netdev_registration_failure() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        static MAC1: [u8; 6] = [0x02, 0, 0, 0, 0, 5];
        let _ = install_test_rx(key(5), net::NetIfaceId::from_raw(55));
        set_registered_iface(key(5), net::NetIfaceId::from_raw(55));
        state::fail_next_netdev_registration();

        assert!(!init_modern_with_rx_pool(
            key(5),
            resources_with_mac(&MAC1),
            alloc::vec![virtio::VirtioNetRxBuffer {
                desc_id: 0,
                pa: 0x9000,
                len: 2048,
            }],
            0xb000,
        ));
        assert!(!is_modern_present_for(key(5)));
        assert!(registered_iface_for(key(5)).is_none());
        assert!(net_runtime_for(key(5)).is_none());
        assert!(first_iface_ip_for(key(5)).is_none());
        assert!(!SOFTIRQ_INSTALLED.load(Ordering::Acquire));
        assert_eq!(state::test_released_frames(), 2);
        assert_eq!(state::test_resets(), 1);
    }

    #[test]
    fn uninstall_modern_removes_only_named_device() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        {
            let mut devices = MODERN_DEVS.lock();
            devices.push(state(1));
            devices.push(state(2));
        }
        set_registered_iface(key(1), net::NetIfaceId::from_raw(77));
        set_registered_iface(key(2), net::NetIfaceId::from_raw(88));
        let _ = set_test_rx(key(1), net::NetIfaceId::from_raw(77), [10, 0, 0, 1]);
        let _ = set_test_rx(key(2), net::NetIfaceId::from_raw(88), [10, 0, 0, 2]);

        assert!(uninstall_modern(key(1)));
        assert!(!is_modern_present_for(key(1)));
        assert!(is_modern_present_for(key(2)));
        assert!(registered_iface_for(key(1)).is_none());
        assert_eq!(registered_iface_for(key(2)).unwrap().raw(), 88);
        assert!(set_softirq_ip_for_iface(net::NetIfaceId::from_raw(88), [10, 0, 0, 3]));
        assert_eq!(first_iface_ip_for(key(2)), Some(net::Ipv4Addr::new(10, 0, 0, 3)));

        assert!(uninstall_modern(key(2)));
        assert!(!is_modern_present());
    }

    #[test]
    fn uninstall_modern_clears_keyed_runtime_without_primary_record() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        set_registered_iface(key(1), net::NetIfaceId::from_raw(77));
        let _ = ensure_net_runtime(key(1));
        let _ = set_test_rx(key(1), net::NetIfaceId::from_raw(77), [10, 0, 0, 1]);

        assert!(uninstall_modern(key(1)));
        assert!(registered_iface_for(key(1)).is_none());
        assert!(net_runtime_for(key(1)).is_none());
        assert!(first_iface_ip_for(key(1)).is_none());
        assert!(!uninstall_modern(key(1)));
    }

    #[test]
    fn uninstall_modern_removes_only_named_netdev_runtime() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        {
            let mut devices = MODERN_DEVS.lock();
            devices.push(state(1));
            devices.push(state(2));
        }
        set_registered_iface(key(1), net::NetIfaceId::from_raw(77));
        set_registered_iface(key(2), net::NetIfaceId::from_raw(88));
        assert_eq!(ensure_net_runtime(key(1)).name.as_str(), "eth0");
        assert_eq!(ensure_net_runtime(key(2)).name.as_str(), "eth1");

        assert!(uninstall_modern(key(1)));
        assert!(registered_iface_for(key(1)).is_none());
        assert!(net_runtime_for(key(1)).is_none());
        assert_eq!(registered_iface_for(key(2)).unwrap().raw(), 88);
        assert_eq!(net_runtime_for(key(2)).unwrap().name.as_str(), "eth1");
        clear_test_state();
    }

    #[test]
    fn shutdown_modern_quiesces_transport_without_forgetting_iface() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        set_registered_iface(key(1), net::NetIfaceId::from_raw(77));
        let _ = set_test_rx(key(1), net::NetIfaceId::from_raw(77), [10, 0, 0, 1]);
        MODERN_DEVS.lock().push(state(1));

        assert!(shutdown_modern(key(1)));
        assert!(!is_modern_present());
        assert!(modern_state_for(key(1)).is_none());
        assert_eq!(registered_iface_for(key(1)).unwrap().raw(), 77);
        assert!(registered_iface_for(key(2)).is_none());
        assert!(first_iface_ip_for(key(1)).is_none());
        assert!(matches!(tx_frame_for(key(1), &[0; 14]), Err(TxErr::NotPresent)));
    }

    #[test]
    fn registered_iface_is_keyed_by_device() {
        let _guard = TEST_STATE_LOCK.lock();
        REGISTERED_NETDEVS.lock().clear();
        set_registered_iface(key(0x0012_0304), net::NetIfaceId::from_raw(9));
        assert_eq!(registered_iface_for(key(0x0012_0304)).unwrap().raw(), 9);
        assert!(registered_iface_for(key(0x0012_0305)).is_none());
        set_registered_iface(key(0x0012_0305), net::NetIfaceId::from_raw(10));
        let snapshot = registered_ifaces();
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.iter().any(|(dev_key, id)| *dev_key == key(0x0012_0304) && id.raw() == 9));
        assert!(snapshot.iter().any(|(dev_key, id)| *dev_key == key(0x0012_0305) && id.raw() == 10));
        assert_eq!(registered_iface_for(key(0x0012_0305)).unwrap().raw(), 10);
        assert_eq!(remove_registered_iface(key(0x0012_0304)).unwrap().raw(), 9);
        assert!(registered_iface_for(key(0x0012_0304)).is_none());
        assert_eq!(registered_iface_for(key(0x0012_0305)).unwrap().raw(), 10);
        let snapshot = registered_ifaces();
        assert_eq!(snapshot, alloc::vec![(key(0x0012_0305), net::NetIfaceId::from_raw(10))]);
        REGISTERED_NETDEVS.lock().clear();
    }

    #[test]
    fn net_runtime_names_are_unique_and_reusable() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        {
            let mut devices = MODERN_DEVS.lock();
            devices.push(state(1));
            devices.push(state(2));
        }
        let dev1 = VirtioNetDev::new_for(key(1)).unwrap();
        let dev2 = VirtioNetDev::new_for(key(2)).unwrap();
        assert_eq!(dev1.device_key(), key(1));
        assert_eq!(dev2.device_key(), key(2));
        assert_eq!(dev1.name(), "eth0");
        assert_eq!(dev2.name(), "eth1");
        let (rt1, rt2) = (ensure_net_runtime(key(1)), ensure_net_runtime(key(2)));
        assert_eq!((rt1.name.as_str(), rt2.name.as_str()), ("eth0", "eth1"));
        rt1.rx_packets.store(3, Ordering::Relaxed); rt1.rx_bytes.store(30, Ordering::Relaxed);
        rt2.rx_packets.store(5, Ordering::Relaxed); rt2.rx_bytes.store(50, Ordering::Relaxed);
        assert_eq!((dev1.stats().rx_packets, dev1.stats().rx_bytes), (3, 30));
        assert_eq!((dev2.stats().rx_packets, dev2.stats().rx_bytes), (5, 50));

        let _ = remove_net_runtime(key(1));
        let rt3 = ensure_net_runtime(key(3));
        assert_eq!(rt3.name.as_str(), "eth0");
        clear_test_state();
    }

    #[test]
    fn ipv4_unicast_resolution_is_owned_by_net_stack() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        let dst = net::Ipv4Addr::new(10, 0, 0, 2);

        assert_eq!(
            resolve_next_hop_mac(key(1), [0x02, 0, 0, 0, 0, 1], net::pkt::TxNextHop::V4(dst)),
            None
        );
        assert_eq!(
            resolve_next_hop_mac(key(2), [0x02, 0, 0, 0, 0, 2], net::pkt::TxNextHop::V4(dst)),
            None
        );
        clear_test_state();
    }

    #[test]
    fn ipv4_gateway_resolution_is_owned_by_net_stack() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        let gateway = net::Ipv4Addr::new(10, 0, 0, 1);

        assert_eq!(
            resolve_next_hop_mac(key(1), [0x02, 0, 0, 0, 0, 1],
                net::pkt::TxNextHop::V4(gateway)),
            None,
        );
        clear_test_state();
    }

    #[test]
    fn ndp_cache_is_keyed_by_device() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        let rt1 = ensure_net_runtime(key(1));
        let rt2 = ensure_net_runtime(key(2));
        let src = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
        let dst = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2]);
        let mac1 = net::MacAddr([1, 1, 1, 1, 1, 1]);
        let mac2 = net::MacAddr([2, 2, 2, 2, 2, 2]);
        rt1.ndp.insert(dst, mac1);
        rt2.ndp.insert(dst, mac2);

        assert_eq!(
            resolve_next_hop_mac(key(1), [0x02, 0, 0, 0, 0, 1],
                net::pkt::TxNextHop::V6 { addr: dst, src }),
            Some(mac1)
        );
        assert_eq!(
            resolve_next_hop_mac(key(2), [0x02, 0, 0, 0, 0, 2],
                net::pkt::TxNextHop::V6 { addr: dst, src }),
            Some(mac2)
        );
        let _ = remove_net_runtime(key(1));
        assert_eq!(
            resolve_next_hop_mac(key(2), [0x02, 0, 0, 0, 0, 2],
                net::pkt::TxNextHop::V6 { addr: dst, src }),
            Some(mac2)
        );
        clear_test_state();
    }

    #[test]
    fn rx_runtime_is_keyed_by_device() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        let _ = install_test_rx(key(0x0012_0304), net::NetIfaceId::from_raw(9));
        let _ = install_test_rx(key(0x0012_0305), net::NetIfaceId::from_raw(10));
        assert!(SOFTIRQ_INSTALLED.load(Ordering::Acquire));
        assert_eq!(first_iface_ip_for(key(0x0012_0304)), Some(net::Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(first_iface_ip_for(key(0x0012_0305)), Some(net::Ipv4Addr::new(0, 0, 0, 0)));
        assert!(set_softirq_ip_for_iface(net::NetIfaceId::from_raw(9), [10, 0, 0, 3]));
        assert_eq!(first_iface_ip_for(key(0x0012_0304)), Some(net::Ipv4Addr::new(10, 0, 0, 3)));
        assert_eq!(first_iface_ip_for(key(0x0012_0305)), Some(net::Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!set_softirq_ip_for_iface(net::NetIfaceId::from_raw(11), [10, 0, 0, 4]));
        assert_eq!(first_iface_ip_for(key(0x0012_0304)), Some(net::Ipv4Addr::new(10, 0, 0, 3)));
        assert!(first_iface_ip_for(key(0x0012_0305)).is_some());
        clear_test_state();
    }

    #[test]
    fn rx_runtime_install_does_not_seed_boot_ipv4_policy() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        let iface = net::NetIfaceId::from_raw(77);
        let _ = install_test_rx(key(1), iface);
        assert_eq!(first_iface_ip_for(key(1)), Some(net::Ipv4Addr::new(0, 0, 0, 0)));
        assert!(set_softirq_ip_for_iface(iface, [10, 0, 0, 3]));
        assert_eq!(first_iface_ip_for(key(1)), Some(net::Ipv4Addr::new(10, 0, 0, 3)));
        clear_test_state();
    }

    #[test]
    fn removing_one_rx_runtime_keeps_shared_rx_runtime_owned() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        let _ = install_test_rx(key(1), net::NetIfaceId::from_raw(77));
        let _ = install_test_rx(key(2), net::NetIfaceId::from_raw(88));

        let empty_after_first = remove_rx_runtime_for(key(1))
            .expect("expected first RX runtime removal");
        assert!(!empty_after_first);
        release_rx_shared_runtime_if_last(empty_after_first);
        assert!(SOFTIRQ_INSTALLED.load(Ordering::Acquire));
        assert!(first_iface_ip_for(key(2)).is_some());

        let empty_after_last = remove_rx_runtime_for(key(2))
            .expect("expected last RX runtime removal");
        assert!(empty_after_last);
        release_rx_shared_runtime_if_last(empty_after_last);
        assert!(!SOFTIRQ_INSTALLED.load(Ordering::Acquire));
        clear_test_state();
    }

    #[test]
    fn uninstall_without_primary_state_releases_last_rx_runtime() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        install_rx_softirq_handler();
        let _ = set_test_rx(key(1), net::NetIfaceId::from_raw(77), [10, 0, 0, 1]);

        assert!(uninstall_modern(key(1)));
        assert!(!SOFTIRQ_INSTALLED.load(Ordering::Acquire));
        assert!(first_iface_ip_for(key(1)).is_none());
        clear_test_state();
    }

    #[test]
    fn solicited_node_address_uses_low_24_bits() {
        let _guard = TEST_STATE_LOCK.lock();
        let ip = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0x1234, 0x5678]);
        let got = test_solicited_node_multicast(ip);
        assert_eq!(
            got,
            net::Ipv6Addr::from_segments([0xff02, 0, 0, 0, 0, 0x0001, 0xff34, 0x5678])
        );
    }

    #[test]
    fn solicited_node_ethernet_uses_low_24_bits() {
        let _guard = TEST_STATE_LOCK.lock();
        let ip = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0x1234, 0x5678]);
        assert_eq!(
            test_solicited_node_ethernet(ip),
            net::MacAddr([0x33, 0x33, 0xff, 0x34, 0x56, 0x78])
        );
    }
