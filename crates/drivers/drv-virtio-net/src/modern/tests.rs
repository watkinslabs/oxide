    use super::*;
    use net::NetDev;

    static TEST_STATE_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());

    const fn key(raw: u32) -> DeviceKey {
        DeviceKey::from_raw(raw)
    }

    fn state(bus: u8) -> ModernNetState {
        ModernNetState {
            device_key: key(bus as u32),
            bus,
            device: 1,
            function: 0,
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
                pa: 0x9000 + bus as u64,
                len: 2048,
            }],
            mac: [0x02, 0, 0, 0, 0, bus],
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
        uninstall_rx_softirq_handler();
        unregister_timers();
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
            1,
            1,
            0,
            9,
            2048,
            10
        ));
        assert!(is_modern_present_for(key(1)));
        assert_eq!(mac_for(key(1)), Some(MAC1));
        assert!(init_modern(
            key(2),
            resources_with_mac(&MAC2),
            2,
            1,
            0,
            9,
            2048,
            10
        ));
        assert_eq!(mac_for(key(2)), Some(MAC2));
        assert_eq!(modern_state_for(key(1)).unwrap().bus, 1);
        assert_eq!(modern_state_for(key(2)).unwrap().bus, 2);
        assert!(!init_modern(
            key(2),
            resources_with_mac(&MAC2),
            2,
            1,
            0,
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
            3,
            1,
            0,
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
            4,
            1,
            0,
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
        set_softirq_iface(key(1), net::NetIfaceId::from_raw(77), [10, 0, 0, 1]);
        set_softirq_iface(key(2), net::NetIfaceId::from_raw(88), [10, 0, 0, 2]);

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
        set_softirq_iface(key(1), net::NetIfaceId::from_raw(77), [10, 0, 0, 1]);

        assert!(uninstall_modern(key(1)));
        assert!(registered_iface_for(key(1)).is_none());
        assert!(first_iface_ip_for(key(1)).is_none());
        assert!(!uninstall_modern(key(1)));
    }

    #[test]
    fn shutdown_modern_quiesces_transport_without_forgetting_iface() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        set_registered_iface(key(1), net::NetIfaceId::from_raw(77));
        set_softirq_iface(key(1), net::NetIfaceId::from_raw(77), [10, 0, 0, 1]);
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
        assert_eq!(dev1.name(), "eth0");
        assert_eq!(dev2.name(), "eth1");
        assert_eq!(ensure_net_runtime(key(1)).name.as_str(), "eth0");
        assert_eq!(ensure_net_runtime(key(2)).name.as_str(), "eth1");

        let _ = remove_net_runtime(key(1));
        let rt3 = ensure_net_runtime(key(3));
        assert_eq!(rt3.name.as_str(), "eth0");
        clear_test_state();
    }

    #[test]
    fn arp_cache_is_keyed_by_device() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        let rt1 = ensure_net_runtime(key(1));
        let rt2 = ensure_net_runtime(key(2));
        let dst = net::Ipv4Addr::new(10, 0, 0, 2);
        let mac1 = net::MacAddr([1, 1, 1, 1, 1, 1]);
        let mac2 = net::MacAddr([2, 2, 2, 2, 2, 2]);
        rt1.arp.insert(dst, mac1);
        rt2.arp.insert(dst, mac2);

        let mut body = [0u8; 20];
        body[16..20].copy_from_slice(&dst.octets());
        assert_eq!(
            resolve_next_hop_mac(key(1), [0x02, 0, 0, 0, 0, 1], net::eth_p::IPV4, &body),
            Some(mac1)
        );
        assert_eq!(
            resolve_next_hop_mac(key(2), [0x02, 0, 0, 0, 0, 2], net::eth_p::IPV4, &body),
            Some(mac2)
        );
        let _ = remove_net_runtime(key(1));
        assert_eq!(
            resolve_next_hop_mac(key(2), [0x02, 0, 0, 0, 0, 2], net::eth_p::IPV4, &body),
            Some(mac2)
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

        let mut body = [0u8; net::ipv6::IPV6_HDR_LEN];
        net::ipv6::Ipv6Hdr::build(src, dst, net::IpProto::Udp, 0).write_to(&mut body);
        assert_eq!(
            resolve_next_hop_mac(key(1), [0x02, 0, 0, 0, 0, 1], net::eth_p::IPV6, &body),
            Some(mac1)
        );
        assert_eq!(
            resolve_next_hop_mac(key(2), [0x02, 0, 0, 0, 0, 2], net::eth_p::IPV6, &body),
            Some(mac2)
        );
        let _ = remove_net_runtime(key(1));
        assert_eq!(
            resolve_next_hop_mac(key(2), [0x02, 0, 0, 0, 0, 2], net::eth_p::IPV6, &body),
            Some(mac2)
        );
        clear_test_state();
    }

    #[test]
    fn rx_ndp_learning_is_keyed_by_device() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        let rt1 = ensure_net_runtime(key(1));
        let rt2 = ensure_net_runtime(key(2));
        let router = net::Ipv6Addr::from_segments([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
        let all_nodes = net::ndp::IPV6_ALL_NODES;
        let prefix = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0xabcd, 0, 0, 0, 0, 0]);
        let mac1 = net::MacAddr([0x02, 0, 0, 0, 0, 1]);
        let mac2 = net::MacAddr([0x02, 0, 0, 0, 0, 2]);
        let ra1 = net::ndp::RouterAdvertisement::build_one_prefix(
            router, all_nodes, mac1, 1800, prefix, 64, net::ndp::NDP_PIO_FLAG_AUTO,
        );
        let ra2 = net::ndp::RouterAdvertisement::build_one_prefix(
            router, all_nodes, mac2, 1800, prefix, 64, net::ndp::NDP_PIO_FLAG_AUTO,
        );
        let mut frame1 = alloc::vec![0u8; net::ipv6::IPV6_HDR_LEN + ra1.len()];
        net::ipv6::Ipv6Hdr::build(
            router, all_nodes, net::IpProto::Icmpv6, ra1.len() as u16,
        )
        .write_to(&mut frame1[..net::ipv6::IPV6_HDR_LEN]);
        frame1[net::ipv6::IPV6_HDR_LEN..].copy_from_slice(&ra1);
        let mut frame2 = alloc::vec![0u8; net::ipv6::IPV6_HDR_LEN + ra2.len()];
        net::ipv6::Ipv6Hdr::build(
            router, all_nodes, net::IpProto::Icmpv6, ra2.len() as u16,
        )
        .write_to(&mut frame2[..net::ipv6::IPV6_HDR_LEN]);
        frame2[net::ipv6::IPV6_HDR_LEN..].copy_from_slice(&ra2);

        learn_ndp_from_ipv6(key(1), &frame1);
        learn_ndp_from_ipv6(key(2), &frame2);
        assert_eq!(rt1.ndp.lookup(router), Some(mac1));
        assert_eq!(rt2.ndp.lookup(router), Some(mac2));
        clear_test_state();
    }

    #[test]
    fn rx_runtime_is_keyed_by_device() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_rx_runtime();
        set_softirq_iface(key(0x0012_0304), net::NetIfaceId::from_raw(9), [10, 0, 0, 2]);
        assert_eq!(first_iface_ip_for(key(0x0012_0304)), Some(net::Ipv4Addr::new(10, 0, 0, 2)));
        assert!(set_softirq_ip_for_iface(net::NetIfaceId::from_raw(9), [10, 0, 0, 3]));
        assert_eq!(first_iface_ip_for(key(0x0012_0304)), Some(net::Ipv4Addr::new(10, 0, 0, 3)));
        assert!(!set_softirq_ip_for_iface(net::NetIfaceId::from_raw(10), [10, 0, 0, 4]));
        assert_eq!(first_iface_ip_for(key(0x0012_0304)), Some(net::Ipv4Addr::new(10, 0, 0, 3)));
        clear_rx_runtime();
        assert!(first_iface_ip_for(key(0x0012_0304)).is_none());
    }

    #[test]
    fn removing_one_rx_runtime_keeps_shared_softirq_owned() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        install_rx_softirq_handler();
        set_softirq_iface(key(1), net::NetIfaceId::from_raw(77), [10, 0, 0, 1]);
        set_softirq_iface(key(2), net::NetIfaceId::from_raw(88), [10, 0, 0, 2]);

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
        set_softirq_iface(key(1), net::NetIfaceId::from_raw(77), [10, 0, 0, 1]);

        assert!(uninstall_modern(key(1)));
        assert!(!SOFTIRQ_INSTALLED.load(Ordering::Acquire));
        assert!(first_iface_ip_for(key(1)).is_none());
        clear_test_state();
    }

    #[test]
    fn solicited_node_address_uses_low_24_bits() {
        let _guard = TEST_STATE_LOCK.lock();
        let ip = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0x1234, 0x5678]);
        let got = solicited_node_multicast(ip);
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
            solicited_node_ethernet(ip),
            net::MacAddr([0x33, 0x33, 0xff, 0x34, 0x56, 0x78])
        );
    }
