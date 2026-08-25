    use super::*;

    #[test]
    fn addr_table_insert_remove_snapshot() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let before = addr_snapshot_ns(0).len();
        addr_insert(net::iface_addr::Ipv4IfaceAddr {
            ns: 0, iface: net::NetIfaceId::from_raw(9999),
            addr: net::Ipv4Addr::from_u32(u32::from_be_bytes([10, 9, 9, 9])), peer: None,
            mask: u32::MAX, broadcast: None, prefixlen: 32, scope: RT_SCOPE_UNIVERSE,
            flags: net::iface_addr::IFA_F_PERMANENT, proto: 0, rt_priority: 0,
            cacheinfo: net::iface_addr::Ipv4AddrCacheInfo::PERMANENT,
        });
        let after_insert = addr_snapshot_ns(0).len();
        assert_eq!(after_insert, before + 1);
        let n = addr_remove(0, 9999, [10, 9, 9, 9], 32);
        assert_eq!(n, 1);
        assert_eq!(addr_snapshot_ns(0).len(), before);
    }

    #[test]
    fn addr_insert_dedupes_same_key() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let row = net::iface_addr::Ipv4IfaceAddr {
            ns: 0, iface: net::NetIfaceId::from_raw(9998),
            addr: net::Ipv4Addr::from_u32(u32::from_be_bytes([10, 9, 9, 8])), peer: None,
            mask: u32::MAX, broadcast: None, prefixlen: 32, scope: RT_SCOPE_UNIVERSE,
            flags: net::iface_addr::IFA_F_PERMANENT, proto: 0, rt_priority: 0,
            cacheinfo: net::iface_addr::Ipv4AddrCacheInfo::PERMANENT,
        };
        let before = addr_snapshot_ns(0).len();
        addr_insert(row);
        addr_insert(row); // second insert should replace, not duplicate
        let after = addr_snapshot_ns(0).len();
        assert_eq!(after, before + 1);
        let _ = addr_remove(0, 9998, [10, 9, 9, 8], 32);
    }

    #[test]
    fn addrs_are_isolated_per_net_ns() {
        let row = |ns| net::iface_addr::Ipv4IfaceAddr {
            ns, iface: net::NetIfaceId::from_raw(9997),
            addr: net::Ipv4Addr::from_u32(u32::from_be_bytes([10, 9, 9, 7])), peer: None,
            mask: u32::MAX, broadcast: None, prefixlen: 32, scope: RT_SCOPE_UNIVERSE,
            flags: net::iface_addr::IFA_F_PERMANENT, proto: 0, rt_priority: 0,
            cacheinfo: net::iface_addr::Ipv4AddrCacheInfo::PERMANENT,
        };
        let n0 = addr_snapshot_ns(880).len();
        let n1 = addr_snapshot_ns(881).len();
        addr_insert(row(880));
        assert_eq!(addr_snapshot_ns(880).len(), n0 + 1);
        assert_eq!(addr_snapshot_ns(881).len(), n1);
        assert_eq!(addr_remove(881, 9997, [10, 9, 9, 7], 32), 0);
        assert_eq!(addr_remove(880, 9997, [10, 9, 9, 7], 32), 1);
    }

    #[test]
    fn rtm_newaddr_and_deladdr_mutate_table() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let iface = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), 0);
        let ifindex = visible_ifindex(iface, 0);
        let addr = [10, 9, 9, 6];
        let (new_hdr, new_msg) = addr_req(RTM_NEWADDR, ifindex, 32, addr);
        assert_eq!(ack_errno(&handle_newaddr(&new_hdr, &new_msg)), 0);
        assert!(addr_snapshot_ns(0).iter().any(|r|
            r.iface == iface && r.addr == net::Ipv4Addr::from_u32(u32::from_be_bytes(addr)) && r.prefixlen == 32));

        let (del_hdr, del_msg) = addr_req(RTM_DELADDR, ifindex, 32, addr);
        assert_eq!(ack_errno(&handle_deladdr(&del_hdr, &del_msg)), 0);
        assert!(!addr_snapshot_ns(0).iter().any(|r|
            r.iface == iface && r.addr == net::Ipv4Addr::from_u32(u32::from_be_bytes(addr)) && r.prefixlen == 32));
        let _ = net::global_stack().ifaces.unregister(iface);
    }


