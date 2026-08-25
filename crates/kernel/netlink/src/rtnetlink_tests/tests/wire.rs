    use super::*;

    #[test]
    fn rtmsg_size_matches_linux() {
        assert_eq!(Rtmsg::SIZE, 12);
    }

    #[test]
    fn build_newroute_reply_well_formed() {
        let _domain = net::hosted_fixture::init_net_domain();
        let bytes = build_newroute_row_reply(1, 42, RouteRow {
            ns: 0, table: RT_TABLE_MAIN as u32, protocol: RTPROT_KERNEL,
            scope: RT_SCOPE_LINK, kind: RTN_UNICAST,
            dst: Some(([10, 0, 2, 0], 24)), gateway: None,
            oif_ifindex: 2, prefsrc: Some([10, 0, 2, 15]),
            metric: 0, metrics: net::RouteMetrics::NONE, flags: 0, weight: 1, nh_flags: 0,
        }, true);
        let ty = u16::from_ne_bytes([bytes[4], bytes[5]]);
        assert_eq!(ty, RTM_NEWROUTE);
        assert_eq!(bytes[Nlmsghdr::SIZE], AF_INET);
        assert_eq!(bytes[Nlmsghdr::SIZE + 1], 24); // dst_len
        assert_eq!(bytes[Nlmsghdr::SIZE + 4], RT_TABLE_MAIN);
    }

    #[test]
    fn route_key_masks_destination_prefix() {
        let (dst, prefix) = route_key(Some(([192, 168, 99, 123], 24)));
        assert_eq!(dst.octets(), [192, 168, 99, 0]);
        assert_eq!(prefix, 24);
        let (default_dst, default_prefix) = route_key(None);
        assert_eq!(default_dst.octets(), [0, 0, 0, 0]);
        assert_eq!(default_prefix, 0);
    }

    #[test]
    fn build_newaddr_reply_well_formed() {
        let bytes = build_newaddr_reply(
            1, 42, 2, "eth0", [10, 0, 2, 15], None, Some([10, 0, 2, 255]), 24,
            RT_SCOPE_UNIVERSE, net::iface_addr::IFA_F_PERMANENT, 0, 0,
            IfaCacheInfo::PERMANENT, crate::flags::NLM_F_MULTI, None,
        );
        // Header nlmsg_type == RTM_NEWADDR
        let ty = u16::from_ne_bytes([bytes[4], bytes[5]]);
        assert_eq!(ty, RTM_NEWADDR);
        // ifaddrmsg right after the 16-byte header
        assert_eq!(bytes[Nlmsghdr::SIZE], AF_INET);
        assert_eq!(bytes[Nlmsghdr::SIZE + 1], 24); // prefixlen
        assert_eq!(bytes[Nlmsghdr::SIZE + 2], net::iface_addr::IFA_F_PERMANENT as u8);
        assert_eq!(bytes[Nlmsghdr::SIZE + 3], RT_SCOPE_UNIVERSE);
        let attrs = &bytes[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
        assert_eq!(find_attr(attrs, ifa::IFA_LOCAL).unwrap(), &[10, 0, 2, 15]);
        assert_eq!(find_attr(attrs, ifa::IFA_ADDRESS).unwrap(), &[10, 0, 2, 15]);
        // The broadcast is the one the setter stated — the reference never
        // derives one from the prefix.
        assert_eq!(find_attr(attrs, ifa::IFA_BROADCAST).unwrap(), &[10, 0, 2, 255]);
        assert!(find_attr(attrs, ifa::IFA_FLAGS).is_some());
        let ci = find_attr(attrs, ifa::IFA_CACHEINFO)
            .expect("IFA_CACHEINFO");
        assert_eq!(u32::from_ne_bytes(ci[0..4].try_into().unwrap()), u32::MAX);
        assert_eq!(u32::from_ne_bytes(ci[4..8].try_into().unwrap()), u32::MAX);
    }

    #[test]
    fn build_newaddr_reply_encodes_distinct_ipv4_peer_without_broadcast() {
        let local = [192, 0, 2, 10];
        let peer = [192, 0, 2, 11];
        let bytes = build_newaddr_reply(
            1, 42, 2, "ppp0", local, Some(peer), None, 32, RT_SCOPE_UNIVERSE,
            net::iface_addr::IFA_F_PERMANENT, 0, 0, IfaCacheInfo::PERMANENT,
            crate::flags::NLM_F_MULTI, None,
        );
        let attrs = &bytes[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
        assert_eq!(find_attr(attrs, ifa::IFA_LOCAL).unwrap(), &local);
        assert_eq!(find_attr(attrs, ifa::IFA_ADDRESS).unwrap(), &peer);
        assert!(find_attr(attrs, ifa::IFA_BROADCAST).is_none());
    }

    // An IPv6 address with no point-to-point peer reports IFA_ADDRESS alone —
    // no IFA_LOCAL, and no IFA_LABEL: the label attribute names an IPv4 alias
    // and the IPv6 fill does not emit one.
    #[test]
    fn build_newaddr6_reply_well_formed() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ci = IfaCacheInfo { preferred: 1800, valid: 3600, cstamp: 11, tstamp: 12 };
        let bytes = build_newaddr6_reply(1, 42, 2, addr, None, 64, RT_SCOPE_UNIVERSE,
            net::iface_addr::IFA_F_PERMANENT, 0, 0, ci, crate::flags::NLM_F_MULTI, None);
        assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]), RTM_NEWADDR);
        assert_eq!(bytes[Nlmsghdr::SIZE], AF_INET6);
        assert_eq!(bytes[Nlmsghdr::SIZE + 1], 64);
        assert_eq!(bytes[Nlmsghdr::SIZE + 2], net::iface_addr::IFA_F_PERMANENT as u8);
        let attrs = &bytes[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
        assert_eq!(find_attr(attrs, ifa::IFA_ADDRESS).expect("IFA_ADDRESS"), &addr);
        assert!(find_attr(attrs, ifa::IFA_LOCAL).is_none());
        assert!(find_attr(attrs, ifa::IFA_LABEL).is_none());
        assert!(find_attr(attrs, ifa::IFA_PROTO).is_none());
        assert!(find_attr(attrs, ifa::IFA_RT_PRIORITY).is_none());
        let got_ci = find_attr(attrs, ifa::IFA_CACHEINFO).expect("IFA_CACHEINFO");
        assert_eq!(u32::from_ne_bytes(got_ci[0..4].try_into().unwrap()), 1800);
        assert_eq!(u32::from_ne_bytes(got_ci[4..8].try_into().unwrap()), 3600);
        assert_eq!(u32::from_ne_bytes(got_ci[8..12].try_into().unwrap()), 11);
        assert_eq!(u32::from_ne_bytes(got_ci[12..16].try_into().unwrap()), 12);
    }

    // A point-to-point row reports the local address in IFA_LOCAL and the peer
    // in IFA_ADDRESS, and the two optional attributes appear once set.
    #[test]
    fn build_newaddr6_reply_reports_peer_proto_and_priority() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut peer = addr;
        peer[15] = 2;
        let ci = IfaCacheInfo { preferred: 0, valid: 0, cstamp: 0, tstamp: 0 };
        let bytes = build_newaddr6_reply(1, 42, 2, addr, Some(peer), 128, RT_SCOPE_UNIVERSE,
            0, 3, 1024, ci, 0, None);
        let attrs = &bytes[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
        assert_eq!(find_attr(attrs, ifa::IFA_LOCAL).expect("IFA_LOCAL"), &addr);
        assert_eq!(find_attr(attrs, ifa::IFA_ADDRESS).expect("IFA_ADDRESS"), &peer);
        assert_eq!(find_attr(attrs, ifa::IFA_PROTO).expect("IFA_PROTO"), &[3]);
        assert_eq!(u32::from_ne_bytes(
            find_attr(attrs, ifa::IFA_RT_PRIORITY).expect("IFA_RT_PRIORITY").try_into().unwrap()),
            1024);
    }

    #[test]
    fn put_nlattr_str_nul_terminates() {
        let mut out = Vec::new();
        put_nlattr_str(&mut out, ifla::IFLA_IFNAME, "eth0");
        // header(4) + "eth0\0"(5) = 9, padded to 12.
        assert_eq!(out.len(), 12);
        let nla_len = u16::from_ne_bytes([out[0], out[1]]) as usize;
        assert_eq!(nla_len, 9);
        assert_eq!(&out[4..9], b"eth0\0");
    }

    #[test]
    fn newlink_emits_stats64_in_linux_order() {
        let stats = LinkStats64 {
            rx_packets: 1,
            tx_packets: 2,
            rx_bytes: 3,
            tx_bytes: 4,
            rx_errors: 5,
            tx_errors: 6,
            rx_dropped: 7,
            tx_dropped: 8,
        };
        let msg = build_newlink_reply(
            1,
            2,
            3,
            "eth0",
            [2, 0, 0, 0, 0, 1],
            &[u8::MAX; core::mem::size_of::<net::MacAddr>()],
            1500,
            false,
            iff::IFF_UP | iff::IFF_RUNNING,
            stats,
            true, None,
        );
        let attrs = &msg[Nlmsghdr::SIZE + Ifinfomsg::SIZE..];
        let raw = find_attr(attrs, ifla::IFLA_STATS64).expect("IFLA_STATS64");
        assert_eq!(raw.len(), LinkStats64::SIZE);
        let field = |i: usize| u64::from_ne_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
        assert_eq!(field(0), 1);
        assert_eq!(field(1), 2);
        assert_eq!(field(2), 3);
        assert_eq!(field(3), 4);
        assert_eq!(field(4), 5);
        assert_eq!(field(5), 6);
        assert_eq!(field(6), 7);
        assert_eq!(field(7), 8);
        assert_eq!(field(24), 0);
    }

