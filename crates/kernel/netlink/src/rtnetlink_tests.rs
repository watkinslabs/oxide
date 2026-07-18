    use alloc::{sync::Arc, vec::Vec};

    use crate::{nlmsg_align, Nlmsghdr};

    use super::*;
    use super::route_ops::route_key;
    use super::rtnetlink_link::LinkStats64;

    struct MovingDev;

    impl net::NetDev for MovingDev {
        fn name(&self) -> &str { "eth-stable" }
        fn mac(&self) -> net::MacAddr { net::MacAddr([2, 0, 0, 0, 0, 1]) }
        fn mtu(&self) -> u32 { 1500 }
        fn xmit(&self, _pkt: net::Pkt) -> net::NetResult<()> { Ok(()) }
        fn retire_namespace(&self) {}
        fn namespace_drop_action(&self) -> net::NamespaceDropAction {
            net::NamespaceDropAction::MoveToInitial
        }
    }

    #[path = "rtnetlink_tests/route_semantics.rs"]
    mod route_semantics;
    #[path = "rtnetlink_tests/notification_races.rs"]
    mod notification_races;
    #[path = "rtnetlink_tests/address_semantics.rs"]
    mod address_semantics;

    fn visible_ifindex(iface: net::NetIfaceId, ns: u64) -> u32 {
        net::global_stack().ifaces.ifindex_in_ns(iface, ns).unwrap()
    }

    fn find_attr(attrs: &[u8], needle: u16) -> Option<&[u8]> {
        let mut off = 0;
        while off + 4 <= attrs.len() {
            let len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
            let ty = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
            if len < 4 || off + len > attrs.len() { break; }
            if ty == needle { return Some(&attrs[off + 4..off + len]); }
            off += nlmsg_align(len);
        }
        None
    }

    #[test]
    fn rtm_constants_match_linux() {
        assert_eq!(RTM_NEWLINK,  16);
        assert_eq!(RTM_GETLINK,  18);
        assert_eq!(RTM_NEWADDR,  20);
        assert_eq!(RTM_DELADDR,  21);
        assert_eq!(RTM_GETADDR,  22);
        assert_eq!(RTM_NEWROUTE, 24);
        assert_eq!(RTM_GETROUTE, 26);
        assert_eq!(RTM_NEWRULE,  32);
        assert_eq!(RTM_GETRULE,  34);
    }

    // K4: an RTM_GETLINK dump must end with a well-formed NLMSG_DONE.
    // Modern Linux + iproute2 require the DONE to carry a 4-byte error code
    // (0=success) in its payload, so nlmsg_len = SIZE+4 = 20; a header-only
    // DONE made iproute2 print "Dump terminated". The DONE is the last 20
    // bytes (16-byte header + 4-byte err); its header sits at [len-20..len-4].
    #[test]
    fn getlink_dump_ends_with_nlmsg_done() {
        const DONE_LEN: usize = crate::Nlmsghdr::SIZE + 4;
        let req = crate::Nlmsghdr { nlmsg_len: 32, nlmsg_type: RTM_GETLINK,
            nlmsg_flags: crate::flags::NLM_F_DUMP, nlmsg_seq: 7, nlmsg_pid: 42 };
        let reply = handle_getlink(&req);
        let done = crate::Nlmsghdr::parse(&reply[reply.len() - DONE_LEN..]).unwrap();
        assert_eq!(done.nlmsg_type, crate::msg::NLMSG_DONE);
        assert_eq!(done.nlmsg_len, DONE_LEN as u32);
        assert!(done.nlmsg_flags & crate::flags::NLM_F_MULTI != 0);
        assert_eq!((done.nlmsg_seq, done.nlmsg_pid), (7, 42), "DONE echoes seq/pid");
        // The 4-byte trailing error code is 0 (success).
        assert_eq!(&reply[reply.len() - 4..], &[0u8; 4], "DONE err=0");
    }

    #[test]
    fn ifinfomsg_size_matches_linux() {
        assert_eq!(Ifinfomsg::SIZE, 16);
    }

    #[test]
    fn put_nlattr_pads_to_4_bytes() {
        let mut out = Vec::new();
        put_nlattr(&mut out, ifla::IFLA_IFNAME, b"eth0");
        // 4-byte header + 4-byte payload, already aligned, no pad.
        assert_eq!(out.len(), 8);
        // header len field covers header+payload, not pad.
        let nla_len = u16::from_ne_bytes([out[0], out[1]]) as usize;
        assert_eq!(nla_len, 8);

        let mut out2 = Vec::new();
        put_nlattr(&mut out2, ifla::IFLA_IFNAME, b"lo");
        // 4-byte header + 2-byte payload = 6 raw, padded to 8.
        assert_eq!(out2.len(), 8);
        let nla_len2 = u16::from_ne_bytes([out2[0], out2[1]]) as usize;
        assert_eq!(nla_len2, 6);
    }

    #[test]
    fn ifaddrmsg_size_matches_linux() {
        assert_eq!(Ifaddrmsg::SIZE, 8);
    }

    #[test]
    fn route_table_insert_remove_snapshot() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let before = route_snapshot_ns(0).len();
        route_insert(RouteRow {
            ns: 0,
            table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC,
            scope: RT_SCOPE_LINK, kind: RTN_UNICAST,
            dst: Some(([192, 168, 99, 0], 24)),
            gateway: None, oif_ifindex: 7777, prefsrc: None,
            metric: 0, mtu: None, flags: 0, weight: 1, nh_flags: 0,
        });
        assert_eq!(route_snapshot_ns(0).len(), before + 1);
        let n = route_remove(0, RT_TABLE_MAIN as u32, Some(([192, 168, 99, 0], 24)), 7777, None);
        assert_eq!(n, 1);
        assert_eq!(route_snapshot_ns(0).len(), before);
    }

    #[test]
    fn routes_isolated_per_net_ns() {
        let row = |ns| RouteRow {
            ns, table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC,
            scope: RT_SCOPE_LINK, kind: RTN_UNICAST,
            dst: Some(([10, 9, 8, 0], 24)), gateway: None,
            oif_ifindex: 6543, prefsrc: None, metric: 0, mtu: None, flags: 0,
            weight: 1, nh_flags: 0,
        };
        let n0 = route_snapshot_ns(770).len();
        let n1 = route_snapshot_ns(771).len();
        route_insert(row(770));
        // The route is visible in ns 770 only; ns 771's view is unchanged.
        assert_eq!(route_snapshot_ns(770).len(), n0 + 1);
        assert_eq!(route_snapshot_ns(771).len(), n1, "other netns unaffected");
        // Removing under the wrong ns is a no-op; under the right ns it works.
        assert_eq!(route_remove(771, RT_TABLE_MAIN as u32, Some(([10, 9, 8, 0], 24)), 6543, None), 0);
        assert_eq!(route_remove(770, RT_TABLE_MAIN as u32, Some(([10, 9, 8, 0], 24)), 6543, None), 1);
    }

    #[test]
    fn newroute_multipath_inserts_each_nexthop() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        fn push_rtnh(out: &mut Vec<u8>, oif: u32, gw: [u8; 4]) {
            let start = out.len();
            out.extend_from_slice(&0u16.to_ne_bytes());
            out.push(0);
            out.push(0);
            out.extend_from_slice(&oif.to_ne_bytes());
            put_nlattr(out, rta::RTA_GATEWAY, &gw);
            let len = out.len() - start;
            out[start..start + 2].copy_from_slice(&(len as u16).to_ne_bytes());
            let pad = nlmsg_align(len) - len;
            for _ in 0..pad { out.push(0); }
        }

        let stack = net::global_stack();
        let iface1_id = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), 0);
        let iface2_id = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), 0);
        let iface1 = stack.ifaces.ifindex_in_ns(iface1_id, 0).unwrap();
        let iface2 = stack.ifaces.ifindex_in_ns(iface2_id, 0).unwrap();
        let dst = Some(([198, 51, 77, 0], 24));
        let mut body = alloc::vec![0u8; Rtmsg::SIZE];
        Rtmsg {
            rtm_family: AF_INET, rtm_dst_len: 24, rtm_table: RT_TABLE_MAIN,
            rtm_protocol: RTPROT_STATIC, rtm_scope: RT_SCOPE_UNIVERSE,
            rtm_type: RTN_UNICAST, ..Rtmsg::default()
        }.write_to(&mut body[..Rtmsg::SIZE]);
        put_nlattr(&mut body, rta::RTA_DST, &[198, 51, 77, 0]);
        let mut mp = Vec::new();
        push_rtnh(&mut mp, iface1, [192, 0, 2, 1]);
        push_rtnh(&mut mp, iface2, [192, 0, 2, 2]);
        put_nlattr(&mut body, rta::RTA_MULTIPATH, &mp);
        let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
        msg.extend_from_slice(&body);
        let req = Nlmsghdr {
            nlmsg_len: msg.len() as u32, nlmsg_type: RTM_NEWROUTE,
            nlmsg_flags: crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE
                | crate::flags::NLM_F_EXCL,
            nlmsg_seq: 44, nlmsg_pid: 9,
        };
        req.write_to(&mut msg[..Nlmsghdr::SIZE]);

        let _ack = handle_newroute(&req, &msg);
        let rows = route_snapshot_ns(0);
        assert!(rows.iter().any(|r| r.dst == dst && r.oif_ifindex == iface1_id.raw() && r.gateway == Some([192, 0, 2, 1])));
        assert!(rows.iter().any(|r| r.dst == dst && r.oif_ifindex == iface2_id.raw() && r.gateway == Some([192, 0, 2, 2])));
        assert_eq!(route_remove(0, RT_TABLE_MAIN as u32, dst, iface1_id.raw(), Some([192, 0, 2, 1])), 1);
        assert_eq!(route_remove(0, RT_TABLE_MAIN as u32, dst, iface2_id.raw(), Some([192, 0, 2, 2])), 1);
        assert!(stack.unregister_iface(iface1_id));
        assert!(stack.unregister_iface(iface2_id));
    }

    #[test]
    fn canonical_routes_and_netlink_rows_are_one_state() {
        const NS: u64 = 9071;
        let row = RouteRow {
            ns: NS, table: 1001, protocol: RTPROT_STATIC, scope: RT_SCOPE_LINK,
            kind: RTN_UNICAST, dst: Some(([172, 20, 0, 0], 16)),
            gateway: Some([192, 0, 2, 9]), oif_ifindex: 4401,
            prefsrc: Some([172, 20, 0, 1]), metric: 77, mtu: Some(1400), flags: 0x20,
            weight: 1, nh_flags: 0,
        };
        route_insert(row);
        let live = net::global_stack().routes
            .lookup_in_table_in(NS, 1001, net::Ipv4Addr::new(172, 20, 4, 5)).unwrap();
        assert_eq!(live.iface.raw(), 4401);
        assert_eq!(route_snapshot_ns(NS), alloc::vec![row]);
        assert_eq!(route_remove(NS, 1001, row.dst, 4401, row.gateway), 1);
    }

    #[test]
    fn exact_remove_preserves_same_iface_ecmp_peer() {
        const NS: u64 = 9072;
        let make = |gateway| RouteRow {
            ns: NS, table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC,
            scope: RT_SCOPE_LINK, kind: RTN_UNICAST, dst: Some(([203, 0, 113, 0], 24)),
            gateway: Some(gateway), oif_ifindex: 4402, prefsrc: None,
            metric: 0, mtu: None, flags: 0, weight: 1, nh_flags: 0,
        };
        route_insert(make([192, 0, 2, 1]));
        route_insert(make([192, 0, 2, 2]));
        assert_eq!(route_remove(NS, RT_TABLE_MAIN as u32, Some(([203, 0, 113, 0], 24)), 4402, Some([192, 0, 2, 1])), 1);
        let rows = route_snapshot_ns(NS);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].gateway, Some([192, 0, 2, 2]));
        assert_eq!(route_remove(NS, RT_TABLE_MAIN as u32, rows[0].dst, 4402, rows[0].gateway), 1);
    }

    #[test]
    fn policy_lookup_uses_requested_namespace() {
        const NS: u64 = 9073;
        let row = |table, iface| RouteRow {
            ns: NS, table, protocol: RTPROT_STATIC, scope: RT_SCOPE_LINK,
            kind: RTN_UNICAST, dst: None, gateway: None, oif_ifindex: iface,
            prefsrc: None, metric: 0, mtu: None, flags: 0, weight: 1, nh_flags: 0,
        };
        route_insert(row(RT_TABLE_MAIN as u32, 4403));
        route_insert(row(1002, 4404));
        net::policy_rule::insert(net::policy_rule::PolicyRule {
            ns: NS, family: net::policy_rule::AF_INET, priority: 1000, table: 1002,
            action: net::policy_rule::FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0,
        });
        assert_eq!(route_lookup_ns(NS, [8, 8, 8, 8]).unwrap().oif_ifindex, 4404);
        assert_eq!(net::policy_rule::remove(NS, net::policy_rule::AF_INET, Some(1000), Some(1002)), 1);
        assert_eq!(route_remove(NS, RT_TABLE_MAIN as u32, None, 4403, None), 1);
        assert_eq!(route_remove(NS, 1002, None, 4404, None), 1);
    }

    #[test]
    fn addr_table_insert_remove_snapshot() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let before = addr_snapshot_ns(0).len();
        addr_insert(IfaceAddr {
            ns: 0, ifindex: 9999, family: AF_INET,
            addr: [10, 9, 9, 9], peer: None, prefixlen: 32, scope: RT_SCOPE_UNIVERSE,
            flags: net::iface_addr::IFA_F_PERMANENT,
            cacheinfo: IfaCacheInfo::PERMANENT,
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
        let row = IfaceAddr {
            ns: 0, ifindex: 9998, family: AF_INET,
            addr: [10, 9, 9, 8], peer: None, prefixlen: 32, scope: RT_SCOPE_UNIVERSE,
            flags: net::iface_addr::IFA_F_PERMANENT,
            cacheinfo: IfaCacheInfo::PERMANENT,
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
        let row = |ns| IfaceAddr {
            ns, ifindex: 9997, family: AF_INET,
            addr: [10, 9, 9, 7], peer: None, prefixlen: 32, scope: RT_SCOPE_UNIVERSE,
            flags: net::iface_addr::IFA_F_PERMANENT,
            cacheinfo: IfaCacheInfo::PERMANENT,
        };
        let n0 = addr_snapshot_ns(880).len();
        let n1 = addr_snapshot_ns(881).len();
        addr_insert(row(880));
        assert_eq!(addr_snapshot_ns(880).len(), n0 + 1);
        assert_eq!(addr_snapshot_ns(881).len(), n1);
        assert_eq!(addr_remove(881, 9997, [10, 9, 9, 7], 32), 0);
        assert_eq!(addr_remove(880, 9997, [10, 9, 9, 7], 32), 1);
    }

    fn addr_req(ty: u16, ifindex: u32, prefixlen: u8, addr: [u8; 4]) -> (crate::Nlmsghdr, Vec<u8>) {
        let mut body = Vec::new();
        let ifa = Ifaddrmsg {
            ifa_family: AF_INET,
            ifa_prefixlen: prefixlen,
            ifa_flags: 0,
            ifa_scope: RT_SCOPE_UNIVERSE,
            ifa_index: ifindex,
        };
        let mut ifa_buf = [0u8; Ifaddrmsg::SIZE];
        ifa.write_to(&mut ifa_buf);
        body.extend_from_slice(&ifa_buf);
        put_nlattr(&mut body, ifa::IFA_LOCAL, &addr);
        let hdr = crate::Nlmsghdr {
            nlmsg_len: (crate::Nlmsghdr::SIZE + body.len()) as u32,
            nlmsg_type: ty,
            nlmsg_flags: crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_ACK,
            nlmsg_seq: 31,
            nlmsg_pid: 44,
        };
        let mut msg = Vec::new();
        let mut hdr_buf = [0u8; crate::Nlmsghdr::SIZE];
        hdr.write_to(&mut hdr_buf);
        msg.extend_from_slice(&hdr_buf);
        msg.extend_from_slice(&body);
        (hdr, msg)
    }

    fn ack_errno(reply: &[u8]) -> i32 {
        assert_eq!(u16::from_ne_bytes([reply[4], reply[5]]), crate::msg::NLMSG_ERROR);
        i32::from_ne_bytes(reply[crate::Nlmsghdr::SIZE..crate::Nlmsghdr::SIZE + 4].try_into().unwrap())
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
            r.ifindex == iface.raw() && r.addr == addr && r.prefixlen == 32));

        let (del_hdr, del_msg) = addr_req(RTM_DELADDR, ifindex, 32, addr);
        assert_eq!(ack_errno(&handle_deladdr(&del_hdr, &del_msg)), 0);
        assert!(!addr_snapshot_ns(0).iter().any(|r|
            r.ifindex == iface.raw() && r.addr == addr && r.prefixlen == 32));
        let _ = net::global_stack().ifaces.unregister(iface);
    }

    #[test]
    fn rtmsg_size_matches_linux() {
        assert_eq!(Rtmsg::SIZE, 12);
    }

    #[test]
    fn build_newroute_reply_well_formed() {
        let bytes = build_newroute_reply(
            1, 42,
            RT_TABLE_MAIN, RTPROT_KERNEL, RT_SCOPE_LINK, RTN_UNICAST,
            Some(([10, 0, 2, 0], 24)),
            None,
            2, Some([10, 0, 2, 15]),
            true,
        );
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
            1, 42, 2, "eth0", [10, 0, 2, 15], None, 24, RT_SCOPE_UNIVERSE,
            net::iface_addr::IFA_F_PERMANENT, IfaCacheInfo::PERMANENT, true,
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
            1, 42, 2, "ppp0", local, Some(peer), 32, RT_SCOPE_UNIVERSE,
            net::iface_addr::IFA_F_PERMANENT, IfaCacheInfo::PERMANENT, true,
        );
        let attrs = &bytes[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
        assert_eq!(find_attr(attrs, ifa::IFA_LOCAL).unwrap(), &local);
        assert_eq!(find_attr(attrs, ifa::IFA_ADDRESS).unwrap(), &peer);
        assert!(find_attr(attrs, ifa::IFA_BROADCAST).is_none());
    }

    #[test]
    fn build_newaddr6_reply_well_formed() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ci = IfaCacheInfo { preferred: 1800, valid: 3600, cstamp: 0, tstamp: 0 };
        let bytes = build_newaddr6_reply(1, 42, 2, "eth0", addr, 64, RT_SCOPE_UNIVERSE,
            net::iface_addr::IFA_F_PERMANENT, ci, true);
        assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]), RTM_NEWADDR);
        assert_eq!(bytes[Nlmsghdr::SIZE], AF_INET6);
        assert_eq!(bytes[Nlmsghdr::SIZE + 1], 64);
        assert_eq!(bytes[Nlmsghdr::SIZE + 2], net::iface_addr::IFA_F_PERMANENT as u8);
        let attrs = &bytes[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
        assert_eq!(find_attr(attrs, ifa::IFA_LOCAL).expect("IFA_LOCAL"), &addr);
        let got_ci = find_attr(attrs, ifa::IFA_CACHEINFO).expect("IFA_CACHEINFO");
        assert_eq!(u32::from_ne_bytes(got_ci[0..4].try_into().unwrap()), 1800);
        assert_eq!(u32::from_ne_bytes(got_ci[4..8].try_into().unwrap()), 3600);
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
            1500,
            false,
            iff::IFF_UP | iff::IFF_RUNNING,
            stats,
            true,
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
