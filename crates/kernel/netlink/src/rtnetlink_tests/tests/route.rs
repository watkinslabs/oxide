    use super::*;

    #[test]
    fn rtm_constants_match_linux() {
        let _domain = net::hosted_fixture::init_net_domain();
        assert_eq!(RTM_NEWLINK,  16);
        assert_eq!(RTM_GETLINK,  18);
        assert_eq!(RTM_NEWADDR,  20);
        assert_eq!(RTM_DELADDR,  21);
        assert_eq!(RTM_GETADDR,  22);
        assert_eq!(RTM_NEWROUTE, 24);
        assert_eq!(RTM_GETROUTE, 26);
        assert_eq!(RTM_NEWRULE,  32);
        assert_eq!(RTM_GETRULE,  34);
        assert_eq!(RTM_NEWMULTICAST, 56);
        assert_eq!(RTM_GETMULTICAST, 58);
        assert_eq!(RTM_NEWANYCAST, 60);
        assert_eq!(RTM_GETANYCAST, 62);
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

    // N22 exoneration: a non-`lo` ether device registered into the initial
    // net-ns (id 0) MUST appear in the RTM_GETLINK dump alongside `lo`, with a
    // well-formed Ifinfomsg (ARPHRD_ETHER) and IFLA_IFNAME. NetworkManager reads
    // this dump to discover interfaces; the source-only investigation proved the
    // ns keying + dump assembly are correct, so this locks that in and redirects
    // any "NM sees only lo" regression away from the kernel dump path.
    #[test]
    fn getlink_dump_includes_non_lo_ether_device_in_initial_ns() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let stack = net::global_stack();
        let lo = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), 0);
        let eth = stack.ifaces.register_in_ns(Arc::new(MovingDev), 0);
        let lo_idx = visible_ifindex(lo, 0);
        let eth_idx = visible_ifindex(eth, 0);

        let req = crate::Nlmsghdr { nlmsg_len: 32, nlmsg_type: RTM_GETLINK,
            nlmsg_flags: crate::flags::NLM_F_DUMP, nlmsg_seq: 9, nlmsg_pid: 11 };
        let mut dump_msg = [0u8; crate::Nlmsghdr::SIZE];
        req.write_to(&mut dump_msg);
        let reply = handle_getlink_in(0, &req, &dump_msg, false);

        // The SINGLE-device form must answer with the device that was named.
        // Answering it with a dump handed the caller the first entry in the
        // table, so `ip link show eth0` printed `lo` and every client that
        // queried a device by name read loopback's identity and flags.
        {
            let mut body = alloc::vec![0u8; 16];
            let name = b"eth-stable";
            body.extend_from_slice(&((4 + name.len() + 1) as u16).to_ne_bytes());
            body.extend_from_slice(&3u16.to_ne_bytes());   // IFLA_IFNAME
            body.extend_from_slice(name);
            body.push(0);
            while body.len() % 4 != 0 { body.push(0); }
            let one = crate::Nlmsghdr {
                nlmsg_len: (crate::Nlmsghdr::SIZE + body.len()) as u32,
                nlmsg_type: RTM_GETLINK, nlmsg_flags: crate::flags::NLM_F_REQUEST,
                nlmsg_seq: 12, nlmsg_pid: 11,
            };
            let mut msg = alloc::vec![0u8; crate::Nlmsghdr::SIZE];
            one.write_to(&mut msg[..]);
            msg.extend_from_slice(&body);
            let single = handle_getlink_in(0, &one, &msg, false);
            let hdr = crate::Nlmsghdr::parse(&single).expect("one reply");
            assert_eq!(hdr.nlmsg_type, RTM_NEWLINK, "a single RTM_NEWLINK, not an error");
            assert_eq!(hdr.nlmsg_flags & crate::flags::NLM_F_MULTI, 0,
                "not multipart: the caller asked for one device");
            assert_eq!(hdr.nlmsg_len as usize, single.len(), "exactly one message, no DONE");
            let off = crate::Nlmsghdr::SIZE;
            let got = i32::from_ne_bytes([single[off + 4], single[off + 5],
                                          single[off + 6], single[off + 7]]);
            assert_eq!(got, eth_idx as i32, "the named device comes back, not the first in the table");
            assert_ne!(got, lo_idx as i32, "not loopback");
        }

        // Walk the multipart dump; collect (ifindex, ifi_type, IFLA_IFNAME) for
        // each RTM_NEWLINK. Ifinfomsg: ifi_type @ off+2 (u16), ifi_index @ off+4
        // (i32); attrs follow at off + Ifinfomsg::SIZE.
        let mut eth_seen: Option<(u16, Vec<u8>)> = None;
        let mut lo_seen = false;
        let mut off = 0usize;
        while off + crate::Nlmsghdr::SIZE <= reply.len() {
            let hdr = crate::Nlmsghdr::parse(&reply[off..]).unwrap();
            let len = hdr.nlmsg_len as usize;
            if len < crate::Nlmsghdr::SIZE || off + len > reply.len() { break; }
            if hdr.nlmsg_type == RTM_NEWLINK {
                let b = off + crate::Nlmsghdr::SIZE;
                let ifi_type = u16::from_ne_bytes([reply[b + 2], reply[b + 3]]);
                let idx = i32::from_ne_bytes(reply[b + 4..b + 8].try_into().unwrap()) as u32;
                let attrs = &reply[b + Ifinfomsg::SIZE..off + len];
                let name = find_attr(attrs, ifla::IFLA_IFNAME).map(|s| s.to_vec());
                if idx == lo_idx { lo_seen = true; }
                if idx == eth_idx { eth_seen = Some((ifi_type, name.unwrap_or_default())); }
            }
            off += nlmsg_align(len);
        }
        assert!(lo_seen, "lo must appear in the dump");
        let (eth_type, eth_name) = eth_seen.expect("non-lo ether device must appear in the dump");
        assert_eq!(eth_type, net::uapi::ARPHRD_ETHER, "ether device reports ARPHRD_ETHER");
        assert_eq!(&eth_name[..eth_name.iter().position(|&c| c == 0).unwrap_or(eth_name.len())],
                   b"eth-stable", "IFLA_IFNAME present + correct");

        let _ = stack.ifaces.unregister(lo);
        let _ = stack.ifaces.unregister(eth);
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
            metric: 0, metrics: net::RouteMetrics::NONE, flags: 0, weight: 1, nh_flags: 0,
        });
        assert_eq!(route_snapshot_ns(0).len(), before + 1);
        let n = route_remove(0, RT_TABLE_MAIN as u32, Some(([192, 168, 99, 0], 24)), 7777, None);
        assert_eq!(n, 1);
        assert_eq!(route_snapshot_ns(0).len(), before);
    }

    #[test]
    fn routes_isolated_per_net_ns() {
        let _domain = net::hosted_fixture::init_net_domain();
        let row = |ns| RouteRow {
            ns, table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC,
            scope: RT_SCOPE_LINK, kind: RTN_UNICAST,
            dst: Some(([10, 9, 8, 0], 24)), gateway: None,
            oif_ifindex: 6543, prefsrc: None, metric: 0, metrics: net::RouteMetrics::NONE, flags: 0,
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
        let _domain = net::hosted_fixture::init_net_domain();
        const NS: u64 = 9071;
        let row = RouteRow {
            ns: NS, table: 1001, protocol: RTPROT_STATIC, scope: RT_SCOPE_LINK,
            kind: RTN_UNICAST, dst: Some(([172, 20, 0, 0], 16)),
            gateway: Some([192, 0, 2, 9]), oif_ifindex: 4401,
            prefsrc: Some([172, 20, 0, 1]), metric: 77, metrics: net::RouteMetrics { mtu: 1400, ..net::RouteMetrics::NONE }, flags: 0x20,
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
        let _domain = net::hosted_fixture::init_net_domain();
        const NS: u64 = 9072;
        let make = |gateway| RouteRow {
            ns: NS, table: RT_TABLE_MAIN as u32, protocol: RTPROT_STATIC,
            scope: RT_SCOPE_LINK, kind: RTN_UNICAST, dst: Some(([203, 0, 113, 0], 24)),
            gateway: Some(gateway), oif_ifindex: 4402, prefsrc: None,
            metric: 0, metrics: net::RouteMetrics::NONE, flags: 0, weight: 1, nh_flags: 0,
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
        let _domain = net::hosted_fixture::init_net_domain();
        const NS: u64 = 9073;
        let row = |table, iface| RouteRow {
            ns: NS, table, protocol: RTPROT_STATIC, scope: RT_SCOPE_LINK,
            kind: RTN_UNICAST, dst: None, gateway: None, oif_ifindex: iface,
            prefsrc: None, metric: 0, metrics: net::RouteMetrics::NONE, flags: 0, weight: 1, nh_flags: 0,
        };
        route_insert(row(RT_TABLE_MAIN as u32, 4403));
        route_insert(row(1002, 4404));
        net::policy_rule::insert(net::policy_rule::PolicyRule {
            ns: NS, family: net::policy_rule::AF_INET, priority: 1000, table: 1002,
            action: net::policy_rule::FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0, fwmark: 0, fwmask: 0,
        });
        assert_eq!(route_lookup_ns(NS, [8, 8, 8, 8]).unwrap().oif_ifindex, 4404);
        assert_eq!(net::policy_rule::remove(NS, net::policy_rule::AF_INET, Some(1000), Some(1002)), 1);
        assert_eq!(route_remove(NS, RT_TABLE_MAIN as u32, None, 4403, None), 1);
        assert_eq!(route_remove(NS, 1002, None, 4404, None), 1);
    }


