    use super::*;

    #[test]
    fn rtm_constants_match_linux() {
        assert_eq!(RTM_NEWLINK,  16);
        assert_eq!(RTM_GETLINK,  18);
        assert_eq!(RTM_NEWADDR,  20);
        assert_eq!(RTM_GETADDR,  22);
        assert_eq!(RTM_NEWROUTE, 24);
        assert_eq!(RTM_GETROUTE, 26);
    }

    // K4: an RTM_GETLINK dump must end with a well-formed NLMSG_DONE
    // (len=16, type=3, NLM_F_MULTI, echoing seq/pid) — absent/malformed is
    // the "EOF on netlink" mode that breaks `ip link`. Host snapshot is
    // empty so the whole reply IS the terminator.
    #[test]
    fn getlink_dump_ends_with_nlmsg_done() {
        let req = crate::Nlmsghdr { nlmsg_len: 32, nlmsg_type: RTM_GETLINK,
            nlmsg_flags: crate::flags::NLM_F_DUMP, nlmsg_seq: 7, nlmsg_pid: 42 };
        let reply = handle_getlink(&req);
        let done = crate::Nlmsghdr::parse(&reply[reply.len() - crate::Nlmsghdr::SIZE..]).unwrap();
        assert_eq!(done.nlmsg_type, crate::msg::NLMSG_DONE);
        assert_eq!(done.nlmsg_len, crate::Nlmsghdr::SIZE as u32);
        assert!(done.nlmsg_flags & crate::flags::NLM_F_MULTI != 0);
        assert_eq!((done.nlmsg_seq, done.nlmsg_pid), (7, 42), "DONE echoes seq/pid");
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
        let before = route_snapshot().len();
        route_insert(RouteRow {
            table: RT_TABLE_MAIN, protocol: RTPROT_STATIC,
            scope: RT_SCOPE_LINK, kind: RTN_UNICAST,
            dst: Some(([192, 168, 99, 0], 24)),
            gateway: None, oif_ifindex: 7777, prefsrc: None,
        });
        assert_eq!(route_snapshot().len(), before + 1);
        let n = route_remove(RT_TABLE_MAIN, Some(([192, 168, 99, 0], 24)), 7777);
        assert_eq!(n, 1);
        assert_eq!(route_snapshot().len(), before);
    }

    #[test]
    fn addr_table_insert_remove_snapshot() {
        // Snapshot of total rows changes around our operations; we
        // capture before/after rather than asserting absolute counts
        // (other tests in the binary may have seeded rows).
        let before = addr_snapshot().len();
        addr_insert(IfaceAddr {
            ifindex: 9999, family: AF_INET,
            addr: [10, 9, 9, 9], prefixlen: 32, scope: RT_SCOPE_UNIVERSE,
        });
        let after_insert = addr_snapshot().len();
        assert_eq!(after_insert, before + 1);
        let n = addr_remove(9999, [10, 9, 9, 9], 32);
        assert_eq!(n, 1);
        assert_eq!(addr_snapshot().len(), before);
    }

    #[test]
    fn addr_insert_dedupes_same_key() {
        let row = IfaceAddr {
            ifindex: 9998, family: AF_INET,
            addr: [10, 9, 9, 8], prefixlen: 32, scope: RT_SCOPE_UNIVERSE,
        };
        let before = addr_snapshot().len();
        addr_insert(row);
        addr_insert(row); // second insert should replace, not duplicate
        let after = addr_snapshot().len();
        assert_eq!(after, before + 1);
        let _ = addr_remove(9998, [10, 9, 9, 8], 32);
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
    fn build_newaddr_reply_well_formed() {
        let bytes = build_newaddr_reply(
            1, 42, 2, "eth0", [10, 0, 2, 15], 24, RT_SCOPE_UNIVERSE, true,
        );
        // Header nlmsg_type == RTM_NEWADDR
        let ty = u16::from_ne_bytes([bytes[4], bytes[5]]);
        assert_eq!(ty, RTM_NEWADDR);
        // ifaddrmsg right after the 16-byte header
        assert_eq!(bytes[Nlmsghdr::SIZE], AF_INET);
        assert_eq!(bytes[Nlmsghdr::SIZE + 1], 24); // prefixlen
        assert_eq!(bytes[Nlmsghdr::SIZE + 3], RT_SCOPE_UNIVERSE);
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
