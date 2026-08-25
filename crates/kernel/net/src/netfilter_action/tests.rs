use alloc::{string::String, sync::Arc, vec};
    use conntrack::entry::Conn;
    use conntrack::tuple::{InetAddr, ProtoPart, Tuple, TupleEnd};
    use conntrack::uapi::{IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY, IP_CT_NEW, IPPROTO_TCP,
                          NFPROTO_IPV4};
    use super::{apply_conntrack_packet, Action, ApplyError, PAYLOAD_NETWORK_HEADER,
                PAYLOAD_TRANSPORT_HEADER};
    use crate::pkt::Pkt;

    #[test]
    fn payload_set_repairs_ipv4_header_checksum() {
        let src = crate::Ipv4Addr::new(10, 0, 0, 1);
        let dst = crate::Ipv4Addr::new(10, 0, 0, 2);
        let mut bytes = vec![0u8; 20];
        crate::ipv4::Ipv4Hdr::build(src, dst, crate::IpProto::Udp, 0, 1).write_to(&mut bytes);
        let action = Action::PayloadSet { base: PAYLOAD_NETWORK_HEADER, offset: 1,
            data: vec![0x2e], csum_type: super::PAYLOAD_CSUM_INET, csum_offset: 10,
            csum_flags: 0 };
        let mut pkt = Pkt::from_owned(bytes);
        action.apply(&mut pkt, NFPROTO_IPV4).unwrap();
        assert_eq!(crate::ipv4::ip_checksum(pkt.data()), 0);
    }

    #[test]
    fn conntrack_sequence_adjust_rewrites_tcp_numbers_and_checksum() {
        let src = crate::Ipv4Addr::new(10, 0, 0, 2);
        let dst = crate::Ipv4Addr::new(10, 0, 0, 1);
        let mut bytes = vec![0u8; 40];
        crate::ipv4::Ipv4Hdr::build(src, dst, crate::IpProto::Tcp, 20, 1).write_to(&mut bytes);
        let mut tcp = crate::tcp_hdr::TcpHdr {
            src_port: 80, dst_port: 4000, seq: 1000, ack: 2000, data_offset: 5,
            flags: crate::tcp_hdr::flags::ACK, window: 4096, checksum: 0, urg_ptr: 0,
        };
        tcp.build_into(src, dst, &mut bytes[20..]);
        let orig = Tuple {
            l3num: NFPROTO_IPV4, protonum: IPPROTO_TCP,
            src: TupleEnd { addr: InetAddr::v4([10, 0, 0, 1]), proto: ProtoPart::port(4000) },
            dst: TupleEnd { addr: InetAddr::v4([10, 0, 0, 2]), proto: ProtoPart::port(80) },
            zone: 0,
        };
        let conn = Arc::new(Conn::new(1, orig, orig.invert().unwrap(), 0));
        conn.seqadj_init(IP_CT_DIR_REPLY, 100);
        conn.seqadj_init(IP_CT_DIR_ORIGINAL, 50);
        let mut pkt = Pkt::from_owned(bytes);
        apply_conntrack_packet(&mut pkt, conn, IP_CT_DIR_REPLY, NFPROTO_IPV4, 0).unwrap();
        let parsed = crate::tcp_hdr::TcpHdr::parse(&pkt.data()[20..], src, dst).unwrap();
        assert_eq!((parsed.seq, parsed.ack), (1100, 1950));
        assert!(crate::tcp_hdr::tcp_checksum_ok(&pkt.data()[20..], src, dst));
    }

    #[test]
    fn payload_set_repairs_ipv4_udp_checksum() {
        let src = crate::Ipv4Addr::new(10, 0, 0, 1);
        let dst = crate::Ipv4Addr::new(10, 0, 0, 2);
        let mut bytes = vec![0u8; 32];
        crate::ipv4::Ipv4Hdr::build(src, dst, crate::IpProto::Udp, 12, 1).write_to(&mut bytes);
        crate::udp::UdpHdr::build_into(1000, 2000, src, dst, &[1, 2, 3, 4], &mut bytes[20..]);
        let action = Action::PayloadSet { base: PAYLOAD_TRANSPORT_HEADER, offset: 8,
            data: vec![9], csum_type: super::PAYLOAD_CSUM_INET, csum_offset: 6,
            csum_flags: super::PAYLOAD_L4CSUM_PSEUDOHDR };
        let mut pkt = Pkt::from_owned(bytes);
        action.apply(&mut pkt, NFPROTO_IPV4).unwrap();
        assert!(crate::udp::udp_checksum_ok(&pkt.data()[20..], src, dst));
    }

    #[test]
    fn exthdr_set_updates_tcp_option_and_checksum() {
        let src = crate::Ipv4Addr::new(10, 0, 0, 1);
        let dst = crate::Ipv4Addr::new(10, 0, 0, 2);
        let mut bytes = vec![0u8; 44];
        crate::ipv4::Ipv4Hdr::build(src, dst, crate::IpProto::Tcp, 24, 1).write_to(&mut bytes);
        let mut tcp = crate::tcp_hdr::TcpHdr {
            src_port: 1000, dst_port: 2000, seq: 1, ack: 0, data_offset: 6,
            flags: crate::tcp_hdr::flags::SYN, window: 4096, checksum: 0, urg_ptr: 0,
        };
        tcp.build_into(src, dst, &mut bytes[20..]);
        bytes[40..44].copy_from_slice(&[2, 4, 0x05, 0xb4]);
        tcp.build_into(src, dst, &mut bytes[20..]);
        let action = Action::ExthdrSet { op: 1, htype: 2, offset: 2,
            data: vec![0x04, 0x00] };
        let mut pkt = Pkt::from_owned(bytes);
        action.apply(&mut pkt, NFPROTO_IPV4).unwrap();
        assert_eq!(&pkt.data()[42..44], &[0x04, 0x00]);
        assert!(crate::tcp_hdr::tcp_checksum_ok(&pkt.data()[20..], src, dst));
    }

    #[test]
    fn payload_set_mutates_packet_owner_buffer() {
        let mut pkt = Pkt::from_owned(vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17,
                                            0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
        let action = Action::PayloadSet { base: PAYLOAD_NETWORK_HEADER, offset: 1,
            data: vec![0x2e], csum_type: 0, csum_offset: 0, csum_flags: 0 };
        action.apply(&mut pkt, 2).unwrap();
        assert_eq!(pkt.data()[1], 0x2e);
    }

    #[test]
    fn ipv6_udp_tproxy_records_target() {
        let src = crate::Ipv6Addr([0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = crate::Ipv6Addr([0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut bytes = vec![0u8; 48];
        crate::ipv6::Ipv6Hdr::build(src, dst, crate::IpProto::Udp, 8)
            .write_to(&mut bytes);
        bytes[40..48].copy_from_slice(&[0x03, 0xe8, 0x07, 0xd0, 0, 8, 0, 0]);
        let target = InetAddr::v6([0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        let mut pkt = Pkt::from_owned(bytes);
        Action::TproxyAssign { addr: target, port: 5353 }
            .apply_at(&mut pkt, crate::netfilter_hook::NFPROTO_IPV6,
                crate::netfilter_hook::NF_INET_PRE_ROUTING).unwrap();
        assert_eq!(pkt.tproxy_target(), Some(crate::pkt::TproxyTarget { addr: target, port: 5353 }));
    }

    #[test]
    fn payload_set_resolves_transport_header_and_rejects_bounds() {
        let mut pkt = Pkt::from_owned(vec![0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17,
                                            0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
                                            0, 53, 0, 54]);
        let action = Action::PayloadSet { base: PAYLOAD_TRANSPORT_HEADER, offset: 1,
            data: vec![0xab], csum_type: 0, csum_offset: 0, csum_flags: 0 };
        action.apply(&mut pkt, 2).unwrap();
        assert_eq!(pkt.data()[21], 0xab);
        let invalid = Action::PayloadSet { base: PAYLOAD_NETWORK_HEADER, offset: 24,
            data: vec![1], csum_type: 0, csum_offset: 0, csum_flags: 0 };
        assert_eq!(invalid.apply(&mut pkt, 2), Err(ApplyError::Invalid));
    }

    #[test]
    fn stateful_actions_are_not_silently_discarded() {
        let mut pkt = Pkt::from_owned(vec![0; 20]);
        let action = Action::FlowOffload { table: String::new(), flowtable: String::new() };
        assert_eq!(action.apply(&mut pkt, 2), Err(ApplyError::Unsupported));
        let action = Action::FlowOffload { table: String::from("filter"), flowtable: String::from("ft") };
        assert_eq!(action.apply_at(&mut pkt, 2, crate::netfilter_hook::NF_INET_FORWARD),
            Err(ApplyError::Invalid));
    }

    #[test]
    fn syslog_log_is_consumed_without_changing_the_packet_verdict() {
        let mut pkt = Pkt::from_owned(vec![0u8; 20]);
        let action = Action::Log { group: None, level: 4, prefix: String::from("nft: "),
            snaplen: 32, qthreshold: 0, flags: 0 };
        assert_eq!(action.apply(&mut pkt, 2), Ok(()));
        let nflog = Action::Log { group: Some(7), level: 4, prefix: String::new(),
            snaplen: 0, qthreshold: 1, flags: 0 };
        assert_eq!(nflog.apply(&mut pkt, 2), Err(ApplyError::Unsupported));
    }

    #[test]
    fn nat_action_binds_the_pending_flow_and_rewrites_the_owner() {
        let orig = Tuple { src: TupleEnd { addr: InetAddr::v4([10, 0, 0, 1]),
                proto: ProtoPart::port(40000) },
            dst: TupleEnd { addr: InetAddr::v4([198, 51, 100, 2]),
                proto: ProtoPart::port(443) }, l3num: NFPROTO_IPV4, protonum: IPPROTO_TCP, zone: 0 };
        let conn = Arc::new(Conn::new(1, orig, orig.invert().unwrap(), 7));
        let table = Arc::new(conntrack::CtNet::new(7, 1));
        table.table.add_pending(conn.clone());
        let mut pkt = Pkt::from_owned(vec![
            0x45, 0, 0, 40, 0, 0, 0, 0, 64, IPPROTO_TCP, 0, 0,
            10, 0, 0, 1, 198, 51, 100, 2, 0x9c, 0x40, 1, 0xbb,
            0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0, 0, 0, 0, 0,
        ]);
        pkt.set_conntrack_state(table, Some(conn.clone()), IP_CT_NEW, 0);
        let action = Action::Nat { manip: nat::uapi::NF_NAT_MANIP_SRC,
            range: nat::NatRange::single_addr(InetAddr::v4([203, 0, 113, 9]), 0) };
        action.apply_at(&mut pkt, NFPROTO_IPV4, 4).unwrap();
        apply_conntrack_packet(&mut pkt, conn.clone(), 0, NFPROTO_IPV4, 4).unwrap();
        assert_eq!(&pkt.data()[12..16], &[203, 0, 113, 9]);
        assert_eq!(conn.reply_tuple().dst.addr, InetAddr::v4([203, 0, 113, 9]));
        assert!(action.apply_at(&mut pkt, NFPROTO_IPV4, 4).is_ok());
    }

    #[test]
    fn netdev_fwd_neighbour_form_decrements_ttl_and_uses_the_target_device() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = crate::global_stack();
        let (source, _) = stack.register_loopback();
        let (target, target_dev) = stack.register_loopback();
        let ifindex = stack.ifaces.ifindex_in_ns(target, 0).unwrap();
        let mut l3 = vec![0u8; 20];
        crate::ipv4::Ipv4Hdr::build(crate::Ipv4Addr::LOOPBACK, crate::Ipv4Addr::LOOPBACK,
            crate::IpProto::Udp, 0, 1).write_to(&mut l3);
        let mut frame = vec![0u8; crate::ethernet::ETH_HDR_LEN + l3.len()];
        crate::ethernet::EthHdr::write_to(crate::MacAddr::BROADCAST,
            crate::MacAddr([2, 0, 0, 0, 0, 1]), crate::eth_p::IPV4, &mut frame);
        frame[crate::ethernet::ETH_HDR_LEN..].copy_from_slice(&l3);
        let mut pkt = Pkt::from_owned(frame);
        pkt.proto = crate::eth_p::IPV4;
        pkt.iface = Some(source);
        let action = Action::Fwd { oif: ifindex,
            gateway: Some(InetAddr::v4([127, 0, 0, 1])), nfproto: Some(NFPROTO_IPV4) };
        assert_eq!(action.apply_at(&mut pkt, crate::netfilter_hook::NFPROTO_NETDEV, 0),
            Err(ApplyError::Stolen));
        assert_eq!(target_dev.rx_len(), 1);
        assert_eq!(target_dev.rx_pop().unwrap().data()[8], 63);
    }

    #[test]
    fn netdev_dup_mirrors_the_frame_and_keeps_the_original_owner() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = crate::global_stack();
        let (source, _) = stack.register_loopback();
        let (target, target_dev) = stack.register_loopback();
        let ifindex = stack.ifaces.ifindex_in_ns(target, 0).unwrap();
        let mut frame = vec![0u8; crate::ethernet::ETH_HDR_LEN + 20];
        crate::ethernet::EthHdr::write_to(crate::MacAddr::BROADCAST,
            crate::MacAddr([2, 0, 0, 0, 0, 1]), crate::eth_p::IPV4, &mut frame);
        frame[crate::ethernet::ETH_HDR_LEN] = 0x45;
        let original = frame.clone();
        let mut pkt = Pkt::from_owned(frame);
        pkt.proto = crate::eth_p::IPV4;
        pkt.iface = Some(source);
        let action = Action::Dup { gateway: None, oif: Some(ifindex) };
        action.apply_at(&mut pkt, crate::netfilter_hook::NFPROTO_NETDEV, 0).unwrap();
        assert_eq!(pkt.data(), original.as_slice());
        assert_eq!(target_dev.rx_len(), 1);
    }
