// Netlink/conntrack conformance tests kept outside the dispatcher module.
use alloc::{vec, vec::Vec};
    use alloc::sync::Arc;
    use crate::{subsys, Nfgenmsg};
    use super::{handle_one, parse_ct_tuple, parse_dump_filter, parse_helper_name, parse_labels,
                parse_nat_range, parse_seqadjs, parse_sctp_protoinfo, parse_synproxy,
                parse_tcp_protoinfo, reply_errno};
    use ::conntrack::{ProtoPart, Tuple, TupleEnd, InetAddr};
    use netlink::{flags, NetlinkSocket, Nlmsghdr, proto, register_netfilter_listener};

    #[test]
    fn ctnetlink_tuple_parser_preserves_family_ports_and_zone() {
        let expected = Tuple {
            src: TupleEnd { addr: InetAddr::v4([192, 0, 2, 1]), proto: ProtoPart::port(12345) },
            dst: TupleEnd { addr: InetAddr::v4([198, 51, 100, 2]), proto: ProtoPart::port(443) },
            l3num: ::conntrack::uapi::NFPROTO_IPV4,
            protonum: ::conntrack::uapi::IPPROTO_TCP,
            zone: 7,
        };
        let mut raw = Vec::new();
        ::conntrack::ctnetlink::put_tuple(
            &mut raw, ::conntrack::uapi::CTA_TUPLE_ORIG, &expected);
        assert_eq!(parse_ct_tuple(&raw[4..], expected.l3num, expected.zone), Some(expected));
    }

    #[test]
    fn osf_netlink_add_remove_uses_the_canonical_fingerprint_list() {
        let mut finger = vec![0u8; 592];
        finger[8] = 64;
        finger[10..12].copy_from_slice(&40u16.to_ne_bytes());
        finger[16..24].copy_from_slice(b"netlink\0");
        finger[48..53].copy_from_slice(b"test\0");
        finger[80..85].copy_from_slice(b"unit\0");
        let message = |cmd: u8, nl_flags: u16| {
            let mut body = Vec::new();
            let mut family = [0u8; Nfgenmsg::SIZE];
            Nfgenmsg { nfgen_family: ::conntrack::uapi::NFPROTO_IPV4,
                       version: 0, res_id: 0 }.write_to(&mut family);
            body.extend_from_slice(&family);
            super::put_nlattr(&mut body, crate::osf_attr::OSF_ATTR_FINGER, &finger);
            let hdr = Nlmsghdr {
                nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
                nlmsg_type: ((subsys::NFNL_SUBSYS_OSF as u16) << 8) | cmd as u16,
                nlmsg_flags: nl_flags, nlmsg_seq: 8, nlmsg_pid: 0,
            };
            let mut frame = Vec::new();
            let mut header = [0u8; Nlmsghdr::SIZE];
            hdr.write_to(&mut header);
            frame.extend_from_slice(&header);
            frame.extend_from_slice(&body);
            frame
        };
        assert_eq!(reply_errno(&handle_one(&message(crate::osf_msg::OSF_MSG_ADD,
            flags::NLM_F_REQUEST | flags::NLM_F_CREATE | flags::NLM_F_ACK), 0)), Some(0));
        assert_eq!(reply_errno(&handle_one(&message(crate::osf_msg::OSF_MSG_ADD,
            flags::NLM_F_REQUEST | flags::NLM_F_CREATE | flags::NLM_F_EXCL), 0)), Some(-17));
        assert_eq!(reply_errno(&handle_one(&message(crate::osf_msg::OSF_MSG_REMOVE,
            flags::NLM_F_REQUEST | flags::NLM_F_ACK), 0)), Some(0));
        assert_eq!(reply_errno(&handle_one(&message(crate::osf_msg::OSF_MSG_REMOVE,
            flags::NLM_F_REQUEST | flags::NLM_F_ACK), 0)), Some(-2));
    }

    #[test]
    fn ctnetlink_seqadj_parser_requires_the_linux_nested_fields() {
        let mut raw = Vec::new();
        let n = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_SEQ_ADJ_ORIG);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_SEQADJ_CORRECTION_POS, 100);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_SEQADJ_OFFSET_BEFORE, (-4i32) as u32);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_SEQADJ_OFFSET_AFTER, 8);
        ::conntrack::ctnetlink::nest_end(&mut raw, n);
        let parsed = parse_seqadjs(&raw).unwrap();
        assert_eq!(parsed[0].unwrap().offset_before, -4);
        assert_eq!(parsed[0].unwrap().offset_after, 8);
        let mut incomplete = Vec::new();
        let n = ::conntrack::ctnetlink::nest_start(
            &mut incomplete, ::conntrack::uapi::CTA_SEQ_ADJ_REPLY);
        ::conntrack::ctnetlink::put_be32(
            &mut incomplete, ::conntrack::uapi::CTA_SEQADJ_CORRECTION_POS, 1);
        ::conntrack::ctnetlink::nest_end(&mut incomplete, n);
        assert!(parse_seqadjs(&incomplete).is_err());
    }

    #[test]
    fn ctnetlink_tcp_protoinfo_applies_linux_state_and_masked_flags_shape() {
        let mut raw = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO);
        let tcp = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO_TCP);
        ::conntrack::ctnetlink::put_u8(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO_TCP_STATE, 4);
        ::conntrack::ctnetlink::put_attr(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO_TCP_FLAGS_ORIGINAL, &[0x80, 0xff]);
        ::conntrack::ctnetlink::nest_end(&mut raw, tcp);
        ::conntrack::ctnetlink::nest_end(&mut raw, outer);
        let parsed = parse_tcp_protoinfo(&raw).unwrap().unwrap();
        assert_eq!(parsed.state, Some(4));
        assert_eq!(parsed.flags[0], Some((0x80, 0xff)));
        assert_eq!(parsed.flags[1], None);

        let mut bad = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut bad, ::conntrack::uapi::CTA_PROTOINFO);
        let tcp = ::conntrack::ctnetlink::nest_start(
            &mut bad, ::conntrack::uapi::CTA_PROTOINFO_TCP);
        ::conntrack::ctnetlink::put_u8(
            &mut bad, ::conntrack::uapi::CTA_PROTOINFO_TCP_STATE, 10);
        ::conntrack::ctnetlink::nest_end(&mut bad, tcp);
        ::conntrack::ctnetlink::nest_end(&mut bad, outer);
        assert!(parse_tcp_protoinfo(&bad).is_err());
    }

    #[test]
    fn ctnetlink_sctp_protoinfo_requires_state_and_both_vtags() {
        let mut raw = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO);
        let sctp = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO_SCTP);
        ::conntrack::ctnetlink::put_u8(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO_SCTP_STATE, 4);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO_SCTP_VTAG_ORIGINAL, 0x1122_3344);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO_SCTP_VTAG_REPLY, 0x5566_7788);
        ::conntrack::ctnetlink::nest_end(&mut raw, sctp);
        ::conntrack::ctnetlink::nest_end(&mut raw, outer);
        let parsed = parse_sctp_protoinfo(&raw).unwrap().unwrap();
        assert_eq!(parsed.state, 4);
        assert_eq!(parsed.vtag, [0x1122_3344, 0x5566_7788]);

        let mut incomplete = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut incomplete, ::conntrack::uapi::CTA_PROTOINFO);
        let sctp = ::conntrack::ctnetlink::nest_start(
            &mut incomplete, ::conntrack::uapi::CTA_PROTOINFO_SCTP);
        ::conntrack::ctnetlink::put_u8(
            &mut incomplete, ::conntrack::uapi::CTA_PROTOINFO_SCTP_STATE, 4);
        ::conntrack::ctnetlink::put_be32(
            &mut incomplete, ::conntrack::uapi::CTA_PROTOINFO_SCTP_VTAG_ORIGINAL, 1);
        ::conntrack::ctnetlink::nest_end(&mut incomplete, sctp);
        ::conntrack::ctnetlink::nest_end(&mut incomplete, outer);
        assert!(parse_sctp_protoinfo(&incomplete).is_err());
    }

    #[test]
    fn ctnetlink_dump_filters_use_linux_masks_and_parse_partial_tuples() {
        let mut raw = Vec::new();
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_MARK, 0x55);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_MARK_MASK, 0xf0);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_STATUS, 0x10);
        let (_, filter) = parse_dump_filter(
            &raw, ::conntrack::uapi::NFPROTO_IPV4).unwrap();
        assert_eq!(filter.mark, Some((0x55, 0xf0)));
        assert_eq!(filter.status, Some((0x10, 0x10)));
        assert_eq!(filter.family, Some(::conntrack::uapi::NFPROTO_IPV4));

        let mut mask_only = Vec::new();
        ::conntrack::ctnetlink::put_be32(
            &mut mask_only, ::conntrack::uapi::CTA_STATUS_MASK, 1);
        assert_eq!(parse_dump_filter(&mask_only, 0), Err(-22));

        let mut nested = Vec::new();
        let n = ::conntrack::ctnetlink::nest_start(
            &mut nested, ::conntrack::uapi::CTA_FILTER);
        ::conntrack::ctnetlink::nest_end(&mut nested, n);
        let (selected, empty) = parse_dump_filter(&nested, 0).unwrap();
        assert!(selected);
        assert_eq!(empty.orig, None);

        let tuple = Tuple {
            src: ::conntrack::TupleEnd {
                addr: InetAddr::v4([192, 0, 2, 1]), proto: ProtoPart::port(40000),
            },
            dst: ::conntrack::TupleEnd {
                addr: InetAddr::v4([198, 51, 100, 2]), proto: ProtoPart::port(53),
            },
            l3num: ::conntrack::uapi::NFPROTO_IPV4,
            protonum: ::conntrack::uapi::IPPROTO_UDP,
            zone: 0,
        };
        let mut partial = Vec::new();
        ::conntrack::ctnetlink::put_tuple(
            &mut partial, ::conntrack::uapi::CTA_TUPLE_ORIG, &tuple);
        let n = ::conntrack::ctnetlink::nest_start(
            &mut partial, ::conntrack::uapi::CTA_FILTER);
        ::conntrack::ctnetlink::put_be32(
            &mut partial, ::conntrack::uapi::CTA_FILTER_ORIG_FLAGS,
            ::conntrack::ctnetlink::FILTER_IP_SRC
                | ::conntrack::ctnetlink::FILTER_PROTO_NUM);
        ::conntrack::ctnetlink::nest_end(&mut partial, n);
        let (_, parsed) = parse_dump_filter(
            &partial, ::conntrack::uapi::NFPROTO_IPV4).unwrap();
        let orig = parsed.orig.unwrap();
        assert_eq!(orig.flags, ::conntrack::ctnetlink::FILTER_IP_SRC
            | ::conntrack::ctnetlink::FILTER_PROTO_NUM);
        assert_eq!(orig.tuple.src.addr, tuple.src.addr);
        assert_eq!(orig.tuple.protonum, tuple.protonum);

        let mut incomplete = Vec::new();
        let n = ::conntrack::ctnetlink::nest_start(
            &mut incomplete, ::conntrack::uapi::CTA_FILTER);
        ::conntrack::ctnetlink::put_be32(
            &mut incomplete, ::conntrack::uapi::CTA_FILTER_ORIG_FLAGS,
            ::conntrack::ctnetlink::FILTER_PROTO_SRC_PORT);
        ::conntrack::ctnetlink::nest_end(&mut incomplete, n);
        assert_eq!(parse_dump_filter(&incomplete,
            ::conntrack::uapi::NFPROTO_IPV4), Err(-22));
    }

    #[test]
    fn ctnetlink_helper_parser_requires_a_nul_terminated_name() {
        let mut raw = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_HELP);
        ::conntrack::ctnetlink::put_attr(
            &mut raw, ::conntrack::uapi::CTA_HELP_NAME, b"dns\0");
        ::conntrack::ctnetlink::nest_end(&mut raw, outer);
        assert_eq!(parse_helper_name(&raw).unwrap().as_deref(), Some("dns"));

        let mut bad = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut bad, ::conntrack::uapi::CTA_HELP);
        ::conntrack::ctnetlink::put_attr(
            &mut bad, ::conntrack::uapi::CTA_HELP_NAME, b"dns");
        ::conntrack::ctnetlink::nest_end(&mut bad, outer);
        assert!(parse_helper_name(&bad).is_err());
    }

    #[test]
    fn ctnetlink_nat_parser_matches_linux_range_defaults() {
        let mut raw = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_NAT_SRC);
        ::conntrack::ctnetlink::put_attr(
            &mut raw, ::conntrack::uapi::CTA_NAT_V4_MINIP, &[203, 0, 113, 9]);
        let proto = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_NAT_PROTO);
        ::conntrack::ctnetlink::put_be16(
            &mut raw, ::conntrack::uapi::CTA_PROTONAT_PORT_MIN, 40000);
        ::conntrack::ctnetlink::put_be16(
            &mut raw, ::conntrack::uapi::CTA_PROTONAT_PORT_MAX, 40010);
        ::conntrack::ctnetlink::nest_end(&mut raw, proto);
        ::conntrack::ctnetlink::nest_end(&mut raw, outer);
        let parsed = parse_nat_range(&raw, ::conntrack::uapi::NFPROTO_IPV4,
            ::conntrack::uapi::CTA_NAT_SRC).unwrap().unwrap();
        assert_eq!(parsed.min_addr, ::conntrack::InetAddr::v4([203, 0, 113, 9]));
        assert_eq!(parsed.max_addr, parsed.min_addr);
        assert_eq!(parsed.ordered_ports(), (40000, 40010));
        assert!(parsed.maps_addr() && parsed.proto_specified());

        let mut max_only = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut max_only, ::conntrack::uapi::CTA_NAT_SRC);
        let proto = ::conntrack::ctnetlink::nest_start(
            &mut max_only, ::conntrack::uapi::CTA_NAT_PROTO);
        ::conntrack::ctnetlink::put_be16(
            &mut max_only, ::conntrack::uapi::CTA_PROTONAT_PORT_MAX, 99);
        ::conntrack::ctnetlink::nest_end(&mut max_only, proto);
        ::conntrack::ctnetlink::nest_end(&mut max_only, outer);
        let parsed = parse_nat_range(&max_only, ::conntrack::uapi::NFPROTO_IPV4,
            ::conntrack::uapi::CTA_NAT_SRC).unwrap().unwrap();
        assert_eq!(parsed.ordered_ports(), (0, 99));
    }

    #[test]
    fn ctnetlink_labels_parser_requires_aligned_matching_mask() {
        let mut raw = Vec::new();
        ::conntrack::ctnetlink::put_attr(
            &mut raw, ::conntrack::uapi::CTA_LABELS, &[0x05, 0, 0, 0]);
        ::conntrack::ctnetlink::put_attr(
            &mut raw, ::conntrack::uapi::CTA_LABELS_MASK, &[0x0f, 0, 0, 0]);
        let parsed = parse_labels(&raw).unwrap().unwrap();
        assert_eq!(parsed.data[0], 0x05);
        assert_eq!(parsed.mask.unwrap()[0], 0x0f);
        assert_eq!(parsed.len, 4);

        let mut bad = Vec::new();
        ::conntrack::ctnetlink::put_attr(
            &mut bad, ::conntrack::uapi::CTA_LABELS, &[1, 2, 3]);
        assert!(parse_labels(&bad).is_err());
        let mut bad_mask = Vec::new();
        ::conntrack::ctnetlink::put_attr(
            &mut bad_mask, ::conntrack::uapi::CTA_LABELS, &[0, 0, 0, 0]);
        ::conntrack::ctnetlink::put_attr(
            &mut bad_mask, ::conntrack::uapi::CTA_LABELS_MASK, &[0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(parse_labels(&bad_mask).is_err());
    }

    #[test]
    fn ctnetlink_create_requires_both_matching_direction_tuples() {
        let orig = Tuple {
            src: TupleEnd { addr: InetAddr::v4([192, 0, 2, 1]), proto: ProtoPart::port(40000) },
            dst: TupleEnd { addr: InetAddr::v4([198, 51, 100, 2]), proto: ProtoPart::port(53) },
            l3num: ::conntrack::uapi::NFPROTO_IPV4,
            protonum: ::conntrack::uapi::IPPROTO_UDP,
            zone: 0,
        };
        let make_request = |reply: Option<&Tuple>| {
            let mut body = Vec::new();
            let mut family = [0u8; Nfgenmsg::SIZE];
            Nfgenmsg { nfgen_family: ::conntrack::uapi::NFPROTO_IPV4,
                       version: 0, res_id: 0 }.write_to(&mut family);
            body.extend_from_slice(&family);
            ::conntrack::ctnetlink::put_tuple(
                &mut body, ::conntrack::uapi::CTA_TUPLE_ORIG, &orig);
            if let Some(reply) = reply {
                ::conntrack::ctnetlink::put_tuple(
                    &mut body, ::conntrack::uapi::CTA_TUPLE_REPLY, reply);
            }
            ::conntrack::ctnetlink::put_be32(
                &mut body, ::conntrack::uapi::CTA_TIMEOUT, 30);
            let hdr = Nlmsghdr {
                nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
                nlmsg_type: ((subsys::NFNL_SUBSYS_CTNETLINK as u16) << 8)
                    | ::conntrack::uapi::IPCTNL_MSG_CT_NEW as u16,
                nlmsg_flags: flags::NLM_F_REQUEST | flags::NLM_F_CREATE | flags::NLM_F_ACK,
                nlmsg_seq: 1, nlmsg_pid: 0,
            };
            let mut frame = Vec::new();
            let mut header = [0u8; Nlmsghdr::SIZE];
            hdr.write_to(&mut header);
            frame.extend_from_slice(&header);
            frame.extend_from_slice(&body);
            frame
        };
        assert_eq!(reply_errno(&handle_one(&make_request(None), 0)), Some(-22));

        let reply = Tuple { protonum: ::conntrack::uapi::IPPROTO_TCP,
                            ..orig };
        assert_eq!(reply_errno(&handle_one(&make_request(Some(&reply)), 0)), Some(-22));
    }

    #[test]
    fn ctnetlink_get_without_dump_requires_a_directional_tuple() {
        let make_request = |attrs: &[u8]| {
            let mut body = Vec::new();
            let mut family = [0u8; Nfgenmsg::SIZE];
            Nfgenmsg { nfgen_family: ::conntrack::uapi::NFPROTO_IPV4,
                       version: 0, res_id: 0 }.write_to(&mut family);
            body.extend_from_slice(&family);
            body.extend_from_slice(attrs);
            let hdr = Nlmsghdr {
                nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
                nlmsg_type: ((subsys::NFNL_SUBSYS_CTNETLINK as u16) << 8)
                    | ::conntrack::uapi::IPCTNL_MSG_CT_GET as u16,
                nlmsg_flags: flags::NLM_F_REQUEST | flags::NLM_F_ACK,
                nlmsg_seq: 1, nlmsg_pid: 0,
            };
            let mut frame = Vec::new();
            let mut header = [0u8; Nlmsghdr::SIZE];
            hdr.write_to(&mut header);
            frame.extend_from_slice(&header);
            frame.extend_from_slice(&body);
            frame
        };
        assert_eq!(reply_errno(&handle_one(&make_request(&[]), 0)), Some(-22));
        let mut selector = Vec::new();
        ::conntrack::ctnetlink::put_be32(
            &mut selector, ::conntrack::uapi::CTA_MARK, 0x55);
        assert_eq!(reply_errno(&handle_one(&make_request(&selector), 0)), Some(-22));
    }

    #[test]
    fn ctnetlink_synproxy_parser_requires_all_nested_words() {
        let mut raw = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_SYNPROXY);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_SYNPROXY_ISN, 0x1122_3344);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_SYNPROXY_ITS, 0x5566_7788);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_SYNPROXY_TSOFF, (-12i32) as u32);
        ::conntrack::ctnetlink::nest_end(&mut raw, outer);
        let state = parse_synproxy(&raw).unwrap().unwrap();
        assert_eq!(state.isn, 0x1122_3344);
        assert_eq!(state.its, 0x5566_7788);
        assert_eq!(state.tsoff, -12);

        let mut incomplete = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut incomplete, ::conntrack::uapi::CTA_SYNPROXY);
        ::conntrack::ctnetlink::put_be32(
            &mut incomplete, ::conntrack::uapi::CTA_SYNPROXY_ISN, 1);
        ::conntrack::ctnetlink::nest_end(&mut incomplete, outer);
        assert!(parse_synproxy(&incomplete).is_err());
    }

    #[test]
    fn ctnetlink_event_flush_multicasts_the_canonical_new_message() {
        let ns = net::net_ns::initial_namespace();
        let socket = Arc::new(NetlinkSocket::new(proto::NETLINK_NETFILTER, &ns));
        register_netfilter_listener(&socket);
        socket.add_membership(1).unwrap();
        let stack = net::global_stack();
        let tuple = Tuple {
            src: TupleEnd { addr: InetAddr::v4([192, 0, 2, 9]), proto: ProtoPart::port(49123) },
            dst: TupleEnd { addr: InetAddr::v4([198, 51, 100, 9]), proto: ProtoPart::port(53) },
            l3num: ::conntrack::uapi::NFPROTO_IPV4,
            protonum: ::conntrack::uapi::IPPROTO_UDP,
            zone: 0,
        };
        let ct = stack.conntrack_in(0);
        let id = ct.create_tuple(tuple, None, 0, 30, 0, None, None, None).expect("create event");
        super::flush_conntrack_events(0);
        let mut bytes = [0u8; 512];
        let n = socket.read(&mut bytes).expect("conntrack event datagram");
        assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]),
            ((crate::subsys::NFNL_SUBSYS_CTNETLINK as u16) << 8)
                | ::conntrack::uapi::IPCTNL_MSG_CT_NEW as u16);
        assert_eq!(bytes[16], ::conntrack::uapi::NFPROTO_IPV4);
        assert!(bytes[..n].windows(4).any(|w| w == (id as u32).to_be_bytes().as_slice()));
        let _ = ct.delete_id(id, 0);
        stack.conntrack_set_groups_in(0, 0);
    }

