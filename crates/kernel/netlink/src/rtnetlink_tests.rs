    use alloc::{sync::Arc, vec::Vec};

    use crate::{nlmsg_align, Nlmsghdr};

    use super::*;
    use super::route_ops::{build_newroute_row_reply, route_key};
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
    #[path = "rtnetlink_tests/notification_races/mod.rs"]
    mod notification_races;
    #[path = "rtnetlink_tests/address_semantics.rs"]
    mod address_semantics;
    #[path = "rtnetlink_tests/address6_common.rs"]
    mod address6_common;
    #[path = "rtnetlink_tests/address6_semantics.rs"]
    mod address6_semantics;
    #[path = "rtnetlink_tests/address6_autojoin.rs"]
    mod address6_autojoin;
    #[path = "rtnetlink_tests/address6_ordering.rs"]
    mod address6_ordering;
    #[path = "rtnetlink_tests/strict_dumps.rs"]
    mod strict_dumps;
    #[path = "rtnetlink_tests/addr_fields.rs"]
    mod addr_fields;
    #[path = "rtnetlink_tests/link_operstate.rs"]
    mod link_operstate;
    #[path = "rtnetlink_tests/dump_only.rs"]
    mod dump_only;
    #[path = "rtnetlink_tests/link_kind_dispatch.rs"]
    mod link_kind_dispatch;

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

    #[path = "rtnetlink_tests/tests/route.rs"]
    mod route;
    #[path = "rtnetlink_tests/tests/address.rs"]
    mod address;
    #[path = "rtnetlink_tests/tests/wire.rs"]
    mod wire;
