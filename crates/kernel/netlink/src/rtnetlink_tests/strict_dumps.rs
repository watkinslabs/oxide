// `NETLINK_GET_STRICT_CHK` on the RTM_GETADDR / RTM_GETLINK dump paths.

use super::*;

/// Every RTM_NEWADDR in a reply, as (ifindex, nlmsg_flags).
fn addr_rows(reply: &[u8]) -> alloc::vec::Vec<(u32, u16)> {
    let mut out = alloc::vec::Vec::new();
    let mut at = 0usize;
    while at + Nlmsghdr::SIZE <= reply.len() {
        let hdr = Nlmsghdr::parse(&reply[at..]).expect("a header");
        if hdr.nlmsg_type == RTM_NEWADDR {
            let b = at + Nlmsghdr::SIZE;
            out.push((u32::from_ne_bytes([reply[b + 4], reply[b + 5], reply[b + 6], reply[b + 7]]),
                      hdr.nlmsg_flags));
        }
        let len = nlmsg_align(hdr.nlmsg_len as usize);
        if len == 0 { break; }
        at += len;
    }
    out
}

fn getaddr_request(ifa_index: u32, prefixlen: u8) -> (Nlmsghdr, alloc::vec::Vec<u8>) {
    let mut body = alloc::vec![0u8; super::uapi::Ifaddrmsg::SIZE];
    body[0] = super::uapi::AF_INET;
    body[1] = prefixlen;
    body[4..8].copy_from_slice(&ifa_index.to_ne_bytes());
    let hdr = Nlmsghdr {
        nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
        nlmsg_type: RTM_GETADDR, nlmsg_flags: crate::flags::NLM_F_DUMP,
        nlmsg_seq: 5, nlmsg_pid: 7,
    };
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut msg[..]);
    msg.extend_from_slice(&body);
    (hdr, msg)
}

fn ack_errno(reply: &[u8]) -> i32 {
    assert_eq!(u16::from_ne_bytes([reply[4], reply[5]]), crate::msg::NLMSG_ERROR);
    i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]])
}

fn target_attr(msg: &mut alloc::vec::Vec<u8>, nsid: i32) {
    msg.extend_from_slice(&8u16.to_ne_bytes());
    msg.extend_from_slice(&ifa::IFA_TARGET_NETNSID.to_ne_bytes());
    msg.extend_from_slice(&nsid.to_ne_bytes());
    let mut hdr = Nlmsghdr::parse(msg).unwrap();
    hdr.nlmsg_len = msg.len() as u32;
    hdr.write_to(&mut msg[..Nlmsghdr::SIZE]);
}

fn link_target_attr(msg: &mut alloc::vec::Vec<u8>, nsid: i32) {
    msg.extend_from_slice(&8u16.to_ne_bytes());
    msg.extend_from_slice(&ifla::IFLA_TARGET_NETNSID.to_ne_bytes());
    msg.extend_from_slice(&nsid.to_ne_bytes());
    let mut hdr = Nlmsghdr::parse(msg).unwrap();
    hdr.nlmsg_len = msg.len() as u32;
    hdr.write_to(&mut msg[..Nlmsghdr::SIZE]);
}

fn getlink_dump_request() -> (Nlmsghdr, alloc::vec::Vec<u8>) {
    let body = alloc::vec![0u8; Ifinfomsg::SIZE];
    let hdr = Nlmsghdr {
        nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
        nlmsg_type: RTM_GETLINK, nlmsg_flags: crate::flags::NLM_F_DUMP,
        nlmsg_seq: 5, nlmsg_pid: 7,
    };
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut msg[..]);
    msg.extend_from_slice(&body);
    (hdr, msg)
}

fn getaddr6_one_request(ifindex: u32, addr: [u8; 16]) -> (Nlmsghdr, alloc::vec::Vec<u8>) {
    let mut body = alloc::vec![0u8; super::uapi::Ifaddrmsg::SIZE];
    body[0] = super::uapi::AF_INET6;
    body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    super::put_nlattr(&mut body, ifa::IFA_ADDRESS, &addr);
    let hdr = Nlmsghdr {
        nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
        nlmsg_type: RTM_GETADDR, nlmsg_flags: crate::flags::NLM_F_REQUEST,
        nlmsg_seq: 5, nlmsg_pid: 7,
    };
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut msg[..]);
    msg.extend_from_slice(&body);
    (hdr, msg)
}

#[test]
fn a_strict_address_dump_answers_only_the_device_the_caller_named() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let stack = net::global_stack();
    let lo = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), 0);
    let eth = stack.ifaces.register_in_ns(Arc::new(MovingDev), 0);
    let lo_idx = visible_ifindex(lo, 0);
    let eth_idx = visible_ifindex(eth, 0);
    // The address table is keyed by the internal device id; the dump maps it
    // to the namespace ifindex the reply carries.
    for (idx, addr, plen) in [(lo.raw(), [127, 0, 0, 1], 8u8), (eth.raw(), [10, 0, 2, 15], 24)] {
        super::rtnetlink_addr::addr_insert(net::iface_addr::Ipv4IfaceAddr {
            ns: 0, iface: net::NetIfaceId::from_raw(idx), addr: net::Ipv4Addr::from_u32(u32::from_be_bytes(addr)), peer: None, mask: 0,
            broadcast: None,
            prefixlen: plen, scope: super::uapi::RT_SCOPE_UNIVERSE,
            flags: net::iface_addr::IFA_F_PERMANENT, proto: 0, rt_priority: 0,
            cacheinfo: net::iface_addr::Ipv4AddrCacheInfo::PERMANENT,
        });
    }

    // Without the option the header is not a filter: every address comes back,
    // which is what `ip addr show dev eth0` used to receive for the namespace.
    let (req, msg) = getaddr_request(eth_idx, 0);
    let lax = addr_rows(&handle_getaddr_in(0, &req, &msg, false));
    assert!(lax.iter().any(|(i, _)| *i == lo_idx));
    assert!(lax.iter().any(|(i, _)| *i == eth_idx));
    assert!(lax.iter().all(|(_, f)| f & crate::rtnetlink::NLM_F_DUMP_FILTERED == 0),
        "an unfiltered answer must not claim to be filtered");

    // With it the answer covers exactly the named device and says so.
    let strict = addr_rows(&handle_getaddr_in(0, &req, &msg, true));
    assert_eq!(strict.len(), 1, "only the named device");
    assert_eq!(strict[0].0, eth_idx);
    assert_ne!(strict[0].1 & crate::rtnetlink::NLM_F_DUMP_FILTERED, 0,
        "the reference marks a filtered dump so the client can tell");
    assert_ne!(strict[0].1 & crate::flags::NLM_F_MULTI, 0, "still a multipart dump");

    // A zero filter under the option still dumps the namespace.
    let (all_req, all_msg) = getaddr_request(0, 0);
    let all = addr_rows(&handle_getaddr_in(0, &all_req, &all_msg, true));
    assert!(all.len() >= 2);
    assert!(all.iter().all(|(_, f)| f & crate::rtnetlink::NLM_F_DUMP_FILTERED == 0));
}

#[test]
fn a_strict_address_dump_resolves_a_caller_local_target_namespace() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let caller = network_namespace::initial();
    let target = crate::netlink_tests::test_namespace();
    let target_id = target.id().as_u64();
    caller.assign_peer_id(&target, 47).unwrap();
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), target_id);
    let addr = net::Ipv4Addr::new(198, 51, 100, 7);
    assert!(stack.set_ipv4_prefix_meta_in(target_id, iface, addr, None, 24,
        net::iface_addr::Ipv4AddrMeta::permanent(super::uapi::RT_SCOPE_UNIVERSE)));
    let (req, mut msg) = getaddr_request(0, 0);
    target_attr(&mut msg, 47);

    let reply = handle_getaddr_with_access(0, &req, &msg, true,
        |owner| owner.id().as_u64() == target_id);
    assert_eq!(addr_rows(&reply).len(), 1);
    assert_eq!(addr_rows(&reply)[0].0, visible_ifindex(iface, target_id));
    let attrs = &reply[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
    assert_eq!(super::find_attr(attrs, ifa::IFA_TARGET_NETNSID).unwrap(), &47i32.to_ne_bytes());
    let denied = handle_getaddr_with_access(0, &req, &msg, true, |_| false);
    assert_eq!(ack_errno(&denied), -(syscall::errno::Errno::Eacces.as_i32()));
}

#[test]
fn a_link_dump_resolves_a_caller_local_target_namespace() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let caller = network_namespace::initial();
    let target = crate::netlink_tests::test_namespace();
    let target_id = target.id().as_u64();
    caller.assign_peer_id(&target, 49).unwrap();
    let iface = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), target_id);
    let (req, mut msg) = getlink_dump_request();
    link_target_attr(&mut msg, 49);

    let reply = crate::rtnetlink::handle_getlink_with_access(0, &req, &msg, true,
        |owner| owner.id().as_u64() == target_id);
    let hdr = Nlmsghdr::parse(&reply).unwrap();
    assert_eq!(hdr.nlmsg_type, RTM_NEWLINK);
    assert_eq!(u32::from_ne_bytes(reply[Nlmsghdr::SIZE + 4..Nlmsghdr::SIZE + 8].try_into().unwrap()),
        visible_ifindex(iface, target_id));
    let attrs = &reply[Nlmsghdr::SIZE + Ifinfomsg::SIZE..];
    assert_eq!(super::find_attr(attrs, ifla::IFLA_TARGET_NETNSID).unwrap(), &49i32.to_ne_bytes());
    let mut one_req = req;
    one_req.nlmsg_flags = crate::flags::NLM_F_REQUEST;
    let mut one_msg = msg.clone();
    one_msg[Nlmsghdr::SIZE + 4..Nlmsghdr::SIZE + 8].copy_from_slice(&visible_ifindex(iface, target_id).to_ne_bytes());
    one_req.write_to(&mut one_msg[..Nlmsghdr::SIZE]);
    let one = crate::rtnetlink::handle_getlink_with_access(0, &one_req, &one_msg, true,
        |owner| owner.id().as_u64() == target_id);
    assert_eq!(Nlmsghdr::parse(&one).unwrap().nlmsg_flags & crate::flags::NLM_F_MULTI, 0);
    assert_eq!(super::find_attr(&one[Nlmsghdr::SIZE + Ifinfomsg::SIZE..], ifla::IFLA_TARGET_NETNSID).unwrap(),
        &49i32.to_ne_bytes());
    let denied = crate::rtnetlink::handle_getlink_with_access(0, &req, &msg, true, |_| false);
    assert_eq!(ack_errno(&denied), -(syscall::errno::Errno::Eacces.as_i32()));
    let _ = net::global_stack().ifaces.unregister(iface);
}

#[test]
fn an_ipv6_address_lookup_resolves_a_caller_local_target_namespace() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let caller = network_namespace::initial();
    let target = crate::netlink_tests::test_namespace();
    let target_id = target.id().as_u64();
    caller.assign_peer_id(&target, 48).unwrap();
    let iface = net::global_stack().ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), target_id);
    let addr = net::Ipv6Addr([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48]);
    net::global_stack().add_v6_addr(iface, addr);
    let (req, mut msg) = getaddr6_one_request(visible_ifindex(iface, target_id), addr.0);
    target_attr(&mut msg, 48);

    let reply = crate::rtnetlink::handle_getaddr6_one_with_access(0, &req, &msg,
        |owner| owner.id().as_u64() == target_id);
    assert_eq!(Nlmsghdr::parse(&reply).unwrap().nlmsg_type, RTM_NEWADDR);
    let attrs = &reply[Nlmsghdr::SIZE + Ifaddrmsg::SIZE..];
    assert_eq!(super::find_attr(attrs, ifa::IFA_TARGET_NETNSID).unwrap(), &48i32.to_ne_bytes());
    let denied = crate::rtnetlink::handle_getaddr6_one_with_access(0, &req, &msg, |_| false);
    assert_eq!(ack_errno(&denied), -(syscall::errno::Errno::Eacces.as_i32()));
    let _ = net::global_stack().ifaces.unregister(iface);
}

#[test]
fn a_strict_address_dump_refuses_a_header_field_a_request_cannot_carry() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let (req, msg) = getaddr_request(0, 24);
    assert_eq!(ack_errno(&handle_getaddr_in(0, &req, &msg, true)),
        -(syscall::errno::Errno::Einval.as_i32()));
    // The same request is answered when the caller never asked for validation.
    let lax = handle_getaddr_in(0, &req, &msg, false);
    assert_ne!(u16::from_ne_bytes([lax[4], lax[5]]), crate::msg::NLMSG_ERROR);
}

#[test]
fn a_strict_address_dump_reports_enodev_for_a_device_that_is_not_there() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let (req, msg) = getaddr_request(4242, 0);
    assert_eq!(ack_errno(&handle_getaddr_in(0, &req, &msg, true)),
        -(syscall::errno::Errno::Enodev.as_i32()));
}

#[test]
fn a_strict_link_dump_refuses_a_device_filter_it_cannot_honour() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let mut body = alloc::vec![0u8; super::uapi::Ifinfomsg::SIZE];
    body[4..8].copy_from_slice(&2i32.to_ne_bytes());
    let hdr = Nlmsghdr {
        nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
        nlmsg_type: RTM_GETLINK, nlmsg_flags: crate::flags::NLM_F_DUMP,
        nlmsg_seq: 1, nlmsg_pid: 2,
    };
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut msg[..]);
    msg.extend_from_slice(&body);
    assert_eq!(ack_errno(&handle_getlink_in(0, &hdr, &msg, true)),
        -(syscall::errno::Errno::Einval.as_i32()));
    // Unvalidated, the same request still produces the full dump it always did.
    let lax = handle_getlink_in(0, &hdr, &msg, false);
    assert_ne!(u16::from_ne_bytes([lax[4], lax[5]]), crate::msg::NLMSG_ERROR);
}
