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
        super::rtnetlink_addr::addr_insert(super::rtnetlink_addr::IfaceAddr {
            ns: 0, ifindex: idx, family: super::uapi::AF_INET, addr, peer: None, broadcast: None,
            prefixlen: plen, scope: super::uapi::RT_SCOPE_UNIVERSE,
            flags: net::iface_addr::IFA_F_PERMANENT, proto: 0, rt_priority: 0,
            cacheinfo: super::rtnetlink_addr::IfaCacheInfo::PERMANENT,
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
