// Everything an RTM_NEWADDR states must read back unchanged.
//
// A field the kernel drops, or one it invents, makes the address read back
// different from the one that was asked for. A manager that reconciles its own
// state against the table then re-applies the address forever trying to
// correct the difference — measured on a live boot as one RTM_NEWADDR every
// four seconds for the whole run.

use super::*;

/// Attributes of the first RTM_NEWADDR in a reply, as (type, payload).
fn attrs(reply: &[u8]) -> alloc::vec::Vec<(u16, alloc::vec::Vec<u8>)> {
    let hdr = Nlmsghdr::parse(reply).expect("a header");
    assert_eq!(hdr.nlmsg_type, RTM_NEWADDR);
    let body = &reply[Nlmsghdr::SIZE..hdr.nlmsg_len as usize];
    let mut out = alloc::vec::Vec::new();
    let mut at = super::uapi::Ifaddrmsg::SIZE;
    while at + 4 <= body.len() {
        let len = u16::from_ne_bytes([body[at], body[at + 1]]) as usize;
        let typ = u16::from_ne_bytes([body[at + 2], body[at + 3]]);
        if len < 4 || at + len > body.len() { break; }
        out.push((typ, body[at + 4..at + len].to_vec()));
        at += nlmsg_align(len);
    }
    out
}

fn find(a: &[(u16, alloc::vec::Vec<u8>)], typ: u16) -> Option<&alloc::vec::Vec<u8>> {
    a.iter().find(|(t, _)| *t == typ).map(|(_, v)| v)
}

const LOCAL: [u8; 4] = [10, 0, 2, 15];
const BCAST: [u8; 4] = [10, 0, 2, 255];
const DHCP_PROTO: u8 = 16;
const METRIC: u32 = 425;

fn reply_for(row: super::rtnetlink_addr::IfaceAddr) -> alloc::vec::Vec<u8> {
    build_newaddr_reply(1, 2, 3, "eth0", row.addr, row.peer, row.broadcast, row.prefixlen,
        row.scope, row.flags, row.proto, row.rt_priority, row.cacheinfo,
        crate::flags::NLM_F_MULTI)
}

fn dhcp_row() -> super::rtnetlink_addr::IfaceAddr {
    super::rtnetlink_addr::IfaceAddr {
        ns: 0, ifindex: 3, family: super::uapi::AF_INET, addr: LOCAL, peer: None,
        broadcast: Some(BCAST), prefixlen: 24, scope: super::uapi::RT_SCOPE_UNIVERSE,
        flags: 0, proto: DHCP_PROTO, rt_priority: METRIC,
        cacheinfo: super::rtnetlink_addr::IfaCacheInfo {
            preferred: 3600, valid: 7200, cstamp: 0, tstamp: 0 },
    }
}

#[test]
fn every_field_the_setter_stated_comes_back() {
    let a = attrs(&reply_for(dhcp_row()));
    assert_eq!(find(&a, ifa::IFA_LOCAL).map(|v| v.as_slice()), Some(&LOCAL[..]));
    assert_eq!(find(&a, ifa::IFA_ADDRESS).map(|v| v.as_slice()), Some(&LOCAL[..]));
    assert_eq!(find(&a, ifa::IFA_BROADCAST).map(|v| v.as_slice()), Some(&BCAST[..]),
        "the broadcast the setter chose, not one derived from the prefix");
    assert_eq!(find(&a, ifa::IFA_PROTO).map(|v| v[0]), Some(DHCP_PROTO),
        "the owning agent is reported so a reader can tell who added the address");
    assert_eq!(find(&a, ifa::IFA_RT_PRIORITY).map(|v| u32::from_ne_bytes(
        v[0..4].try_into().unwrap())), Some(METRIC));
}

#[test]
fn a_field_the_setter_left_unset_is_not_invented() {
    // The reference reports IFA_BROADCAST only when the address carries one,
    // and never derives it. Deriving one hands the setter back a value it
    // never asked for, which reads as a difference it must correct.
    let mut row = dhcp_row();
    row.broadcast = None;
    row.proto = 0;
    row.rt_priority = 0;
    let a = attrs(&reply_for(row));
    assert!(find(&a, ifa::IFA_BROADCAST).is_none());
    assert!(find(&a, ifa::IFA_PROTO).is_none());
    assert!(find(&a, ifa::IFA_RT_PRIORITY).is_none());
    // The address itself is still fully reported.
    assert_eq!(find(&a, ifa::IFA_LOCAL).map(|v| v.as_slice()), Some(&LOCAL[..]));
}

#[test]
fn a_point_to_point_address_reports_the_peer_as_the_prefix_address() {
    let mut row = dhcp_row();
    let peer = [192, 0, 2, 1];
    row.peer = Some(peer);
    let a = attrs(&reply_for(row));
    assert_eq!(find(&a, ifa::IFA_LOCAL).map(|v| v.as_slice()), Some(&LOCAL[..]));
    assert_eq!(find(&a, ifa::IFA_ADDRESS).map(|v| v.as_slice()), Some(&peer[..]));
}

#[test]
fn the_header_flags_are_the_low_byte_and_the_attribute_carries_all_32_bits() {
    let mut row = dhcp_row();
    // IFA_F_NOPREFIXROUTE is 0x200 — it does not fit the u8 header field, so a
    // reader that only looks there must still find it in IFA_FLAGS.
    row.flags = 0x200 | net::iface_addr::IFA_F_PERMANENT;
    let reply = reply_for(row);
    let header_flags = reply[Nlmsghdr::SIZE + 2];
    assert_eq!(header_flags, net::iface_addr::IFA_F_PERMANENT as u8);
    let a = attrs(&reply);
    assert_eq!(find(&a, ifa::IFA_FLAGS).map(|v| u32::from_ne_bytes(v[0..4].try_into().unwrap())),
        Some(0x200 | net::iface_addr::IFA_F_PERMANENT));
}

#[test]
fn a_permanent_address_reports_infinite_lifetimes() {
    let mut row = dhcp_row();
    row.flags = net::iface_addr::IFA_F_PERMANENT;
    let a = attrs(&reply_for(row));
    let ci = find(&a, ifa::IFA_CACHEINFO).expect("cacheinfo");
    assert_eq!(u32::from_ne_bytes(ci[0..4].try_into().unwrap()), u32::MAX);
    assert_eq!(u32::from_ne_bytes(ci[4..8].try_into().unwrap()), u32::MAX);
}

#[test]
fn a_new_address_carries_every_field_through_the_table_to_the_dump() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let stack = net::global_stack();
    let eth = stack.ifaces.register_in_ns(Arc::new(MovingDev), 0);
    let idx = visible_ifindex(eth, 0);

    // RTM_NEWADDR naming a broadcast, an owning protocol and a route metric.
    let mut body = alloc::vec![0u8; super::uapi::Ifaddrmsg::SIZE];
    body[0] = super::uapi::AF_INET;
    body[1] = 24;
    body[3] = super::uapi::RT_SCOPE_UNIVERSE;
    body[4..8].copy_from_slice(&idx.to_ne_bytes());
    let mut put = |typ: u16, payload: &[u8]| {
        let len = 4 + payload.len();
        body.extend_from_slice(&(len as u16).to_ne_bytes());
        body.extend_from_slice(&typ.to_ne_bytes());
        body.extend_from_slice(payload);
        while body.len() % 4 != 0 { body.push(0); }
    };
    put(ifa::IFA_LOCAL, &LOCAL);
    put(ifa::IFA_BROADCAST, &BCAST);
    put(ifa::IFA_PROTO, &[DHCP_PROTO]);
    put(ifa::IFA_RT_PRIORITY, &METRIC.to_ne_bytes());
    let req = Nlmsghdr {
        nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32, nlmsg_type: RTM_NEWADDR,
        nlmsg_flags: crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_CREATE,
        nlmsg_seq: 4, nlmsg_pid: 5,
    };
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    req.write_to(&mut msg[..]);
    msg.extend_from_slice(&body);
    let ack = handle_newaddr_in(0, &req, &msg);
    assert_eq!(i32::from_ne_bytes([ack[16], ack[17], ack[18], ack[19]]), 0, "the add succeeds");

    let dump_req = Nlmsghdr {
        nlmsg_len: Nlmsghdr::SIZE as u32, nlmsg_type: RTM_GETADDR,
        nlmsg_flags: crate::flags::NLM_F_DUMP, nlmsg_seq: 6, nlmsg_pid: 5,
    };
    let mut dump_msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    dump_req.write_to(&mut dump_msg[..]);
    let a = attrs(&handle_getaddr_in(0, &dump_req, &dump_msg, false));
    assert_eq!(find(&a, ifa::IFA_LOCAL).map(|v| v.as_slice()), Some(&LOCAL[..]));
    assert_eq!(find(&a, ifa::IFA_BROADCAST).map(|v| v.as_slice()), Some(&BCAST[..]));
    assert_eq!(find(&a, ifa::IFA_PROTO).map(|v| v[0]), Some(DHCP_PROTO));
    assert_eq!(find(&a, ifa::IFA_RT_PRIORITY).map(|v| u32::from_ne_bytes(
        v[0..4].try_into().unwrap())), Some(METRIC));
}
