//! `RTM_NEWADDR` / `RTM_DELADDR` for `AF_INET6`, driven through the handlers
//! the netlink socket dispatches to.
//!
//! The address in several of these is the link-local one a network manager
//! assigns after it takes the interface: that add answered
//! `EAFNOSUPPORT` before this contract existed, and the manager backed off
//! after retrying with fresh addresses, so the interface never held a
//! link-local address at all.

use super::*;

use net::iface_addr::{IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_MANAGETEMPADDR, IFA_F_MCAUTOJOIN,
    IFA_F_NODAD, IFA_F_NOPREFIXROUTE, IFA_F_PERMANENT, IFA_F_SECONDARY, IFA_F_TENTATIVE,
    INFINITY_LIFE_TIME};

const LINK_LOCAL: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                              0xca, 0x67, 0xcf, 0xc6, 0xb1, 0x78, 0x90, 0x02];
const GLOBAL: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11];

/// One `AF_INET6` address request. `attrs` are appended after `IFA_LOCAL`.
fn addr6_req(ty: u16, ifindex: u32, prefixlen: u8, addr: [u8; 16], ifa_flags: u8, msg_flags: u16)
    -> (Nlmsghdr, Vec<u8>)
{
    let mut body = Vec::new();
    let ifa = Ifaddrmsg {
        ifa_family: AF_INET6,
        ifa_prefixlen: prefixlen,
        ifa_flags,
        ifa_scope: RT_SCOPE_UNIVERSE,
        ifa_index: ifindex,
    };
    let mut ifa_buf = [0u8; Ifaddrmsg::SIZE];
    ifa.write_to(&mut ifa_buf);
    body.extend_from_slice(&ifa_buf);
    put_nlattr(&mut body, ifa::IFA_LOCAL, &addr);
    let mut hdr = Nlmsghdr {
        nlmsg_len: 0, nlmsg_type: ty,
        nlmsg_flags: crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_ACK | msg_flags,
        nlmsg_seq: 77, nlmsg_pid: 91,
    };
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    msg.extend_from_slice(&body);
    hdr.nlmsg_len = msg.len() as u32;
    hdr.write_to(&mut msg[..Nlmsghdr::SIZE]);
    (hdr, msg)
}

/// Re-stamp the header after appending attributes.
fn seal(hdr: &mut Nlmsghdr, msg: &mut [u8]) {
    hdr.nlmsg_len = msg.len() as u32;
    hdr.write_to(&mut msg[..Nlmsghdr::SIZE]);
}

fn cacheinfo_attr(msg: &mut Vec<u8>, preferred: u32, valid: u32) {
    let mut ci = [0u8; 16];
    ci[0..4].copy_from_slice(&preferred.to_ne_bytes());
    ci[4..8].copy_from_slice(&valid.to_ne_bytes());
    ci[8..12].copy_from_slice(&0x1234_5678u32.to_ne_bytes());
    ci[12..16].copy_from_slice(&0x8765_4321u32.to_ne_bytes());
    put_nlattr(msg, ifa::IFA_CACHEINFO, &ci);
}

struct Fixture {
    iface: net::NetIfaceId,
    ifindex: u32,
    _domain: net::hosted_fixture::InitNetDomain,
}

fn fixture() -> Fixture {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let iface = net::global_stack().ifaces.register_in_ns(Arc::new(MovingDev), 0);
    let ifindex = visible_ifindex(iface, 0);
    Fixture { iface, ifindex, _domain: domain }
}

impl Drop for Fixture {
    fn drop(&mut self) { let _ = net::global_stack().ifaces.unregister(self.iface); }
}

fn row_for(iface: net::NetIfaceId, addr: [u8; 16]) -> Option<net::stack_ipv6::Ipv6IfaceAddr> {
    net::global_stack().v6_addr_snapshot_in(0).into_iter()
        .find(|(id, row)| *id == iface && row.addr.0 == addr).map(|(_, row)| row)
}

// The reported failure, as a contract: the add succeeds, and the address is in
// the table the receive path and the dumps read.
#[test]
fn a_link_local_add_succeeds_and_lands_in_the_one_address_table() {
    let fx = fixture();
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, LINK_LOCAL, 0,
        crate::flags::NLM_F_CREATE);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0,
        "an AF_INET6 address add must not report a family error");
    let row = row_for(fx.iface, LINK_LOCAL).expect("the address is in the IPv6 table");
    assert_eq!(row.prefixlen, 64);
    assert_eq!(row.rt_scope(), RT_SCOPE_LINK);
    // The kernel owns permanence and verification state: an add with no
    // lifetime is permanent, and DAD has not finished, so it is tentative.
    assert_eq!(row.flags() & IFA_F_PERMANENT, IFA_F_PERMANENT);
    assert_eq!(row.flags() & IFA_F_TENTATIVE, IFA_F_TENTATIVE);
    assert_eq!(row.valid, INFINITY_LIFE_TIME);
    assert_eq!(row.preferred, INFINITY_LIFE_TIME);
}

// The address must reach the RTM_GETADDR dump, which is what a manager reads
// back to decide whether its own request took effect.
#[test]
fn an_added_address_is_reported_by_the_getaddr_dump() {
    let fx = fixture();
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let dump_req = Nlmsghdr { nlmsg_len: 32, nlmsg_type: RTM_GETADDR,
        nlmsg_flags: crate::flags::NLM_F_DUMP, nlmsg_seq: 5, nlmsg_pid: 6 };
    let dump = handle_getaddr(&dump_req);
    assert!(dump.windows(GLOBAL.len()).any(|window| window == GLOBAL),
        "the dump must carry the address that was just added");
}

#[test]
fn newaddr6_matches_linux_create_replace_exclusive_semantics() {
    let fx = fixture();
    let combinations = [0, crate::flags::NLM_F_CREATE, crate::flags::NLM_F_REPLACE,
        crate::flags::NLM_F_EXCL, crate::flags::NLM_F_CREATE | crate::flags::NLM_F_REPLACE,
        crate::flags::NLM_F_CREATE | crate::flags::NLM_F_EXCL,
        crate::flags::NLM_F_REPLACE | crate::flags::NLM_F_EXCL,
        crate::flags::NLM_F_CREATE | crate::flags::NLM_F_REPLACE | crate::flags::NLM_F_EXCL];
    for (index, flags) in combinations.into_iter().enumerate() {
        let mut addr = GLOBAL;
        addr[15] = 0x20 + index as u8;
        let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, addr, 0, flags);
        assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0, "first add, flags {flags:#x}");
        let expected = if flags & crate::flags::NLM_F_REPLACE != 0
            && flags & crate::flags::NLM_F_EXCL == 0 { 0 } else { -17 };
        let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, addr, 0, flags);
        assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), expected,
            "second add, flags {flags:#x}");
        let (req, msg) = addr6_req(RTM_DELADDR, fx.ifindex, 64, addr, 0, 0);
        assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), 0);
    }
}

// The existence screen is by address alone, so a repeat add naming a different
// prefix length is still EEXIST — and it is decided BEFORE the prefix-length
// ceiling, so an impossible prefix length on an existing address still reports
// the collision.
#[test]
fn an_existing_address_is_eexist_whatever_prefix_length_is_named() {
    let fx = fixture();
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 128, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), -17);
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 200, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), -17,
        "EEXIST is decided before the prefix-length ceiling");
    // A replace keeps the row rather than recreating it, so the prefix length
    // the original add named survives.
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 128, GLOBAL, 0,
        crate::flags::NLM_F_REPLACE);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    assert_eq!(row_for(fx.iface, GLOBAL).unwrap().prefixlen, 64);
}

// An add resolves the interface first; a delete rejects the prefix length
// first. Two different orders, both the reference's.
#[test]
fn prefix_length_and_interface_are_ordered_per_operation() {
    let fx = fixture();
    let (req, msg) = addr6_req(RTM_NEWADDR, u32::MAX, 129, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), -19,
        "an add reports the missing interface before the prefix length");
    let (req, msg) = addr6_req(RTM_DELADDR, u32::MAX, 129, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), -22,
        "a delete reports the prefix length before the missing interface");
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 129, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), -22);
    assert!(row_for(fx.iface, GLOBAL).is_none());
}

// No address attribute at all is EINVAL, and it is decided before anything
// looks at the interface.
#[test]
fn a_request_with_no_address_attribute_is_einval() {
    let fx = fixture();
    for ty in [RTM_NEWADDR, RTM_DELADDR] {
        let mut body = Vec::new();
        let ifa = Ifaddrmsg { ifa_family: AF_INET6, ifa_prefixlen: 64, ifa_flags: 0,
            ifa_scope: RT_SCOPE_UNIVERSE, ifa_index: fx.ifindex };
        let mut ifa_buf = [0u8; Ifaddrmsg::SIZE];
        ifa.write_to(&mut ifa_buf);
        body.extend_from_slice(&ifa_buf);
        let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
        msg.extend_from_slice(&body);
        let mut hdr = Nlmsghdr { nlmsg_len: 0, nlmsg_type: ty,
            nlmsg_flags: crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_ACK,
            nlmsg_seq: 1, nlmsg_pid: 2 };
        seal(&mut hdr, &mut msg);
        let reply = if ty == RTM_NEWADDR { handle_newaddr(&hdr, &msg) }
            else { handle_deladdr(&hdr, &msg) };
        assert_eq!(ack_errno(&reply), -22);
    }
}

// An address attribute shorter than an IPv6 address violates the policy.
#[test]
fn a_short_address_attribute_is_einval() {
    let fx = fixture();
    for attr in [ifa::IFA_LOCAL, ifa::IFA_ADDRESS] {
        let mut body = Vec::new();
        let ifa = Ifaddrmsg { ifa_family: AF_INET6, ifa_prefixlen: 64, ifa_flags: 0,
            ifa_scope: RT_SCOPE_UNIVERSE, ifa_index: fx.ifindex };
        let mut ifa_buf = [0u8; Ifaddrmsg::SIZE];
        ifa.write_to(&mut ifa_buf);
        body.extend_from_slice(&ifa_buf);
        put_nlattr(&mut body, attr, &GLOBAL[..4]);
        let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
        msg.extend_from_slice(&body);
        let mut hdr = Nlmsghdr { nlmsg_len: 0, nlmsg_type: RTM_NEWADDR,
            nlmsg_flags: crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_ACK,
            nlmsg_seq: 1, nlmsg_pid: 2 };
        seal(&mut hdr, &mut msg);
        assert_eq!(ack_errno(&handle_newaddr(&hdr, &msg)), -22);
    }
}

// The unspecified address, and the loopback address on anything but a loopback
// interface, are EADDRNOTAVAIL. A multicast address needs IFA_F_MCAUTOJOIN.
#[test]
fn unassignable_addresses_report_eaddrnotavail() {
    let fx = fixture();
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 0, [0u8; 16], 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), -99);

    let mut loopback = [0u8; 16];
    loopback[15] = 1;
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 128, loopback, 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), -99);

    let mut group = [0u8; 16];
    group[0] = 0xff; group[1] = 0x02; group[15] = 0x42;
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 128, group, 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), -99);
    // MCAUTOJOIN does not fit the header's byte-wide flags field, so it must
    // arrive in IFA_FLAGS.
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 128, group, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_MCAUTOJOIN.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    assert_eq!(row_for(fx.iface, group).unwrap().rt_scope(), RT_SCOPE_UNIVERSE);
}

// IFA_FLAGS overrides the header's byte-wide field, and only the setter-owned
// bits survive: a caller cannot declare its own address verified, failed, or
// permanent past its lifetime.
#[test]
fn only_setter_owned_flags_reach_the_row() {
    let fx = fixture();
    let claimed = IFA_F_NOPREFIXROUTE | IFA_F_DADFAILED | IFA_F_SECONDARY | IFA_F_DEPRECATED;
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &claimed.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let row = row_for(fx.iface, GLOBAL).unwrap();
    assert_eq!(row.flags() & IFA_F_NOPREFIXROUTE, IFA_F_NOPREFIXROUTE, "the setter's bit stays");
    assert_eq!(row.flags() & IFA_F_DADFAILED, 0, "DAD failure is not the setter's to declare");
    assert_eq!(row.flags() & IFA_F_SECONDARY, 0, "the privacy bit is not the setter's");
    assert_eq!(row.flags() & IFA_F_DEPRECATED, 0,
        "deprecation follows the preferred lifetime, not the request");
    assert_eq!(row.flags() & IFA_F_TENTATIVE, IFA_F_TENTATIVE);
}

// IFA_F_NODAD skips verification, so the address is usable the moment it is
// added and reports neither TENTATIVE nor a pending probe.
#[test]
fn nodad_assigns_the_address_without_verification() {
    let fx = fixture();
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_NODAD.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let row = row_for(fx.iface, GLOBAL).unwrap();
    assert_eq!(row.state, net::stack_ipv6::Ipv6AddrState::Assigned);
    assert_eq!(row.flags() & IFA_F_TENTATIVE, 0);
    assert_eq!(row.flags() & IFA_F_NODAD, IFA_F_NODAD);
    assert!(net::global_stack().v6_addr_owned_by(fx.iface, net::Ipv6Addr(GLOBAL)),
        "an address that skipped DAD is immediately usable");
}

// A finite valid lifetime is what strips IFA_F_PERMANENT; a preferred lifetime
// of zero deprecates the address on arrival. The two stamps the setter sends
// are discarded — they are the kernel's to publish.
#[test]
fn cacheinfo_lifetimes_drive_permanence_and_deprecation() {
    let fx = fixture();
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    cacheinfo_attr(&mut msg, 0, 3600);
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let row = row_for(fx.iface, GLOBAL).unwrap();
    assert_eq!(row.flags() & IFA_F_PERMANENT, 0, "a finite valid lifetime is not permanent");
    assert_eq!(row.flags() & IFA_F_DEPRECATED, IFA_F_DEPRECATED);
    assert_eq!(row.valid, 3600);
    assert_eq!(row.preferred, 0);
    assert_ne!(row.cstamp, 0x1234_5678);
    assert_ne!(row.tstamp, 0x8765_4321);

    // An infinite valid lifetime keeps permanence even with a finite preferred.
    let mut second = GLOBAL;
    second[15] = 0x12;
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, second, 0, 0);
    cacheinfo_attr(&mut msg, 600, INFINITY_LIFE_TIME);
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    assert_eq!(row_for(fx.iface, second).unwrap().flags() & IFA_F_PERMANENT, IFA_F_PERMANENT);
}

#[test]
fn a_zero_valid_lifetime_or_preferred_past_valid_is_einval() {
    let fx = fixture();
    for (preferred, valid) in [(0u32, 0u32), (3600, 1800)] {
        let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
        cacheinfo_attr(&mut msg, preferred, valid);
        seal(&mut req, &mut msg);
        assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), -22,
            "preferred {preferred} valid {valid}");
        assert!(row_for(fx.iface, GLOBAL).is_none());
    }
}

// A managed-temporary-address prefix must be a /64, and the rejection lands
// before the address is stored.
#[test]
fn managetempaddr_demands_a_64_bit_prefix() {
    let fx = fixture();
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 128, GLOBAL, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_MANAGETEMPADDR.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), -22);
    assert!(row_for(fx.iface, GLOBAL).is_none());

    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_MANAGETEMPADDR.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
}

// IFA_LOCAL is the local address; a differing IFA_ADDRESS is the peer, and it
// reads back in the attribute the reference reports it in.
#[test]
fn a_distinct_ifa_address_is_the_point_to_point_peer() {
    let fx = fixture();
    let mut peer = GLOBAL;
    peer[15] = 0x99;
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 128, GLOBAL, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_ADDRESS, &peer);
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let row = row_for(fx.iface, GLOBAL).unwrap();
    assert_eq!(row.peer.map(|peer| peer.0), Some(peer));
    assert_eq!(row.address().0, peer);

    // An IFA_ADDRESS equal to IFA_LOCAL names no peer.
    let mut alone = GLOBAL;
    alone[15] = 0x9a;
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 128, alone, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_ADDRESS, &alone);
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    assert_eq!(row_for(fx.iface, alone).unwrap().peer, None);
}

// IFA_ADDRESS alone is the local address, as it is for IPv4.
#[test]
fn ifa_address_alone_is_the_local_address() {
    let fx = fixture();
    let mut body = Vec::new();
    let ifa = Ifaddrmsg { ifa_family: AF_INET6, ifa_prefixlen: 64, ifa_flags: 0,
        ifa_scope: RT_SCOPE_UNIVERSE, ifa_index: fx.ifindex };
    let mut ifa_buf = [0u8; Ifaddrmsg::SIZE];
    ifa.write_to(&mut ifa_buf);
    body.extend_from_slice(&ifa_buf);
    put_nlattr(&mut body, ifa::IFA_ADDRESS, &GLOBAL);
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    msg.extend_from_slice(&body);
    let mut hdr = Nlmsghdr { nlmsg_len: 0, nlmsg_type: RTM_NEWADDR,
        nlmsg_flags: crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_ACK,
        nlmsg_seq: 1, nlmsg_pid: 2 };
    seal(&mut hdr, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&hdr, &msg)), 0);
    let row = row_for(fx.iface, GLOBAL).unwrap();
    assert_eq!(row.peer, None);
}

// IFA_PROTO and IFA_RT_PRIORITY are stored and read back. Dropping either
// makes the address read back different from the one that was asked for.
#[test]
fn proto_and_route_priority_round_trip() {
    let fx = fixture();
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_PROTO, &[3u8]);
    put_nlattr(&mut msg, ifa::IFA_RT_PRIORITY, &4096u32.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let row = row_for(fx.iface, GLOBAL).unwrap();
    assert_eq!(row.proto, 3);
    assert_eq!(row.rt_priority, 4096);
}

// The delete matches the address AND the exact prefix length; a mismatch on
// either is EADDRNOTAVAIL and leaves the row alone.
#[test]
fn deladdr6_matches_address_and_exact_prefix_length() {
    let fx = fixture();
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);

    let (req, msg) = addr6_req(RTM_DELADDR, fx.ifindex, 128, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), -99, "wrong prefix length");
    assert!(row_for(fx.iface, GLOBAL).is_some());

    let mut absent = GLOBAL;
    absent[15] = 0x7f;
    let (req, msg) = addr6_req(RTM_DELADDR, fx.ifindex, 64, absent, 0, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), -99, "address not assigned");

    let (req, msg) = addr6_req(RTM_DELADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), 0);
    assert!(row_for(fx.iface, GLOBAL).is_none(), "the removed address is gone from the table");
}

// An address a setter can add and cannot remove is worse than neither: the
// round trip has to work for the link-local address too.
#[test]
fn a_link_local_address_round_trips_through_add_and_delete() {
    let fx = fixture();
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, LINK_LOCAL, 0,
        crate::flags::NLM_F_CREATE);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let (req, msg) = addr6_req(RTM_DELADDR, fx.ifindex, 64, LINK_LOCAL, 0, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), 0);
    assert!(row_for(fx.iface, LINK_LOCAL).is_none());
}

// Both operations report a missing interface, not a missing address.
#[test]
fn an_unknown_interface_is_enodev() {
    let _fx = fixture();
    for ty in [RTM_NEWADDR, RTM_DELADDR] {
        let (req, msg) = addr6_req(ty, u32::MAX, 64, GLOBAL, 0, 0);
        let reply = if ty == RTM_NEWADDR { handle_newaddr(&req, &msg) }
            else { handle_deladdr(&req, &msg) };
        assert_eq!(ack_errno(&reply), -19);
    }
}

// A replace rewrites the lifetimes, the proto and the priority the setter
// restated, and leaves the verification state alone.
#[test]
fn a_replace_rewrites_the_restated_fields_and_keeps_dad_state() {
    let fx = fixture();
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_PROTO, &[2u8]);
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let before = row_for(fx.iface, GLOBAL).unwrap();
    assert_eq!(before.proto, 2);

    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0,
        crate::flags::NLM_F_REPLACE);
    put_nlattr(&mut msg, ifa::IFA_PROTO, &[5u8]);
    put_nlattr(&mut msg, ifa::IFA_RT_PRIORITY, &777u32.to_ne_bytes());
    cacheinfo_attr(&mut msg, 900, 1800);
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let after = row_for(fx.iface, GLOBAL).unwrap();
    assert_eq!(after.proto, 5);
    assert_eq!(after.rt_priority, 777);
    assert_eq!(after.valid, 1800);
    assert_eq!(after.preferred, 900);
    assert_eq!(after.flags() & IFA_F_PERMANENT, 0);
    assert_eq!(after.state, before.state, "a replace does not restart verification");
}
