//! Which errno an `AF_INET6` address write answers, and in what order, plus
//! what a delete matches. The add and the delete order their checks
//! differently and both orders are the reference's, so they are pinned side by
//! side here.

use super::*;
use super::address6_common::*;

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
