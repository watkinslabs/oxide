//! Address-owned IPv6 multicast membership lifecycle.

use super::*;
use super::address6_common::*;

use net::iface_addr::IFA_F_MCAUTOJOIN;

fn group() -> [u8; 16] {
    let mut group = [0u8; 16];
    group[0] = 0xff; group[1] = 0x02; group[15] = 0x42;
    group
}

fn membership_exists(iface: net::NetIfaceId, group: [u8; 16]) -> bool {
    net::global_stack().v6_multicast_snapshot_in(0).contains(&(iface, net::Ipv6Addr(group)))
}

#[test]
fn mcautojoin_adds_and_delete_releases_the_address_owned_membership() {
    let fx = fixture();
    let group = group();
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 128, group, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_MCAUTOJOIN.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    assert!(membership_exists(fx.iface, group));

    let (req, msg) = addr6_req(RTM_DELADDR, fx.ifindex, 128, group, 0, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), 0);
    assert!(!membership_exists(fx.iface, group));
}

#[test]
fn deleting_an_autojoin_address_preserves_an_independent_membership() {
    let fx = fixture();
    let group = group();
    net::global_stack().join_ipv6_multicast_in(0, fx.iface, net::Ipv6Addr(group),
        net::Ipv6Addr::ANY).unwrap();

    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 128, group, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_MCAUTOJOIN.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let (req, msg) = addr6_req(RTM_DELADDR, fx.ifindex, 128, group, 0, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), 0);
    assert!(membership_exists(fx.iface, group));

    net::global_stack().leave_ipv6_multicast_in(0, fx.iface, net::Ipv6Addr(group),
        net::Ipv6Addr::ANY).unwrap();
    assert!(!membership_exists(fx.iface, group));
}
