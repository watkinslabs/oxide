//! What an `AF_INET6` address add stores and reports: the address itself, the
//! flags the setter owns, the lifetimes, the peer, and what a replace rewrites.
//!
//! The link-local address here is the one a network manager assigns after it
//! takes the interface. That add answered `EAFNOSUPPORT` before this contract
//! existed, and the manager backed off after retrying with fresh addresses, so
//! the interface never held a link-local address at all.

use super::*;
use super::address6_common::*;

use net::iface_addr::{IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_MANAGETEMPADDR, IFA_F_MCAUTOJOIN,
    IFA_F_NODAD, IFA_F_NOPREFIXROUTE, IFA_F_OPTIMISTIC, IFA_F_PERMANENT, IFA_F_SECONDARY, IFA_F_TENTATIVE,
    INFINITY_LIFE_TIME};

struct OptimisticAll;
impl OptimisticAll {
    fn set() -> Self {
        net::sysctl::set_value_in(0, net::net_ns::NetSysctlKey::Ipv6OptimisticDadAll, 1).unwrap();
        Self
    }
}
impl Drop for OptimisticAll {
    fn drop(&mut self) {
        net::sysctl::set_value_in(0, net::net_ns::NetSysctlKey::Ipv6OptimisticDadAll, 0).unwrap();
        net::sysctl::set_value_in(0, net::net_ns::NetSysctlKey::Ipv6UseOptimisticAll, 0).unwrap();
    }
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

#[test]
fn disable_ipv6_is_enforced_by_the_selected_interface() {
    let fx = fixture();
    let conf = net::global_stack().ifaces.ipv6_conf_by_name_in("eth-stable", 0).unwrap();
    conf.set_value(net::netdev::Ipv6ConfKey::DisableIpv6, 1);
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0,
        crate::flags::NLM_F_CREATE);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), -13);

    conf.set_value(net::netdev::Ipv6ConfKey::DisableIpv6, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    conf.set_value(net::netdev::Ipv6ConfKey::DisableIpv6, 1);
    let (req, msg) = addr6_req(RTM_DELADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), -6);
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

#[test]
fn optimistic_dad_policy_keeps_the_tentative_address_live() {
    let fx = fixture();
    let _policy = OptimisticAll::set();
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_OPTIMISTIC.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let row = row_for(fx.iface, GLOBAL).unwrap();
    assert!(matches!(row.state, net::stack_ipv6::Ipv6AddrState::Tentative { .. }));
    assert_eq!(row.flags() & (IFA_F_TENTATIVE | IFA_F_OPTIMISTIC),
        IFA_F_TENTATIVE | IFA_F_OPTIMISTIC);
    assert!(net::global_stack().v6_addr_owned_by(fx.iface, net::Ipv6Addr(GLOBAL)),
        "an optimistic address receives while DAD is pending");
}

#[test]
fn nodad_and_enabled_optimistic_dad_are_mutually_exclusive() {
    let fx = fixture();
    let _policy = OptimisticAll::set();
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    let flags = IFA_F_NODAD | IFA_F_OPTIMISTIC;
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &flags.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), -22);
    assert!(row_for(fx.iface, GLOBAL).is_none());
}

#[test]
fn disabled_optimistic_dad_clears_the_bit_before_conflict_validation() {
    let fx = fixture();
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    let flags = IFA_F_NODAD | IFA_F_OPTIMISTIC;
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &flags.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let row = row_for(fx.iface, GLOBAL).unwrap();
    assert_eq!(row.flags() & IFA_F_OPTIMISTIC, 0);
    assert_eq!(row.flags() & IFA_F_NODAD, IFA_F_NODAD);
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

#[test]
fn managed_public_address_creates_updates_and_deletes_its_temporary_child() {
    let fx = fixture();
    let conf = net::global_stack().ifaces.ipv6_conf_by_name_in("eth-stable", 0).unwrap();
    conf.set_value(net::netdev::Ipv6ConfKey::UseTempaddr, 1);
    conf.set_value(net::netdev::Ipv6ConfKey::TempValidLft, 100);
    conf.set_value(net::netdev::Ipv6ConfKey::TempPreferredLft, 50);
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_MANAGETEMPADDR.to_ne_bytes());
    cacheinfo_attr(&mut msg, 80, 200);
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let rows = net::global_stack().v6_addr_snapshot_in(0).into_iter()
        .filter(|(iface, _)| *iface == fx.iface).map(|(_, row)| row).collect::<Vec<_>>();
    let child = rows.iter().find(|row| row.temporary).expect("one privacy child");
    assert_eq!(child.temporary_parent, Some(net::Ipv6Addr(GLOBAL)));
    assert_eq!(&child.addr.0[..8], &GLOBAL[..8]);
    assert_eq!((child.valid, child.preferred), (100, 50));
    assert!(matches!(child.state, net::stack_ipv6::Ipv6AddrState::Tentative { .. }));

    let child_addr = child.addr;
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0,
        crate::flags::NLM_F_REPLACE);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_MANAGETEMPADDR.to_ne_bytes());
    cacheinfo_attr(&mut msg, 20, 30);
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let updated = net::global_stack().v6_addr_snapshot_in(0).into_iter()
        .find(|(iface, row)| *iface == fx.iface && row.addr == child_addr).unwrap().1;
    assert_eq!((updated.valid, updated.preferred), (30, 20));

    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0,
        crate::flags::NLM_F_REPLACE);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    assert!(net::global_stack().v6_addr_snapshot_in(0).into_iter()
        .filter(|(iface, _)| *iface == fx.iface).all(|(_, row)| !row.temporary));
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

fn address_prefix_routes(iface: net::NetIfaceId) -> Vec<net::Route6Entry> {
    net::global_stack().routes6.snapshot_in(0).into_iter().filter(|route| {
        route.iface == iface && matches!(route.origin, net::Route6Origin::AddressPrefix { .. })
    }).collect()
}

#[test]
fn an_address_installs_a_canonical_kernel_prefix_route_with_its_priority() {
    let fx = fixture();
    let mut dirty = GLOBAL;
    dirty[8] = 0x12; dirty[15] = 0x34;
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, dirty, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_RT_PRIORITY, &777u32.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let routes = address_prefix_routes(fx.iface);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].dst.0, [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(routes[0].prefix_len, 64);
    assert_eq!(routes[0].origin.metric(), 777);

    let wire = super::route_ops::build_newroute6_reply(1, 2, routes[0], false);
    assert_eq!(wire[Nlmsghdr::SIZE + 5], super::uapi::RTPROT_KERNEL);
    let attrs = &wire[Nlmsghdr::SIZE + super::uapi::Rtmsg::SIZE..];
    assert_eq!(u32::from_ne_bytes(find_attr(attrs, rta::RTA_PRIORITY)
        .expect("RTA_PRIORITY").try_into().unwrap()), 777);
}

#[test]
fn noprefixroute_suppresses_and_replace_reconciles_the_owned_route() {
    let fx = fixture();
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_NOPREFIXROUTE.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    assert!(address_prefix_routes(fx.iface).is_empty());

    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0,
        crate::flags::NLM_F_REPLACE);
    put_nlattr(&mut msg, ifa::IFA_RT_PRIORITY, &2048u32.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    assert_eq!(address_prefix_routes(fx.iface)[0].origin.metric(), 2048);

    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0,
        crate::flags::NLM_F_REPLACE);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_NOPREFIXROUTE.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    assert!(address_prefix_routes(fx.iface).is_empty());
}

#[test]
fn a_shared_prefix_route_survives_until_its_last_eligible_address_is_deleted() {
    let fx = fixture();
    let mut second = GLOBAL; second[15] = 2;
    for addr in [GLOBAL, second] {
        let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, addr, 0, 0);
        assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    }
    assert_eq!(address_prefix_routes(fx.iface).len(), 1);
    let (req, msg) = addr6_req(RTM_DELADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), 0);
    assert_eq!(address_prefix_routes(fx.iface).len(), 1);
    let (req, msg) = addr6_req(RTM_DELADDR, fx.ifindex, 64, second, 0, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), 0);
    assert!(address_prefix_routes(fx.iface).is_empty());
}

#[test]
fn finite_and_noprefixroute_peers_follow_the_prefix_cleanup_ladder() {
    let fx = fixture();
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    cacheinfo_attr(&mut msg, 30, 60);
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let (req, msg) = addr6_req(RTM_DELADDR, fx.ifindex, 64, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), 0);
    assert_eq!(address_prefix_routes(fx.iface).len(), 1,
        "a finite address leaves its independently expiring route");

    let mut permanent = GLOBAL; permanent[7] = 1; permanent[15] = 1;
    let mut guarded = permanent; guarded[15] = 2;
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, permanent, 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, guarded, 0, 0);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_NOPREFIXROUTE.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let (req, msg) = addr6_req(RTM_DELADDR, fx.ifindex, 64, permanent, 0, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), 0);
    assert!(address_prefix_routes(fx.iface).iter().any(|route| route.matches(net::Ipv6Addr(guarded))),
        "a same-prefix NOPREFIXROUTE address guards the pre-existing route");
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

// A replace asking for managed temporary addresses is screened against the row
// it would rewrite, not against the prefix length the request carries: a
// replace never changes the prefix length, so a /128 row can never own them
// however the second request is shaped.
#[test]
fn a_replace_cannot_ask_a_non_64_row_to_manage_temporaries() {
    let fx = fixture();
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 128, GLOBAL, 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);

    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, GLOBAL, 0,
        crate::flags::NLM_F_REPLACE);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_MANAGETEMPADDR.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), -22);
    let row = row_for(fx.iface, GLOBAL).unwrap();
    assert_eq!(row.prefixlen, 128, "the refused replace changed nothing");
    assert_eq!(row.flags() & IFA_F_MANAGETEMPADDR, 0);

    // The same replace against a /64 row is accepted.
    let mut sixty_four = GLOBAL;
    sixty_four[15] = 0x64;
    let (req, msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, sixty_four, 0, 0);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    let (mut req, mut msg) = addr6_req(RTM_NEWADDR, fx.ifindex, 64, sixty_four, 0,
        crate::flags::NLM_F_REPLACE);
    put_nlattr(&mut msg, ifa::IFA_FLAGS, &IFA_F_MANAGETEMPADDR.to_ne_bytes());
    seal(&mut req, &mut msg);
    assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0);
    assert_eq!(row_for(fx.iface, sixty_four).unwrap().flags() & IFA_F_MANAGETEMPADDR,
        IFA_F_MANAGETEMPADDR);
}
