// Hosted coverage for the `IPPROTO_IPV6` option table. These encode the
// verified Linux behaviour: value windows, capability ladders, errno ORDERING,
// the sticky-header shape screen and the flow-label lease rules.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::flowlabel::{self, FlowReq, Lease, Owner};
use super::get::{self, Ipv6GetState, Value};
use super::hdr;
use super::set::{self, Action, ArgClass, Ipv6Sock, RECVHOPLIMIT, RECVPKTINFO, RECVTCLASS};
use super::state::{Ipv6Opts, Sticky, flag};
use super::uapi::*;
use crate::sock_opts::sol_socket::OptCaps;

fn dgram() -> Ipv6Sock { Ipv6Sock { dgram: true, protocol: IPPROTO_UDP, ..Default::default() } }
fn stream() -> Ipv6Sock { Ipv6Sock { stream: true, protocol: IPPROTO_TCP, ..Default::default() } }
fn raw(proto: u8) -> Ipv6Sock { Ipv6Sock { raw: true, protocol: proto, ..Default::default() } }
fn none() -> OptCaps { OptCaps::default() }
fn net_raw() -> OptCaps { OptCaps { net_raw: true, net_admin: false } }
fn net_admin() -> OptCaps { OptCaps { net_raw: false, net_admin: true } }

fn set6(name: u64, val: i32, len: u32) -> Result<Action, Errno> {
    set::admit(name, val, len, dgram(), none())
}

// ---- operand shape ------------------------------------------------------

#[test]
fn this_level_reads_a_whole_int_or_nothing() {
    // Unlike the IPv4 level there is no single-byte form: a short operand is
    // either refused or read as zero, never as a byte.
    for name in [IPV6_UNICAST_HOPS, IPV6_MTU, IPV6_MINHOPCOUNT, IPV6_RECVERR,
        IPV6_MTU_DISCOVER, IPV6_TCLASS, IPV6_V6ONLY]
    {
        assert_eq!(set6(name, 0, 1), Err(Errno::Einval), "{name}");
        assert_eq!(set6(name, 0, 3), Err(Errno::Einval), "{name}");
    }
    assert_eq!(set::arg_class(IPV6_RTHDR), ArgClass::Header);
    assert_eq!(set::arg_class(IPV6_PKTINFO), ArgClass::PktInfo);
    assert_eq!(set::arg_class(IPV6_FLOWLABEL_MGR), ArgClass::FlowLabel);
    assert_eq!(set::arg_class(IPV6_XFRM_POLICY), ArgClass::Policy);
    assert_eq!(set::arg_class(MCAST_JOIN_GROUP), ArgClass::Delegated);
}

#[test]
fn three_options_carry_no_width_screen_at_all() {
    // These accept a zero-length operand and read it as zero.
    assert_eq!(set6(IPV6_AUTOFLOWLABEL, 0, 0),
        Ok(Action::Flag { bit: flag::AUTOFLOWLABEL, on: false }));
    assert_eq!(set6(IPV6_DONTFRAG, 0, 0),
        Ok(Action::Flag { bit: flag::DONTFRAG, on: false }));
    assert_eq!(set6(IPV6_RECVFRAGSIZE, 0, 0),
        Ok(Action::Flag { bit: flag::RECVFRAGSIZE, on: false }));
}

// ---- value windows ------------------------------------------------------

#[test]
fn hop_limits_take_the_route_sentinel_through_two_fifty_five() {
    assert_eq!(set6(IPV6_UNICAST_HOPS, -1, 4), Ok(Action::UnicastHops(-1)));
    assert_eq!(set6(IPV6_UNICAST_HOPS, 0, 4), Ok(Action::UnicastHops(0)));
    assert_eq!(set6(IPV6_UNICAST_HOPS, 255, 4), Ok(Action::UnicastHops(255)));
    assert_eq!(set6(IPV6_UNICAST_HOPS, -2, 4), Err(Errno::Einval));
    assert_eq!(set6(IPV6_UNICAST_HOPS, 256, 4), Err(Errno::Einval));
    // The multicast sentinel resolves to one at admission, not at read time.
    assert_eq!(set6(IPV6_MULTICAST_HOPS, -1, 4),
        Ok(Action::MulticastHops(IPV6_DEFAULT_MCASTHOPS)));
    assert_eq!(set::admit(IPV6_MULTICAST_HOPS, 5, 4, stream(), none()),
        Err(Errno::Enoprotoopt));
}

#[test]
fn multicast_loop_admits_exactly_zero_or_one() {
    assert_eq!(set6(IPV6_MULTICAST_LOOP, 1, 4), Ok(Action::MulticastLoop(true)));
    assert_eq!(set6(IPV6_MULTICAST_LOOP, 0, 4), Ok(Action::MulticastLoop(false)));
    assert_eq!(set6(IPV6_MULTICAST_LOOP, 2, 4), Err(Errno::Einval));
    assert_eq!(set6(IPV6_MULTICAST_LOOP, -1, 4), Err(Errno::Einval));
}

#[test]
fn the_fragmentation_size_is_zero_or_at_least_the_ipv6_minimum() {
    assert_eq!(set6(IPV6_MTU, 0, 4), Ok(Action::FragSize(0)));
    assert_eq!(set6(IPV6_MTU, IPV6_MIN_MTU, 4), Ok(Action::FragSize(IPV6_MIN_MTU)));
    assert_eq!(set6(IPV6_MTU, IPV6_MIN_MTU - 1, 4), Err(Errno::Einval));
}

#[test]
fn the_traffic_class_sentinel_resolves_to_zero() {
    assert_eq!(set6(IPV6_TCLASS, -1, 4), Ok(Action::Tclass(0)));
    assert_eq!(set6(IPV6_TCLASS, 255, 4), Ok(Action::Tclass(255)));
    assert_eq!(set6(IPV6_TCLASS, 256, 4), Err(Errno::Einval));
    assert_eq!(set6(IPV6_TCLASS, -2, 4), Err(Errno::Einval));
    // A stream socket keeps its congestion-notification bits.
    assert_eq!(set::tclass_value(0xff, 0b10, true), 0xfe);
    assert_eq!(set::tclass_value(0xff, 0b10, false), 0xff);
}

#[test]
fn v6only_is_refused_once_the_socket_holds_a_port() {
    assert_eq!(set6(IPV6_V6ONLY, 1, 4), Ok(Action::V6Only(true)));
    let bound = Ipv6Sock { inet_num: 53, ..dgram() };
    assert_eq!(set::admit(IPV6_V6ONLY, 1, 4, bound, none()), Err(Errno::Einval));
}

#[test]
fn mtu_discovery_spans_dont_through_omit() {
    for v in IPV6_PMTUDISC_DONT..=IPV6_PMTUDISC_OMIT {
        assert_eq!(set6(IPV6_MTU_DISCOVER, v, 4), Ok(Action::MtuDiscover(v)));
    }
    assert_eq!(set6(IPV6_MTU_DISCOVER, 6, 4), Err(Errno::Einval));
}

// ---- ladders ------------------------------------------------------------

#[test]
fn transparent_answers_the_capability_before_the_width() {
    assert_eq!(set::admit(IPV6_TRANSPARENT, 1, 0, dgram(), none()), Err(Errno::Eperm));
    assert_eq!(set::admit(IPV6_TRANSPARENT, 1, 4, dgram(), net_raw()),
        Ok(Action::Flag { bit: flag::TRANSPARENT, on: true }));
    assert_eq!(set::admit(IPV6_TRANSPARENT, 0, 0, dgram(), none()), Err(Errno::Einval));
}

#[test]
fn the_address_family_conversion_walks_its_whole_ladder() {
    // Only the IPv4 family is a legal target.
    assert_eq!(set6(IPV6_ADDRFORM, 10, 4), Err(Errno::Einval));
    assert_eq!(set6(IPV6_ADDRFORM, PF_INET, 2), Err(Errno::Einval));
    // A raw socket, and any protocol outside the two transports, has no
    // conversion.
    assert_eq!(set::admit(IPV6_ADDRFORM, PF_INET, 4, raw(41), none()),
        Err(Errno::Enoprotoopt));
    let icmp = Ipv6Sock { protocol: 58, ..dgram() };
    assert_eq!(set::admit(IPV6_ADDRFORM, PF_INET, 4, icmp, none()),
        Err(Errno::Enoprotoopt));
    // A send already in flight blocks the conversion.
    let busy = Ipv6Sock { send_pending: true, ..dgram() };
    assert_eq!(set::admit(IPV6_ADDRFORM, PF_INET, 4, busy, none()), Err(Errno::Ebusy));
    // Then connectivity, then the mapped-address requirement.
    assert_eq!(set6(IPV6_ADDRFORM, PF_INET, 4), Err(Errno::Enotconn));
    let connected = Ipv6Sock { established: true, ..dgram() };
    assert_eq!(set::admit(IPV6_ADDRFORM, PF_INET, 4, connected, none()),
        Err(Errno::Eaddrnotavail));
    let v6only = Ipv6Sock { established: true, daddr_v4mapped: true, v6only: true, ..dgram() };
    assert_eq!(set::admit(IPV6_ADDRFORM, PF_INET, 4, v6only, none()),
        Err(Errno::Eaddrnotavail));
    let ok = Ipv6Sock { established: true, daddr_v4mapped: true, ..dgram() };
    assert_eq!(set::admit(IPV6_ADDRFORM, PF_INET, 4, ok, none()), Ok(Action::AddrForm));
}

#[test]
fn the_router_alert_chain_is_the_raw_protocol_socket_only() {
    assert_eq!(set6(IPV6_ROUTER_ALERT, 1, 4), Err(Errno::Enoprotoopt));
    assert_eq!(set::admit(IPV6_ROUTER_ALERT, 1, 4, raw(58), none()), Err(Errno::Enoprotoopt));
    assert_eq!(set::admit(IPV6_ROUTER_ALERT, 1, 4, raw(IPPROTO_RAW), none()),
        Ok(Action::RouterAlert(true)));
    let joined = Ipv6Sock { on_ra_chain: true, ..raw(IPPROTO_RAW) };
    assert_eq!(set::admit(IPV6_ROUTER_ALERT, 1, 4, joined, none()), Err(Errno::Eaddrinuse));
    assert_eq!(set::admit(IPV6_ROUTER_ALERT, 0, 4, raw(IPPROTO_RAW), none()),
        Err(Errno::Enobufs));
}

#[test]
fn the_two_interface_options_differ_in_how_they_treat_a_device_binding() {
    // The multicast form tolerates a binding whose layer-3 master is the named
    // interface; the unicast form refuses any binding at all.
    let bound = Ipv6Sock { bound_if: 3, ..dgram() };
    assert_eq!(set::multicast_if_request(0, 4, stream()), Err(Errno::Enoprotoopt));
    assert_eq!(set::multicast_if_request(0, 2, dgram()), Err(Errno::Einval));
    assert_eq!(set::multicast_if_request(0, 4, dgram()), Ok(None));
    assert_eq!(set::multicast_if_request(7, 4, bound), Ok(Some(7)));
    assert_eq!(set::multicast_if_admit(7, None, 0), Err(Errno::Enodev));
    assert_eq!(set::multicast_if_admit(7, Some(0), 3), Err(Errno::Einval));
    assert_eq!(set::multicast_if_admit(7, Some(3), 3), Ok(Action::MulticastIf(7)));
    assert_eq!(set::multicast_if_admit(3, Some(0), 3), Ok(Action::MulticastIf(3)));

    assert_eq!(set::unicast_if_request(0, 2), Err(Errno::Einval));
    let network_order = 7u32.swap_bytes() as i32;
    assert_eq!(set::unicast_if_request(network_order, 4), Ok(Some(7)));
    assert_eq!(set::unicast_if_admit(7, false, 0), Err(Errno::Eaddrnotavail));
    assert_eq!(set::unicast_if_admit(7, true, 3), Err(Errno::Einval));
    assert_eq!(set::unicast_if_admit(7, true, 0), Ok(Action::UnicastIf(7)));
}

#[test]
fn a_transform_policy_answers_the_capability_then_the_absent_database() {
    assert_eq!(set::admit_policy(none()), Err(Errno::Eperm));
    assert_eq!(set::admit_policy(net_admin()), Err(Errno::Eopnotsupp));
}

#[test]
fn the_sticky_packet_info_refuses_an_interface_the_binding_contradicts() {
    assert_eq!(set::admit_pktinfo(0, 0, 0), Err(Errno::Einval));
    assert_eq!(set::admit_pktinfo(19, 0, 0), Err(Errno::Einval));
    assert_eq!(set::admit_pktinfo(20, 0, 0), Ok(()));
    assert_eq!(set::admit_pktinfo(20, 7, 3), Err(Errno::Einval));
    assert_eq!(set::admit_pktinfo(20, 3, 3), Ok(()));
    // An unset interface never contradicts a binding.
    assert_eq!(set::admit_pktinfo(20, 0, 3), Ok(()));
}

#[test]
fn source_address_preferences_admit_one_choice_per_group() {
    assert!(set::src_prefs(IPV6_PREFER_SRC_TMP).is_ok());
    assert!(set::src_prefs(IPV6_PREFER_SRC_PUBLIC).is_ok());
    assert!(set::src_prefs(IPV6_PREFER_SRC_PUBTMP_DEFAULT).is_ok());
    assert_eq!(set::src_prefs(IPV6_PREFER_SRC_TMP | IPV6_PREFER_SRC_PUBLIC),
        Err(Errno::Einval));
    assert_eq!(set::src_prefs(IPV6_PREFER_SRC_HOME | IPV6_PREFER_SRC_COA),
        Err(Errno::Einval));
    assert_eq!(set::src_prefs(IPV6_PREFER_SRC_CGA | IPV6_PREFER_SRC_NONCGA),
        Err(Errno::Einval));
    // Only the temporary, public and care-of bits are retained, and EVERY
    // write clears all three before setting what the caller named — so a
    // second write naming one group discards the earlier one.
    let with_coa = set::apply_src_prefs(0, IPV6_PREFER_SRC_COA).unwrap();
    assert_eq!(with_coa, IPV6_PREFER_SRC_COA);
    let then_tmp = set::apply_src_prefs(with_coa, IPV6_PREFER_SRC_TMP).unwrap();
    assert_eq!(then_tmp, IPV6_PREFER_SRC_TMP);
    assert_eq!(set::apply_src_prefs(then_tmp, IPV6_PREFER_SRC_PUBLIC).unwrap(),
        IPV6_PREFER_SRC_PUBLIC);
    assert_eq!(set::apply_src_prefs(then_tmp, IPV6_PREFER_SRC_HOME).unwrap(), 0);
    // A combined write does keep both groups.
    assert_eq!(set::apply_src_prefs(0, IPV6_PREFER_SRC_TMP | IPV6_PREFER_SRC_COA).unwrap(),
        IPV6_PREFER_SRC_TMP | IPV6_PREFER_SRC_COA);
}

// ---- sticky extension headers -------------------------------------------

#[test]
fn hop_by_hop_and_destination_options_are_privileged() {
    for name in [IPV6_HOPOPTS, IPV6_DSTOPTS, IPV6_RTHDRDSTOPTS] {
        assert_eq!(hdr::admit(name, &[0u8; 8], none()), Err(Errno::Eperm), "{name}");
        assert!(hdr::admit(name, &[0, 0, 1, 0, 0, 0, 0, 0], net_raw()).is_ok(), "{name}");
    }
    // The routing header is not.
    assert!(hdr::admit(IPV6_RTHDR, &[], none()).is_ok());
}

#[test]
fn an_empty_area_removes_the_stored_header() {
    assert_eq!(hdr::admit(IPV6_HOPOPTS, &[], net_raw()), Ok(None));
    let opts = Ipv6Opts::default();
    opts.set_header(Sticky::HopOpts, Some(Vec::from([0u8; 8])));
    assert!(opts.header(Sticky::HopOpts).is_some());
    opts.set_header(Sticky::HopOpts, None);
    assert!(opts.header(Sticky::HopOpts).is_none());
}

#[test]
fn a_header_area_must_be_eight_byte_aligned_and_bounded() {
    assert_eq!(hdr::admit(IPV6_HOPOPTS, &[0u8; 7], net_raw()), Err(Errno::Einval));
    assert_eq!(hdr::admit(IPV6_HOPOPTS, &[0u8; 12], net_raw()), Err(Errno::Einval));
    assert_eq!(hdr::admit(IPV6_HOPOPTS, &alloc::vec![0u8; 8 * 256], net_raw()),
        Err(Errno::Einval));
    // A declared length past the bytes supplied is refused.
    assert_eq!(hdr::admit(IPV6_HOPOPTS, &[0, 3, 0, 0, 0, 0, 0, 0], net_raw()),
        Err(Errno::Einval));
}

#[test]
fn a_sticky_routing_header_is_the_segment_routing_form_only() {
    // Type zero, the deprecated source route, is refused.
    let type0 = [0u8, 2, IPV6_SRCRT_TYPE_0, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(hdr::admit(IPV6_RTHDR, &type0, net_raw()), Err(Errno::Einval));
    // A single-segment routing header in the segment-routing form: header
    // length four (five eight-byte units minus one), one segment.
    let mut srh = alloc::vec![0u8; 24];
    srh[1] = 2;
    srh[2] = IPV6_SRCRT_TYPE_4;
    srh[3] = 0;
    srh[4] = 0;
    assert!(hdr::validate_srh(&srh));
    assert!(hdr::admit(IPV6_RTHDR, &srh, none()).is_ok());
    // Segments left past the last entry is malformed.
    srh[3] = 5;
    assert!(!hdr::validate_srh(&srh));
}

#[test]
fn the_header_chain_is_published_in_wire_order() {
    let opts = Ipv6Opts::default();
    let area = |tag: u8| Some(alloc::vec![tag, 0, 0, 0, 0, 0, 0, 0]);
    opts.set_header(Sticky::DstOpts, area(4));
    opts.set_header(Sticky::HopOpts, area(1));
    opts.set_header(Sticky::Rthdr, area(3));
    opts.set_header(Sticky::RthdrDstOpts, area(2));
    let chain: Vec<u8> = opts.header_chain().into_iter().map(|(_, b)| b[0]).collect();
    assert_eq!(chain, alloc::vec![1, 2, 3, 4]);
}

// ---- the flow-label table -----------------------------------------------

#[test]
fn a_lease_shorter_than_the_floor_is_raised_and_a_long_one_is_privileged() {
    assert_eq!(flowlabel::check_linger(0, none()),
        Ok(flowlabel::FL_MIN_LINGER as u64 * 1_000_000_000));
    assert!(flowlabel::check_linger(flowlabel::FL_MAX_LINGER, none()).is_ok());
    assert_eq!(flowlabel::check_linger(flowlabel::FL_MAX_LINGER + 1, none()),
        Err(Errno::Eperm));
    assert!(flowlabel::check_linger(flowlabel::FL_MAX_LINGER + 1, net_admin()).is_ok());
}

#[test]
fn a_lease_needs_a_real_destination_and_a_known_sharing_mode() {
    let mut req = FlowReq { dst: [0u8; 16], share: IPV6_FL_S_ANY, ..Default::default() };
    assert_eq!(flowlabel::admit_create(&req, none()), Err(Errno::Einval));
    // A mapped IPv4 destination is not an IPv6 flow.
    req.dst = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
    assert_eq!(flowlabel::admit_create(&req, none()), Err(Errno::Einval));
    req.dst = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert!(flowlabel::admit_create(&req, none()).is_ok());
    req.share = 9;
    assert_eq!(flowlabel::admit_create(&req, none()), Err(Errno::Einval));
}

#[test]
fn an_exclusive_lease_is_never_shared_and_the_owner_must_match() {
    let owner = Owner { pid: 5, uid: 100 };
    let base = Lease { label: 7, dst: [0u8; 16], share: IPV6_FL_S_EXCL, owner,
        linger_ns: 0, expires_ns: 0, users: 1 };
    assert!(!flowlabel::shareable(&base, IPV6_FL_S_EXCL, owner));
    let any = Lease { share: IPV6_FL_S_ANY, ..base };
    assert!(flowlabel::shareable(&any, IPV6_FL_S_ANY, owner));
    // A different mode never matches.
    assert!(!flowlabel::shareable(&any, IPV6_FL_S_PROCESS, owner));
    let per_process = Lease { share: IPV6_FL_S_PROCESS, ..base };
    assert!(flowlabel::shareable(&per_process, IPV6_FL_S_PROCESS, owner));
    assert!(!flowlabel::shareable(&per_process, IPV6_FL_S_PROCESS,
        Owner { pid: 6, uid: 100 }));
    let per_user = Lease { share: IPV6_FL_S_USER, ..base };
    assert!(flowlabel::shareable(&per_user, IPV6_FL_S_USER, Owner { pid: 6, uid: 100 }));
    assert!(!flowlabel::shareable(&per_user, IPV6_FL_S_USER, Owner { pid: 6, uid: 101 }));
}

#[test]
fn the_table_interns_shares_and_releases_a_lease() {
    let table = flowlabel::FlowLabels::new();
    let lease = Lease { label: 0x12345, dst: [1u8; 16], share: IPV6_FL_S_ANY,
        owner: Owner::default(), linger_ns: 10, expires_ns: 100, users: 1 };
    assert_eq!(table.intern(1, lease, || 0).unwrap().label, 0x12345);
    // A second holder of the same label shares the entry.
    assert_eq!(table.intern(1, lease, || 0).unwrap().users, 2);
    assert_eq!(table.count(1), 1);
    // Namespaces do not share labels.
    assert_eq!(table.count(2), 0);
    assert!(table.release(1, 0x12345));
    assert_eq!(table.count(1), 1);
    assert!(table.release(1, 0x12345));
    assert_eq!(table.count(1), 0);
    assert!(!table.release(1, 0x12345));
}

#[test]
fn an_unnamed_label_is_allocated_from_the_label_space() {
    let table = flowlabel::FlowLabels::new();
    let lease = Lease { label: 0, dst: [1u8; 16], share: IPV6_FL_S_ANY,
        owner: Owner::default(), linger_ns: 10, expires_ns: 100, users: 1 };
    let got = table.intern(1, lease, || 0xfff_1234).unwrap();
    // The picked value is masked into the twenty-bit label field.
    assert_eq!(got.label, 0xfff_1234 & IPV6_FLOWINFO_FLOWLABEL);
    assert!(got.label != 0);
}

#[test]
fn renewing_a_lease_only_ever_extends_it() {
    let table = flowlabel::FlowLabels::new();
    let lease = Lease { label: 9, dst: [1u8; 16], share: IPV6_FL_S_ANY,
        owner: Owner::default(), linger_ns: 50, expires_ns: 1_000, users: 1 };
    table.intern(1, lease, || 0).unwrap();
    assert_eq!(table.renew(1, 8, 10, 10, 0), Err(Errno::Esrch));
    table.renew(1, 9, 10, 10, 0).unwrap();
    let after = table.lookup(1, 9).unwrap();
    assert_eq!(after.linger_ns, 50);
    assert_eq!(after.expires_ns, 1_000);
    table.renew(1, 9, 100, 2_000, 0).unwrap();
    let extended = table.lookup(1, 9).unwrap();
    assert_eq!(extended.linger_ns, 100);
    assert_eq!(extended.expires_ns, 2_000);
}

#[test]
fn an_expired_lease_is_retired() {
    let table = flowlabel::FlowLabels::new();
    let lease = Lease { label: 9, dst: [1u8; 16], share: IPV6_FL_S_ANY,
        owner: Owner::default(), linger_ns: 1, expires_ns: 100, users: 1 };
    table.intern(1, lease, || 0).unwrap();
    table.expire(50);
    assert!(table.lookup(1, 9).is_some());
    table.expire(100);
    assert!(table.lookup(1, 9).is_none());
}

#[test]
fn a_flow_label_request_round_trips_through_the_wire_form() {
    let req = FlowReq { dst: [7u8; 16], action: IPV6_FL_A_GET, share: IPV6_FL_S_USER,
        flags: IPV6_FL_F_CREATE, expires: 60, linger: 30, label: 0x2_3456 };
    assert_eq!(FlowReq::parse(&req.encode()), req);
}

#[test]
fn the_socket_lease_list_tracks_what_it_holds() {
    let opts = Ipv6Opts::default();
    assert!(!opts.holds_label(9));
    opts.hold_label(9);
    opts.hold_label(9);
    assert!(opts.holds_label(9));
    assert!(opts.release_label(9));
    assert!(!opts.release_label(9));
    opts.hold_label(1);
    opts.hold_label(2);
    assert_eq!(opts.take_labels(), alloc::vec![1, 2]);
    assert!(opts.take_labels().is_empty());
}

// ---- reads ---------------------------------------------------------------

fn state() -> Ipv6GetState {
    Ipv6GetState { hop_limit: -1, mcast_hops: 1, route_hoplimit: -1,
        default_hoplimit: IPV6_DEFAULT_HOPLIMIT, pmtudisc: IPV6_PMTUDISC_WANT,
        use_min_mtu: -1, ..Default::default() }
}

#[test]
fn an_unset_hop_limit_resolves_through_the_route_then_the_default() {
    assert_eq!(get::read(IPV6_UNICAST_HOPS, dgram(), &state()),
        Ok(Value::Int(IPV6_DEFAULT_HOPLIMIT)));
    let routed = Ipv6GetState { route_hoplimit: 32, ..state() };
    assert_eq!(get::read(IPV6_UNICAST_HOPS, dgram(), &routed), Ok(Value::Int(32)));
    let named = Ipv6GetState { hop_limit: 5, route_hoplimit: 32, ..state() };
    assert_eq!(get::read(IPV6_UNICAST_HOPS, dgram(), &named), Ok(Value::Int(5)));
}

#[test]
fn the_path_mtu_reads_need_a_route() {
    assert_eq!(get::read(IPV6_MTU, dgram(), &state()), Err(Errno::Enotconn));
    assert_eq!(get::read(IPV6_PATHMTU, dgram(), &state()), Err(Errno::Enotconn));
    let routed = Ipv6GetState { mtu: 1400, ..state() };
    assert_eq!(get::read(IPV6_MTU, dgram(), &routed), Ok(Value::Int(1400)));
    let Ok(Value::Exact(bytes)) = get::read(IPV6_PATHMTU, dgram(), &routed) else {
        panic!("the path MTU read publishes a whole structure");
    };
    assert_eq!(bytes.len(), IP6_MTUINFO_SIZE);
    assert_eq!(&bytes[IP6_MTUINFO_SIZE - 4..], &1400u32.to_ne_bytes());
    // A buffer that cannot hold the structure is refused rather than truncated.
    assert_eq!(get::exact_len(IP6_MTUINFO_SIZE, 8), Err(Errno::Einval));
    assert_eq!(get::exact_len(IP6_MTUINFO_SIZE, 64), Ok(IP6_MTUINFO_SIZE));
}

#[test]
fn the_address_family_read_walks_its_own_ladder() {
    assert_eq!(get::read(IPV6_ADDRFORM, raw(41), &state()), Err(Errno::Enoprotoopt));
    assert_eq!(get::read(IPV6_ADDRFORM, dgram(), &state()), Err(Errno::Enotconn));
    let connected = Ipv6Sock { established: true, ..dgram() };
    let s = Ipv6GetState { family: 10, ..state() };
    assert_eq!(get::read(IPV6_ADDRFORM, connected, &s), Ok(Value::Int(10)));
}

#[test]
fn source_preferences_read_back_as_a_complete_set() {
    assert_eq!(get::published_prefs(0),
        IPV6_PREFER_SRC_PUBTMP_DEFAULT | IPV6_PREFER_SRC_HOME);
    assert_eq!(get::published_prefs(IPV6_PREFER_SRC_TMP),
        IPV6_PREFER_SRC_TMP | IPV6_PREFER_SRC_HOME);
    assert_eq!(get::published_prefs(IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_COA),
        IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_COA);
}

#[test]
fn automatic_flow_labels_fall_back_to_the_namespace_policy() {
    let s = Ipv6GetState { default_autoflowlabel: true, ..state() };
    assert_eq!(get::read(IPV6_AUTOFLOWLABEL, dgram(), &s), Ok(Value::Int(1)));
    let named_off = Ipv6GetState { flags: flag::AUTOFLOWLABEL_SET, ..s.clone() };
    assert_eq!(get::read(IPV6_AUTOFLOWLABEL, dgram(), &named_off), Ok(Value::Int(0)));
    let named_on = Ipv6GetState {
        flags: flag::AUTOFLOWLABEL_SET | flag::AUTOFLOWLABEL, ..state() };
    assert_eq!(get::read(IPV6_AUTOFLOWLABEL, dgram(), &named_on), Ok(Value::Int(1)));
}

#[test]
fn the_two_receive_personalities_are_kept_apart() {
    // The RFC 3542 and RFC 2292 bits are distinct: enabling one leaves the
    // other reading zero.
    let modern = Ipv6GetState { flags: RECVPKTINFO, ..state() };
    assert_eq!(get::read(IPV6_RECVPKTINFO, dgram(), &modern), Ok(Value::Int(1)));
    assert_eq!(get::read(IPV6_2292PKTINFO, dgram(), &modern), Ok(Value::Int(0)));
    let legacy = Ipv6GetState { flags: flag::RXOINFO, ..state() };
    assert_eq!(get::read(IPV6_RECVPKTINFO, dgram(), &legacy), Ok(Value::Int(0)));
    assert_eq!(get::read(IPV6_2292PKTINFO, dgram(), &legacy), Ok(Value::Int(1)));
    for (modern_name, modern_bit, legacy_name, legacy_bit) in [
        (IPV6_RECVHOPLIMIT, RECVHOPLIMIT, IPV6_2292HOPLIMIT, flag::RXOHLIM),
        (IPV6_RECVRTHDR, flag::RXSRCRT, IPV6_2292RTHDR, flag::RXOSRCRT),
        (IPV6_RECVHOPOPTS, flag::RXHOPOPTS, IPV6_2292HOPOPTS, flag::RXOHOPOPTS),
        (IPV6_RECVDSTOPTS, flag::RXDSTOPTS, IPV6_2292DSTOPTS, flag::RXODSTOPTS)]
    {
        let s = Ipv6GetState { flags: modern_bit, ..state() };
        assert_eq!(get::read(modern_name, dgram(), &s), Ok(Value::Int(1)));
        assert_eq!(get::read(legacy_name, dgram(), &s), Ok(Value::Int(0)));
        let s2 = Ipv6GetState { flags: legacy_bit, ..state() };
        assert_eq!(get::read(legacy_name, dgram(), &s2), Ok(Value::Int(1)));
    }
    let tclass = Ipv6GetState { flags: RECVTCLASS, ..state() };
    assert_eq!(get::read(IPV6_RECVTCLASS, dgram(), &tclass), Ok(Value::Int(1)));
}

#[test]
fn a_sticky_header_reads_back_as_stored() {
    let mut s = state();
    s.headers[Sticky::Rthdr as usize] = Some(alloc::vec![9u8; 8]);
    assert_eq!(get::read(IPV6_RTHDR, dgram(), &s), Ok(Value::Bytes(alloc::vec![9u8; 8])));
    assert_eq!(get::read(IPV6_HOPOPTS, dgram(), &s), Ok(Value::Bytes(Vec::new())));
}

#[test]
fn this_level_never_narrows_a_read_to_one_byte() {
    assert_eq!(get::int_len(1), 1);
    assert_eq!(get::int_len(4), 4);
    assert_eq!(get::int_len(9), 4);
    // A negative length is not screened here, unlike the IPv4 level.
    assert_eq!(get::int_len(-1), 4);
}

#[test]
fn the_ancillary_snapshot_is_a_stream_socket_read() {
    assert_eq!(get::read(IPV6_2292PKTOPTIONS, dgram(), &state()), Err(Errno::Enoprotoopt));
    assert_eq!(get::read(IPV6_2292PKTOPTIONS, stream(), &state()),
        Ok(Value::Bytes(Vec::new())));
}

#[test]
fn an_unknown_read_is_refused() {
    assert_eq!(get::read(999, dgram(), &state()), Err(Errno::Enoprotoopt));
    assert_eq!(get::read(IPV6_HOPLIMIT, dgram(), &state()), Err(Errno::Enoprotoopt));
}
