// `IPPROTO_IPV6` option coverage: ladders.

use syscall::errno::Errno;
use super::super::set::{self, Action, Ipv6Sock};
use super::super::state::flag;
use super::super::uapi::*;
use super::*;

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
