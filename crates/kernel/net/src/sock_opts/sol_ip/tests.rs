// Hosted coverage for the `IPPROTO_IP` option table. These encode the verified
// Linux behaviour: value windows, capability ladders, errno ORDERING, and the
// copy shapes each read publishes.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::get::{self, IpGetState, ScalarOut, Value};
use super::options;
use super::set::{self, Action, ArgClass, IpSock};
use super::state::{IpOpts, effective_port_range, flag};
use super::uapi::*;
use crate::sock_opts::sol_socket::OptCaps;

fn dgram() -> IpSock { IpSock { dgram: true, ..Default::default() } }
fn stream() -> IpSock { IpSock { stream: true, ..Default::default() } }
fn raw(proto: u8) -> IpSock {
    IpSock { raw: true, inet_num: proto as u16, ..Default::default() }
}
fn none() -> OptCaps { OptCaps::default() }
fn net_raw() -> OptCaps { OptCaps { net_raw: true, net_admin: false } }
fn net_admin() -> OptCaps { OptCaps { net_raw: false, net_admin: true } }

fn set4(name: u64, val: i32, len: u32) -> Result<Action, Errno> {
    set::admit(name, val, len, dgram(), none())
}

// ---- operand shape ------------------------------------------------------

#[test]
fn every_scalar_option_reads_a_byte_or_an_int() {
    for name in [IP_TOS, IP_TTL, IP_PKTINFO, IP_RECVTTL, IP_RECVTOS, IP_RETOPTS,
        IP_MTU_DISCOVER, IP_RECVERR, IP_FREEBIND, IP_MINTTL, IP_TRANSPARENT]
    {
        assert_eq!(set::arg_class(name), ArgClass::ByteOrInt, "{name}");
    }
    assert_eq!(set::arg_class(IP_OPTIONS), ArgClass::Options);
    assert_eq!(set::arg_class(IP_IPSEC_POLICY), ArgClass::Policy);
    assert_eq!(set::arg_class(IP_XFRM_POLICY), ArgClass::Policy);
    assert_eq!(set::arg_class(IP_ADD_MEMBERSHIP), ArgClass::Delegated);
}

#[test]
fn a_zero_length_write_means_zero_not_an_error() {
    // The options that carry no minimum width accept an empty operand and read
    // it as zero — only the ones with an explicit floor refuse it.
    assert_eq!(set4(IP_PKTINFO, 0, 0), Ok(Action::PktInfo(false)));
    assert_eq!(set4(IP_RECVTOS, 0, 0), Ok(Action::Flag { bit: flag::RECVTOS, on: false }));
    assert_eq!(set4(IP_TOS, 0, 0), Ok(Action::Tos(0)));
    assert_eq!(set4(IP_MTU_DISCOVER, 0, 0), Ok(Action::MtuDiscover(IP_PMTUDISC_DONT)));
    assert_eq!(set4(IP_TTL, 0, 0), Err(Errno::Einval));
    assert_eq!(set4(IP_MINTTL, 0, 0), Err(Errno::Einval));
    assert_eq!(set4(IP_FREEBIND, 0, 0), Err(Errno::Einval));
    assert_eq!(set4(IP_MULTICAST_ALL, 0, 0), Err(Errno::Einval));
}

// ---- value windows ------------------------------------------------------

#[test]
fn ttl_takes_the_route_sentinel_or_one_through_two_fifty_five() {
    assert_eq!(set4(IP_TTL, -1, 4), Ok(Action::Ttl(-1)));
    assert_eq!(set4(IP_TTL, 1, 4), Ok(Action::Ttl(1)));
    assert_eq!(set4(IP_TTL, 255, 4), Ok(Action::Ttl(255)));
    assert_eq!(set4(IP_TTL, 0, 4), Err(Errno::Einval));
    assert_eq!(set4(IP_TTL, 256, 4), Err(Errno::Einval));
    assert_eq!(set4(IP_TTL, -2, 4), Err(Errno::Einval));
}

#[test]
fn minttl_takes_zero_through_two_fifty_five_where_ttl_refuses_zero() {
    assert_eq!(set4(IP_MINTTL, 0, 4), Ok(Action::MinTtl(0)));
    assert_eq!(set4(IP_MINTTL, 255, 4), Ok(Action::MinTtl(255)));
    assert_eq!(set4(IP_MINTTL, -1, 4), Err(Errno::Einval));
    assert_eq!(set4(IP_MINTTL, 256, 4), Err(Errno::Einval));
}

#[test]
fn mtu_discover_spans_dont_through_omit() {
    for v in IP_PMTUDISC_DONT..=IP_PMTUDISC_OMIT {
        assert_eq!(set4(IP_MTU_DISCOVER, v, 4), Ok(Action::MtuDiscover(v)));
    }
    assert_eq!(set4(IP_MTU_DISCOVER, -1, 4), Err(Errno::Einval));
    assert_eq!(set4(IP_MTU_DISCOVER, 6, 4), Err(Errno::Einval));
}

#[test]
fn multicast_all_and_recverr_rfc4884_are_strict_booleans() {
    assert_eq!(set4(IP_MULTICAST_ALL, 1, 4), Ok(Action::Flag { bit: flag::MC_ALL_OFF, on: false }));
    assert_eq!(set4(IP_MULTICAST_ALL, 0, 4), Ok(Action::Flag { bit: flag::MC_ALL_OFF, on: true }));
    assert_eq!(set4(IP_MULTICAST_ALL, 2, 4), Err(Errno::Einval));
    assert_eq!(set4(IP_RECVERR_RFC4884, 2, 4), Err(Errno::Einval));
    assert_eq!(set4(IP_RECVERR_RFC4884, -1, 4), Err(Errno::Einval));
}

#[test]
fn tos_keeps_the_congestion_bits_on_a_stream_socket_only() {
    // A datagram socket takes the whole byte; a stream socket keeps the two
    // congestion-notification bits it negotiated.
    assert_eq!(set::tos_value(0xff, 0b10, false), 0xff);
    assert_eq!(set::tos_value(0xff, 0b10, true), 0xfe);
    assert_eq!(set::tos_value(0x00, 0b11, true), 0b11);
    assert_eq!(set4(IP_TOS, 0x1ff, 4), Ok(Action::Tos(0xff)));
}

#[test]
fn local_port_range_needs_exactly_four_bytes_and_an_ordered_pair() {
    let packed = |lo: u16, hi: u16| ((hi as u32) << 16) | lo as u32;
    assert_eq!(set4(IP_LOCAL_PORT_RANGE, packed(100, 200) as i32, 4),
        Ok(Action::LocalPortRange(packed(100, 200))));
    // A half-open request leaves the namespace bound in place on that side.
    assert_eq!(set4(IP_LOCAL_PORT_RANGE, packed(0, 200) as i32, 4),
        Ok(Action::LocalPortRange(packed(0, 200))));
    assert_eq!(set4(IP_LOCAL_PORT_RANGE, packed(300, 200) as i32, 4), Err(Errno::Einval));
    assert_eq!(set4(IP_LOCAL_PORT_RANGE, packed(100, 200) as i32, 2), Err(Errno::Einval));
    assert_eq!(set4(IP_LOCAL_PORT_RANGE, packed(100, 200) as i32, 8), Err(Errno::Einval));
}

#[test]
fn the_effective_port_range_falls_back_per_side() {
    let ns = (32768u16, 60999u16);
    assert_eq!(effective_port_range(0, ns), ns);
    assert_eq!(effective_port_range((200 << 16) | 100, ns), (100, 200));
    assert_eq!(effective_port_range(200 << 16, ns), (ns.0, 200));
    assert_eq!(effective_port_range(100, ns), (100, ns.1));
}

// ---- capability and socket-type ladders ---------------------------------

#[test]
fn transparent_answers_the_capability_before_the_width() {
    // Turning it ON without either network capability is EPERM even when the
    // operand is also too short — the ladder runs first.
    assert_eq!(set::admit(IP_TRANSPARENT, 1, 0, dgram(), none()), Err(Errno::Eperm));
    assert_eq!(set::admit(IP_TRANSPARENT, 1, 4, dgram(), net_raw()),
        Ok(Action::Flag { bit: flag::TRANSPARENT, on: true }));
    assert_eq!(set::admit(IP_TRANSPARENT, 1, 4, dgram(), net_admin()),
        Ok(Action::Flag { bit: flag::TRANSPARENT, on: true }));
    // Turning it OFF is unprivileged, so the width screen is what answers.
    assert_eq!(set::admit(IP_TRANSPARENT, 0, 0, dgram(), none()), Err(Errno::Einval));
    assert_eq!(set::admit(IP_TRANSPARENT, 0, 1, dgram(), none()),
        Ok(Action::Flag { bit: flag::TRANSPARENT, on: false }));
}

#[test]
fn nodefrag_is_a_raw_socket_option() {
    assert_eq!(set::admit(IP_NODEFRAG, 1, 4, dgram(), none()), Err(Errno::Enoprotoopt));
    assert_eq!(set::admit(IP_NODEFRAG, 1, 4, stream(), none()), Err(Errno::Enoprotoopt));
    assert_eq!(set::admit(IP_NODEFRAG, 1, 4, raw(1), none()),
        Ok(Action::Flag { bit: flag::NODEFRAG, on: true }));
}

#[test]
fn recvfragsize_refuses_a_stream_socket() {
    assert_eq!(set::admit(IP_RECVFRAGSIZE, 1, 4, stream(), none()), Err(Errno::Einval));
    assert!(set::admit(IP_RECVFRAGSIZE, 1, 4, dgram(), none()).is_ok());
    assert!(set::admit(IP_RECVFRAGSIZE, 1, 4, raw(1), none()).is_ok());
}

#[test]
fn router_alert_is_raw_only_and_refuses_the_raw_protocol_itself() {
    assert_eq!(set::admit(IP_ROUTER_ALERT, 1, 4, dgram(), none()), Err(Errno::Einval));
    assert_eq!(set::admit(IP_ROUTER_ALERT, 1, 4, raw(IPPROTO_RAW), none()),
        Err(Errno::Einval));
    assert_eq!(set::admit(IP_ROUTER_ALERT, 1, 4, raw(1), none()),
        Ok(Action::RouterAlert(true)));
    // Joining twice, or leaving a chain never joined, each has its own errno.
    let joined = IpSock { on_ra_chain: true, ..raw(1) };
    assert_eq!(set::admit(IP_ROUTER_ALERT, 1, 4, joined, none()), Err(Errno::Eaddrinuse));
    assert_eq!(set::admit(IP_ROUTER_ALERT, 0, 4, raw(1), none()), Err(Errno::Enobufs));
    assert_eq!(set::admit(IP_ROUTER_ALERT, 0, 4, joined, none()),
        Ok(Action::RouterAlert(false)));
}

#[test]
fn a_transform_policy_answers_the_capability_then_the_absent_database() {
    assert_eq!(set::admit_policy(none()), Err(Errno::Eperm));
    assert_eq!(set::admit_policy(net_raw()), Err(Errno::Eperm));
    assert_eq!(set::admit_policy(net_admin()), Err(Errno::Eopnotsupp));
}

#[test]
fn unicast_if_resolves_a_network_order_index_then_the_device() {
    assert_eq!(set::unicast_if_request(0, 2), Err(Errno::Einval));
    assert_eq!(set::unicast_if_request(0, 8), Err(Errno::Einval));
    assert_eq!(set::unicast_if_request(0, 4), Ok(None));
    let network_order = 7u32.swap_bytes() as i32;
    assert_eq!(set::unicast_if_request(network_order, 4), Ok(Some(7)));
    assert_eq!(set::unicast_if_admit(7, None, 0), Err(Errno::Eaddrnotavail));
    assert_eq!(set::unicast_if_admit(7, Some(0), 0), Ok(Action::UnicastIf(7)));
    // A device binding wins unless the named interface's layer-3 master is it.
    assert_eq!(set::unicast_if_admit(7, Some(0), 3), Err(Errno::Einval));
    assert_eq!(set::unicast_if_admit(7, Some(3), 3), Ok(Action::UnicastIf(7)));
}

#[test]
fn read_only_options_refuse_a_write() {
    for name in [IP_MTU, IP_PROTOCOL, IP_PKTOPTIONS] {
        assert_eq!(set4(name, 0, 4), Err(Errno::Enoprotoopt), "{name}");
    }
    assert_eq!(set4(999, 0, 4), Err(Errno::Enoprotoopt));
}

// ---- the header option area --------------------------------------------

#[test]
fn an_option_area_wider_than_a_header_is_refused() {
    assert_eq!(set::admit_options(&[0u8; 41], net_raw(), 0), Err(Errno::Einval));
    assert!(set::admit_options(&[0u8; 40], net_raw(), 0).is_ok());
}

#[test]
fn an_empty_option_area_clears_the_socket() {
    let c = options::build(&[], false).unwrap();
    assert!(c.is_empty());
    let opts = IpOpts::default();
    opts.set_options(c);
    assert_eq!(opts.options_len(), 0);
    assert!(opts.options_undone().is_empty());
}

#[test]
fn a_short_area_is_padded_to_a_four_byte_multiple() {
    // A single no-op pads out with end-of-list markers.
    let c = options::build(&[IPOPT_NOOP], false).unwrap();
    assert_eq!(c.data, alloc::vec![IPOPT_NOOP, IPOPT_END, IPOPT_END, IPOPT_END]);
}

#[test]
fn a_truncated_option_is_refused() {
    // A kind byte with no length byte, and a length that runs past the area.
    assert_eq!(options::build(&[IPOPT_RR], false), Err(Errno::Einval));
    assert_eq!(options::build(&[IPOPT_RR, 40, 4, 0], false), Err(Errno::Einval));
    assert_eq!(options::build(&[IPOPT_RR, 1, 0, 0], false), Err(Errno::Einval));
}

#[test]
fn a_source_route_needs_the_raw_capability_and_a_pointer_of_four() {
    // Loose source route: kind, length, pointer, then one hop.
    let lsrr = [IPOPT_LSRR, 7, 4, 10, 0, 0, 1, IPOPT_END];
    assert_eq!(options::build(&lsrr, false), Err(Errno::Eperm));
    let c = options::build(&lsrr, true).unwrap();
    assert_eq!(c.srr, Some(0));
    assert!(!c.is_strictroute);
    // The first hop is lifted out of the list and carried separately.
    assert_eq!(c.faddr, [10, 0, 0, 1]);
    // A pointer other than four, or a length that is not 3 + 4n, is malformed
    // and answers that BEFORE the capability ladder.
    assert_eq!(options::build(&[IPOPT_LSRR, 7, 8, 10, 0, 0, 1, IPOPT_END], false),
        Err(Errno::Einval));
    assert_eq!(options::build(&[IPOPT_LSRR, 6, 4, 10, 0, 0, IPOPT_END, IPOPT_END], false),
        Err(Errno::Einval));
}

#[test]
fn a_strict_source_route_is_flagged_and_round_trips() {
    let ssrr = [IPOPT_SSRR, 11, 4, 10, 0, 0, 1, 10, 0, 0, 2, IPOPT_END];
    let c = options::build(&ssrr, true).unwrap();
    assert!(c.is_strictroute);
    assert_eq!(c.faddr, [10, 0, 0, 1]);
    // The compiled area shifts the remaining hops down; the inverse pass puts
    // the first hop back so a read reproduces the write.
    assert_eq!(&options::undo(&c)[..11], &ssrr[..11]);
}

#[test]
fn two_source_routes_or_two_record_routes_are_refused() {
    let two_srr = [IPOPT_LSRR, 7, 4, 10, 0, 0, 1, IPOPT_LSRR, 7, 4, 10, 0, 0, 2, 0, 0];
    assert_eq!(options::build(&two_srr, true), Err(Errno::Einval));
    let two_rr = [IPOPT_RR, 7, 4, 0, 0, 0, 0, IPOPT_RR, 7, 4, 0, 0, 0, 0, 0, 0];
    assert_eq!(options::build(&two_rr, true), Err(Errno::Einval));
}

#[test]
fn a_record_route_advances_its_pointer_and_the_inverse_pass_retracts_it() {
    let rr = [IPOPT_RR, 7, 4, 0, 0, 0, 0, IPOPT_END];
    let c = options::build(&rr, false).unwrap();
    assert_eq!(c.rr, Some(0));
    assert!(c.rr_needaddr);
    assert_eq!(c.data[2], 8);
    assert_eq!(options::undo(&c)[2], 4);
}

#[test]
fn a_timestamp_option_advances_by_its_form() {
    // Timestamps only.
    let ts = [IPOPT_TIMESTAMP, 8, 5, IPOPT_TS_TSONLY, 0, 0, 0, 0];
    let c = options::build(&ts, false).unwrap();
    assert!(c.ts_needtime && !c.ts_needaddr);
    assert_eq!(c.data[2], 9);
    // Address and timestamp pairs consume eight bytes per hop.
    let ts2 = [IPOPT_TIMESTAMP, 12, 5, IPOPT_TS_TSANDADDR, 0, 0, 0, 0, 0, 0, 0, 0];
    let c2 = options::build(&ts2, false).unwrap();
    assert!(c2.ts_needtime && c2.ts_needaddr);
    assert_eq!(c2.data[2], 13);
    // A pointer below five, or a length below four, is malformed.
    assert_eq!(options::build(&[IPOPT_TIMESTAMP, 8, 4, 0, 0, 0, 0, 0], false),
        Err(Errno::Einval));
    assert_eq!(options::build(&[IPOPT_TIMESTAMP, 3, 5, 0], false), Err(Errno::Einval));
}

#[test]
fn an_unknown_timestamp_form_needs_the_raw_capability() {
    let ts = [IPOPT_TIMESTAMP, 8, 5, 7, 0, 0, 0, 0];
    assert_eq!(options::build(&ts, false), Err(Errno::Einval));
    assert!(options::build(&ts, true).is_ok());
}

#[test]
fn a_full_timestamp_option_checks_the_overflow_counter() {
    // A pointer past the option means the list is full; the overflow counter
    // may then not already be saturated.
    let full = [IPOPT_TIMESTAMP, 8, 9, IPOPT_TS_TSONLY, 0, 0, 0, 0];
    assert!(options::build(&full, false).is_ok());
    let saturated = [IPOPT_TIMESTAMP, 8, 9, 0xf0, 0, 0, 0, 0];
    assert_eq!(options::build(&saturated, false), Err(Errno::Einval));
}

#[test]
fn a_router_alert_option_is_recognized_only_with_a_zero_value() {
    let ra = [IPOPT_RA, 4, 0, 0];
    assert_eq!(options::build(&ra, false).unwrap().router_alert, Some(0));
    let other = [IPOPT_RA, 4, 0, 1];
    assert_eq!(options::build(&other, false).unwrap().router_alert, None);
    assert_eq!(options::build(&[IPOPT_RA, 3, 0, IPOPT_END], false), Err(Errno::Einval));
}

#[test]
fn a_security_option_needs_the_raw_capability() {
    for kind in [IPOPT_SEC, IPOPT_SID, 200u8] {
        let opt = [kind, 4, 0, 0];
        assert_eq!(options::build(&opt, false), Err(Errno::Einval), "{kind}");
        assert!(options::build(&opt, true).is_ok(), "{kind}");
    }
}

#[test]
fn a_commercial_security_option_is_structurally_screened() {
    // Too short, then a zero domain of interpretation, then a sound one.
    assert_eq!(options::build(&[IPOPT_CIPSO, 4, 0, 0], true), Err(Errno::Einval));
    let zero_doi = [IPOPT_CIPSO, 8, 0, 0, 0, 0, 0, 0];
    assert_eq!(options::build(&zero_doi, true), Err(Errno::Einval));
    let sound = [IPOPT_CIPSO, 8, 0, 0, 0, 1, 1, 2];
    assert_eq!(options::build(&sound, true).unwrap().cipso, Some(0));
    // A zero-length tag would not advance the chain.
    let bad_tag = [IPOPT_CIPSO, 8, 0, 0, 0, 1, 1, 0];
    assert_eq!(options::build(&bad_tag, true), Err(Errno::Einval));
}

#[test]
fn an_end_of_list_marker_forces_the_remainder_to_end_markers() {
    let area = [IPOPT_NOOP, IPOPT_END, 0x99, 0x99];
    let c = options::build(&area, false).unwrap();
    assert_eq!(c.data, alloc::vec![IPOPT_NOOP, IPOPT_END, IPOPT_END, IPOPT_END]);
}

// ---- reads ---------------------------------------------------------------

fn state() -> IpGetState {
    IpGetState { ttl: -1, default_ttl: 64, mcast_ttl: 1, pmtudisc: IP_PMTUDISC_WANT,
        ..Default::default() }
}

#[test]
fn an_unset_hop_limit_reads_as_the_namespace_default() {
    assert_eq!(get::read(IP_TTL, dgram(), &state()), Ok(Value::Int(64)));
    let named = IpGetState { ttl: 3, ..state() };
    assert_eq!(get::read(IP_TTL, dgram(), &named), Ok(Value::Int(3)));
}

#[test]
fn the_path_mtu_read_needs_a_route() {
    assert_eq!(get::read(IP_MTU, dgram(), &state()), Err(Errno::Enotconn));
    let routed = IpGetState { mtu: 1500, ..state() };
    assert_eq!(get::read(IP_MTU, dgram(), &routed), Ok(Value::Int(1500)));
}

#[test]
fn the_ancillary_snapshot_is_a_stream_socket_read() {
    assert_eq!(get::read(IP_PKTOPTIONS, dgram(), &state()), Err(Errno::Enoprotoopt));
    assert_eq!(get::read(IP_PKTOPTIONS, stream(), &state()), Ok(Value::Bytes(Vec::new())));
}

#[test]
fn the_protocol_read_publishes_the_sockets_own_number() {
    assert_eq!(get::read(IP_PROTOCOL, raw(89), &state()), Ok(Value::Int(89)));
}

#[test]
fn multicast_all_reads_back_enabled_by_default() {
    assert_eq!(get::read(IP_MULTICAST_ALL, dgram(), &state()), Ok(Value::Int(1)));
    let off = IpGetState { flags: flag::MC_ALL_OFF, ..state() };
    assert_eq!(get::read(IP_MULTICAST_ALL, dgram(), &off), Ok(Value::Int(0)));
}

#[test]
fn the_unicast_interface_reads_back_in_network_order() {
    let s = IpGetState { unicast_if: 7, ..state() };
    assert_eq!(get::read(IP_UNICAST_IF, dgram(), &s),
        Ok(Value::Int(7u32.swap_bytes() as i32)));
}

#[test]
fn the_multicast_interface_read_publishes_an_address_not_an_index() {
    let s = IpGetState { mcast_addr: [10, 1, 2, 3], ..state() };
    assert_eq!(get::read(IP_MULTICAST_IF, dgram(), &s),
        Ok(Value::Bytes(Vec::from([10u8, 1, 2, 3]))));
}

#[test]
fn a_narrow_request_for_a_small_value_publishes_exactly_one_byte() {
    assert_eq!(get::scalar_out(64, 1), ScalarOut::Byte(64));
    assert_eq!(get::scalar_out(64, 3), ScalarOut::Byte(64));
    assert_eq!(get::scalar_out(64, 4), ScalarOut::Int(4));
    // Outside the unsigned-byte window the narrow form does not apply, so the
    // caller gets the leading bytes of the int instead.
    assert_eq!(get::scalar_out(-1, 2), ScalarOut::Int(2));
    assert_eq!(get::scalar_out(256, 2), ScalarOut::Int(2));
    assert_eq!(get::scalar_out(64, 0), ScalarOut::Int(0));
    assert_eq!(get::scalar_out(64, 8), ScalarOut::Int(4));
}

#[test]
fn an_option_area_read_truncates_to_the_callers_buffer() {
    assert_eq!(get::bytes_len(40, 8), 8);
    assert_eq!(get::bytes_len(8, 40), 8);
    assert_eq!(get::bytes_len(0, 40), 0);
}

#[test]
fn an_unknown_read_is_refused() {
    assert_eq!(get::read(999, dgram(), &state()), Err(Errno::Enoprotoopt));
}

#[test]
fn stored_options_read_back_as_the_caller_wrote_them() {
    let opts = IpOpts::default();
    let area = [IPOPT_RR, 7, 4, 0, 0, 0, 0, IPOPT_END];
    let Ok(Action::Options(c)) = set::admit_options(&area, net_raw(), 0) else {
        panic!("a record route is admissible");
    };
    opts.set_options(c);
    assert_eq!(opts.options_len(), 8);
    assert_eq!(opts.options_undone(), Vec::from(area));
}

#[test]
fn the_flag_word_round_trips_through_every_bit_this_level_owns() {
    let opts = IpOpts::default();
    for bit in [flag::RECVTOS, flag::RECVOPTS, flag::RETOPTS, flag::PASSSEC,
        flag::ORIGDSTADDR, flag::RECVFRAGSIZE, flag::RECVERR_RFC4884, flag::FREEBIND,
        flag::TRANSPARENT, flag::NODEFRAG, flag::BIND_ADDRESS_NO_PORT, flag::CHECKSUM,
        flag::RTALERT, flag::MC_ALL_OFF]
    {
        assert!(!opts.flag(bit));
        opts.set_flag(bit, true);
        assert!(opts.flag(bit));
        opts.set_flag(bit, false);
        assert!(!opts.flag(bit));
    }
    // Multicast delivery starts unrestricted.
    assert!(opts.multicast_all());
    opts.set_flag(flag::MC_ALL_OFF, true);
    assert!(!opts.multicast_all());
}
