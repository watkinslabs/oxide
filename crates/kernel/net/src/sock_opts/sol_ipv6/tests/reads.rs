// `IPPROTO_IPV6` option coverage: reads.

use alloc::vec::Vec;
use syscall::errno::Errno;
use super::super::get::{self, Ipv6GetState, Value};
use super::super::set::{Ipv6Sock, RECVHOPLIMIT, RECVPKTINFO, RECVTCLASS};
use super::super::state::{Sticky, flag};
use super::super::uapi::*;
use super::*;

// ---- reads ---------------------------------------------------------------

fn state() -> Ipv6GetState {
    Ipv6GetState { hop_limit: -1, mcast_hops: 1, route_hoplimit: -1,
        default_hoplimit: IPV6_DEFAULT_HOPLIMIT, pmtudisc: IPV6_PMTUDISC_WANT,
        ..Default::default() }
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

// The sticky source this option writes has no read of its own: it is a write
// and a per-message ancillary type, and the only interface that publishes it
// back is the receive control message. Its real consumer is source selection
// on transmit, so answering the read would be the second reader, not the
// first.
#[test]
fn the_sticky_source_option_has_no_readback() {
    assert_eq!(get::read(IPV6_PKTINFO, dgram(), &state()), Err(Errno::Enoprotoopt));
    assert_eq!(get::read(IPV6_PKTINFO, stream(), &state()), Err(Errno::Enoprotoopt));
    // The ancillary form of the same number stays readable as the receive
    // personality bit it is.
    assert!(get::read(IPV6_2292PKTINFO, dgram(), &state()).is_ok());
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
    use super::super::autolabel;
    // A socket that named no policy publishes the namespace's — and the
    // compiled namespace policy opts sockets IN, so an untouched socket reads
    // back 1, not 0.
    let s = Ipv6GetState { auto_flowlabels: autolabel::DEFAULT_POLICY, ..state() };
    assert_eq!(get::read(IPV6_AUTOFLOWLABEL, dgram(), &s), Ok(Value::Int(1)));
    let opt_in_ns = Ipv6GetState { auto_flowlabels: autolabel::OPTIN, ..state() };
    assert_eq!(get::read(IPV6_AUTOFLOWLABEL, dgram(), &opt_in_ns), Ok(Value::Int(0)));
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
    // A stream socket gets an ancillary STREAM, not a value: the caller's
    // length is a budget the messages pack into, so the read owns its copyout.
    assert_eq!(get::read(IPV6_2292PKTOPTIONS, stream(), &state()), Ok(Value::ControlStream));
}

#[test]
fn an_unknown_read_is_refused() {
    assert_eq!(get::read(999, dgram(), &state()), Err(Errno::Enoprotoopt));
    assert_eq!(get::read(IPV6_HOPLIMIT, dgram(), &state()), Err(Errno::Enoprotoopt));
}
