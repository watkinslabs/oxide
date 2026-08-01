// Which (domain, type, protocol) triples `socketpair(2)` admits, and the errno
// each rejection carries — asserted on returned values, not on shim text.

use super::*;
use net::socket_args::{AF_INET, SOCK_SEQPACKET, SOCK_STREAM};

/// `IPPROTO_ICMP` — a raw protocol that exists, so the capability screen is
/// what the request actually meets.
const IPPROTO_ICMP: u32 = 1;

#[test]
fn only_cloexec_and_nonblock_may_ride_the_type_word() {
    assert_eq!(check_type_flags(SOCK_STREAM), Ok(()));
    assert_eq!(check_type_flags(SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK), Ok(()));
    // Any other high bit is EINVAL before anything else is looked at.
    assert_eq!(check_type_flags(SOCK_STREAM | 0x1000), Err(Errno::Einval));
}

#[test]
fn unix_stream_dgram_and_seqpacket_are_admitted_with_their_own_type() {
    for typ in [SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET] {
        let spec = admit(AF_UNIX, typ, 0, false).expect("AF_UNIX pair");
        assert_eq!(spec.args.family, AF_UNIX);
        assert_eq!(spec.socket_type, typ);
    }
}

#[test]
fn unix_raw_socketpair_takes_the_datagram_personality() {
    // `unix_create` maps SOCK_RAW onto SOCK_DGRAM; the parsed type is left
    // alone so the capability screen still saw a raw request.
    let spec = admit(AF_UNIX, SOCK_RAW, 0, true).expect("AF_UNIX raw pair");
    assert_eq!(spec.args.typ, SOCK_RAW);
    assert_eq!(spec.socket_type, SOCK_DGRAM,
        "both ends are built as, and report, SOCK_DGRAM");
}

#[test]
fn a_raw_socketpair_request_needs_the_same_capability_as_socket() {
    // The per-family creation gate outranks the missing pair operation, so an
    // unprivileged raw request fails its capability screen rather than
    // reaching the AF_UNIX check and reporting EOPNOTSUPP.
    assert_eq!(admit(AF_INET, SOCK_RAW, IPPROTO_ICMP, false).err(), Some(Errno::Eperm));
    // With the capability the family parses, and only then is the missing
    // pair operation reported.
    assert_eq!(admit(AF_INET, SOCK_RAW, IPPROTO_ICMP, true).err(), Some(Errno::Eopnotsupp));
    // AF_UNIX SOCK_RAW carries no capability screen at all (`unix_create`),
    // so it is admitted either way.
    assert!(admit(AF_UNIX, SOCK_RAW, 0, false).is_ok());
}

#[test]
fn a_valid_non_unix_family_is_eopnotsupp_not_eafnosupport() {
    // AF_INET parses fine — it simply owns no socketpair operation. Reporting
    // EAFNOSUPPORT would claim the family does not exist.
    assert_eq!(admit(AF_INET, SOCK_STREAM, 0, false).err(), Some(Errno::Eopnotsupp));
    assert_eq!(admit(AF_INET, SOCK_DGRAM, 0, false).err(), Some(Errno::Eopnotsupp));
}

#[test]
fn an_unknown_family_keeps_the_parse_error() {
    assert_eq!(admit(0xdead, SOCK_STREAM, 0, false).err(), Some(Errno::Eafnosupport));
}

#[test]
fn cloexec_and_nonblock_survive_into_the_parsed_spec() {
    let spec = admit(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, false)
        .expect("AF_UNIX pair");
    assert!(spec.args.cloexec && spec.args.nonblock);
    assert_eq!(spec.socket_type, SOCK_STREAM, "the flag bits are not part of the type");
}
