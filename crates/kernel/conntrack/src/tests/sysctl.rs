// Tunables: name resolution, round-trip, and the writes that must be refused.

use crate::proto::tcp_state::*;
use crate::proto::udp::{UDP_CT_REPLIED, UDP_CT_UNREPLIED};
use crate::sysctl::*;

#[test]
fn every_knob_has_a_name_that_resolves_back() {
    for (name, knob) in KNOBS {
        assert_eq!(knob_by_name(name), Some(*knob), "{name}");
    }
    assert_eq!(knob_by_name("nf_conntrack_no_such_knob"), None);
}

#[test]
fn defaults_match_the_documented_values() {
    let s = CtSysctl::default();
    assert_eq!(s.get(Knob::TcpTimeoutEstablished), 432_000);
    assert_eq!(s.get(Knob::TcpTimeoutSynSent), 120);
    assert_eq!(s.get(Knob::UdpTimeout), 30);
    assert_eq!(s.get(Knob::UdpTimeoutStream), 120);
    assert_eq!(s.get(Knob::IcmpTimeout), 30);
    assert_eq!(s.get(Knob::GenericTimeout), 600);
    assert_eq!(s.get(Knob::Checksum), 1);
    // Automatic helper attachment is off: a payload parser bound purely on a
    // port number is one an attacker chooses.
    assert_eq!(s.get(Knob::Helper), 0);
    assert_eq!(s.get(Knob::TcpMaxRetrans), TCP_MAX_RETRANS as u64);
}

#[test]
fn writes_round_trip() {
    let mut s = CtSysctl::default();
    for (knob, v) in [
        (Knob::TcpTimeoutEstablished, 3600u64), (Knob::TcpTimeoutSynSent, 30),
        (Knob::TcpTimeoutSynRecv, 15), (Knob::TcpTimeoutFinWait, 45),
        (Knob::TcpTimeoutCloseWait, 20), (Knob::TcpTimeoutLastAck, 5),
        (Knob::TcpTimeoutTimeWait, 60), (Knob::TcpTimeoutClose, 3),
        (Knob::TcpTimeoutSynSent2, 90), (Knob::TcpTimeoutMaxRetrans, 100),
        (Knob::TcpTimeoutUnacknowledged, 200), (Knob::TcpLoose, 0),
        (Knob::TcpBeLiberal, 1), (Knob::TcpIgnoreInvalidRst, 1),
        (Knob::TcpMaxRetrans, 9), (Knob::UdpTimeout, 11), (Knob::UdpTimeoutStream, 222),
        (Knob::IcmpTimeout, 7), (Knob::Icmpv6Timeout, 8), (Knob::GenericTimeout, 900),
        (Knob::Checksum, 0), (Knob::Events, 0), (Knob::LogInvalid, 6),
        (Knob::Helper, 1), (Knob::Acct, 1), (Knob::Max, 100_000),
    ] {
        assert!(s.set(knob, v), "{knob:?} must accept {v}");
        assert_eq!(s.get(knob), v, "{knob:?}");
    }
    assert_eq!(s.tcp.timeouts[TCP_CONNTRACK_ESTABLISHED as usize], 3600);
    assert_eq!(s.udp.timeouts[UDP_CT_UNREPLIED], 11);
    assert_eq!(s.udp.timeouts[UDP_CT_REPLIED], 222);
}

#[test]
fn the_bucket_count_is_read_only() {
    let mut s = CtSysctl::default();
    let before = s.get(Knob::Buckets);
    // Accepting the write would report a size the hash does not have.
    assert!(!s.set(Knob::Buckets, 8));
    assert_eq!(s.get(Knob::Buckets), before);
}

#[test]
fn an_out_of_range_write_leaves_the_old_value() {
    let mut s = CtSysctl::default();
    let before = s.get(Knob::TcpMaxRetrans);
    assert!(!s.set(Knob::TcpMaxRetrans, 300), "does not fit the field");
    assert_eq!(s.get(Knob::TcpMaxRetrans), before);
    let before = s.get(Knob::LogInvalid);
    assert!(!s.set(Knob::LogInvalid, 5000));
    assert_eq!(s.get(Knob::LogInvalid), before);
    let before = s.get(Knob::TcpTimeoutEstablished);
    assert!(!s.set(Knob::TcpTimeoutEstablished, u64::MAX));
    assert_eq!(s.get(Knob::TcpTimeoutEstablished), before);
}

#[test]
fn the_entry_ceiling_accepts_a_wide_value() {
    let mut s = CtSysctl::default();
    assert!(s.set(Knob::Max, 5_000_000_000));
    assert_eq!(s.get(Knob::Max), 5_000_000_000);
}
