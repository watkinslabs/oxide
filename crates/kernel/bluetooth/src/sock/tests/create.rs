use super::*;

// The protocol selector is range-checked BEFORE the type. A request naming
// both an out-of-range protocol and a wrong type must report the protocol: the
// family cannot ask a protocol that does not exist about the type.
#[test]
fn the_protocol_range_check_outranks_the_type_check() {
    assert_eq!(plan_create(BT_MAX_PROTO, 0xffff, true), Err(Errno::Einval));
    assert_eq!(plan_create(99, SOCK_DGRAM, true), Err(Errno::Einval));
}

// In range but unserved is a real protocol this host does not carry. Reporting
// it as out of range would tell a caller it can never exist.
#[test]
fn an_in_range_unserved_protocol_reports_the_protocol_not_the_range() {
    for p in [BTPROTO_BNEP, BTPROTO_CMTP, BTPROTO_HIDP, BTPROTO_AVDTP, BTPROTO_ISO] {
        assert!(protocol_unserved(p));
        assert!(!protocol_served(p));
        assert_eq!(plan_create(p, SOCK_STREAM, true), Err(Errno::Eprotonosupport));
    }
}

#[test]
fn every_protocol_selector_is_either_served_or_unserved_and_never_both() {
    for p in 0..BT_MAX_PROTO {
        assert!(protocol_served(p) ^ protocol_unserved(p), "protocol {p}");
    }
}

#[test]
fn raw_controller_access_takes_only_the_raw_type() {
    assert_eq!(plan_create(BTPROTO_HCI, SOCK_RAW, false), Ok(BtSocket::Hci));
    for t in [SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET] {
        assert_eq!(plan_create(BTPROTO_HCI, t, true), Err(Errno::Esocktnosupport));
    }
}

#[test]
fn channels_take_four_types_and_voice_takes_one() {
    for t in [SOCK_SEQPACKET, SOCK_STREAM, SOCK_DGRAM] {
        assert_eq!(plan_create(BTPROTO_L2CAP, t, false), Ok(BtSocket::L2cap { typ: t }));
    }
    assert_eq!(plan_create(BTPROTO_SCO, SOCK_SEQPACKET, false), Ok(BtSocket::Sco));
    for t in [SOCK_STREAM, SOCK_DGRAM, SOCK_RAW] {
        assert_eq!(plan_create(BTPROTO_SCO, t, true), Err(Errno::Esocktnosupport));
    }
}

#[test]
fn serial_emulation_takes_the_stream_and_raw_types_only() {
    assert_eq!(plan_create(BTPROTO_RFCOMM, SOCK_STREAM, false),
        Ok(BtSocket::Rfcomm { typ: SOCK_STREAM }));
    assert_eq!(plan_create(BTPROTO_RFCOMM, SOCK_RAW, false),
        Ok(BtSocket::Rfcomm { typ: SOCK_RAW }));
    for t in [SOCK_DGRAM, SOCK_SEQPACKET] {
        assert_eq!(plan_create(BTPROTO_RFCOMM, t, true), Err(Errno::Esocktnosupport));
    }
}

// The raw channel type reaches the signalling channel itself, so it is
// privileged — but the TYPE screen runs first, so an unprivileged caller
// naming a nonexistent type still learns the type is wrong rather than being
// told it lacks a capability for a socket that could never exist.
#[test]
fn the_privileged_channel_type_is_screened_after_the_type_itself() {
    assert_eq!(plan_create(BTPROTO_L2CAP, SOCK_RAW, false), Err(Errno::Eperm));
    assert_eq!(plan_create(BTPROTO_L2CAP, SOCK_RAW, true),
        Ok(BtSocket::L2cap { typ: SOCK_RAW }));
    // A type that does not exist reports the type, not the capability.
    assert_eq!(plan_create(BTPROTO_L2CAP, 4, false), Err(Errno::Esocktnosupport));
}

// Every other protocol's types are admitted regardless of the capability: only
// the raw channel type is privileged.
#[test]
fn no_other_protocol_requires_the_raw_network_capability() {
    assert!(plan_create(BTPROTO_HCI, SOCK_RAW, false).is_ok());
    assert!(plan_create(BTPROTO_RFCOMM, SOCK_RAW, false).is_ok());
    assert!(plan_create(BTPROTO_SCO, SOCK_SEQPACKET, false).is_ok());
}

#[test]
fn the_highest_served_selector_is_in_range_and_the_next_is_not() {
    assert!(BTPROTO_LAST < BT_MAX_PROTO);
    assert_eq!(plan_create(BT_MAX_PROTO, SOCK_STREAM, true), Err(Errno::Einval));
    assert_eq!(plan_create(BTPROTO_LAST, SOCK_STREAM, true), Err(Errno::Eprotonosupport));
}
