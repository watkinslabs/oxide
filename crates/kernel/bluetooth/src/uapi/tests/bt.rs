use super::*;

#[test]
fn an_address_round_trips_through_the_wire_at_any_offset() {
    let a = BdAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let mut buf = [0u8; 16];
    assert!(a.to_wire(&mut buf, 4));
    assert_eq!(BdAddr::from_wire(&buf, 4), Some(a));
    assert_eq!(&buf[4..10], a.as_bytes());
}

// An address is stored in wire order, so a copy in or out of an ABI struct is
// a straight byte copy with no reversal anywhere.
#[test]
fn an_address_is_stored_in_wire_order() {
    let bytes = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
    let a = BdAddr::from_wire(&bytes, 0).unwrap();
    assert_eq!(a.0, bytes);
    let mut out = [0u8; BDADDR_LEN];
    a.to_wire(&mut out, 0);
    assert_eq!(out, bytes);
}

// A read or write that would run past the buffer is refused rather than
// truncated: a partial address is a different peer.
#[test]
fn a_read_or_write_past_the_buffer_is_refused() {
    let a = BdAddr([1; BDADDR_LEN]);
    let mut small = [0u8; 5];
    assert!(!a.to_wire(&mut small, 0));
    let mut buf = [0u8; 8];
    assert!(!a.to_wire(&mut buf, 3));
    assert!(a.to_wire(&mut buf, 2));
    assert!(BdAddr::from_wire(&[0u8; 5], 0).is_none());
    assert!(BdAddr::from_wire(&[0u8; 8], 3).is_none());
}

#[test]
fn an_offset_that_would_overflow_is_refused_rather_than_wrapping() {
    let a = BdAddr([1; BDADDR_LEN]);
    let mut buf = [0u8; 16];
    assert!(!a.to_wire(&mut buf, usize::MAX));
    assert!(BdAddr::from_wire(&buf, usize::MAX).is_none());
}

// A controller reporting the all-zero address has no assigned identity, which
// is why it cannot be brought up.
#[test]
fn the_all_zero_address_is_the_wildcard() {
    assert!(BDADDR_ANY.is_any());
    assert!(BdAddr::default().is_any());
    assert!(!BdAddr([0, 0, 0, 0, 0, 1]).is_any());
}

#[test]
fn the_protocol_selectors_are_contiguous_and_bounded_by_the_last() {
    let all = [BTPROTO_L2CAP, BTPROTO_HCI, BTPROTO_SCO, BTPROTO_RFCOMM,
        BTPROTO_BNEP, BTPROTO_CMTP, BTPROTO_HIDP, BTPROTO_AVDTP, BTPROTO_ISO];
    for (i, p) in all.iter().enumerate() { assert_eq!(*p, i as u32); }
    assert_eq!(BTPROTO_LAST, BTPROTO_ISO);
    assert!(protocol_in_range(BTPROTO_LAST));
    assert!(!protocol_in_range(BTPROTO_LAST + 1));
}

// The levels are ordered so a numeric comparison IS the sufficiency test; a
// gap or a reordering would make a higher level compare as lower.
#[test]
fn the_security_levels_are_ordered_and_contiguous() {
    let levels = [BT_SECURITY_SDP, BT_SECURITY_LOW, BT_SECURITY_MEDIUM,
        BT_SECURITY_HIGH, BT_SECURITY_FIPS];
    for (i, l) in levels.iter().enumerate() { assert_eq!(*l, i as u8); }
    for w in levels.windows(2) { assert!(w[0] < w[1]); }
    for l in levels { assert!(security_level_valid(l)); }
    assert!(!security_level_valid(BT_SECURITY_FIPS + 1));
    assert!(!security_level_valid(0xff));
}

// The socket states share one numbering across every protocol, and the
// established state is 1 because it aliases what the socket layer reports.
#[test]
fn the_socket_states_are_one_numbering_with_the_established_state_first() {
    assert_eq!(BT_CONNECTED, 1);
    let rest = [BT_OPEN, BT_BOUND, BT_LISTEN, BT_CONNECT, BT_CONNECT2,
        BT_CONFIG, BT_DISCONN, BT_CLOSED];
    for (i, s) in rest.iter().enumerate() { assert_eq!(*s, (i + 2) as u8); }
}

#[test]
fn the_three_address_types_are_distinct_and_start_at_zero() {
    assert_eq!(BDADDR_BREDR, 0);
    assert_eq!(BDADDR_LE_PUBLIC, 1);
    assert_eq!(BDADDR_LE_RANDOM, 2);
}

// The family-wide option numbers must not collide with each other: two options
// sharing a number would let one socket's setting silently become another's.
#[test]
fn no_two_family_wide_option_numbers_collide() {
    let opts = [BT_SECURITY, BT_DEFER_SETUP, BT_FLUSHABLE, BT_POWER,
        BT_CHANNEL_POLICY, BT_VOICE, BT_SNDMTU, BT_RCVMTU, BT_PHY, BT_MODE,
        BT_PKT_STATUS, BT_ISO_QOS, BT_CODEC];
    for (i, a) in opts.iter().enumerate() {
        assert!(!opts[i + 1..].contains(a), "option {a} appears twice");
    }
}

#[test]
fn the_per_protocol_option_levels_are_distinct() {
    let levels = [SOL_HCI, SOL_L2CAP, SOL_SCO, SOL_RFCOMM, SOL_BLUETOOTH];
    for (i, a) in levels.iter().enumerate() {
        assert!(!levels[i + 1..].contains(a), "level {a} appears twice");
    }
}

#[test]
fn the_transmission_modes_are_distinct_and_start_at_the_basic_one() {
    assert_eq!(BT_MODE_BASIC, 0);
    let modes = [BT_MODE_BASIC, BT_MODE_ERTM, BT_MODE_STREAMING,
        BT_MODE_LE_FLOWCTL, BT_MODE_EXT_FLOWCTL];
    for (i, m) in modes.iter().enumerate() { assert_eq!(*m, i as u8); }
}
