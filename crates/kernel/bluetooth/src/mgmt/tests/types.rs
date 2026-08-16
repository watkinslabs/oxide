//! Shared records: widths, round-trips, and the checks that refuse a short or
//! over-long buffer.

use super::*;
use crate::mgmt::codec::{Reader, Writer};
use crate::uapi::mgmt::limits::*;

fn addr() -> AddrInfo { AddrInfo::new(BdAddr([6, 5, 4, 3, 2, 1]), BDADDR_LE_PUBLIC) }

fn roundtrip<T, R, W>(v: &T, width: usize, read: R, write: W)
where T: core::fmt::Debug + PartialEq, R: Fn(&mut Reader) -> Option<T>, W: Fn(&T, &mut Writer) {
    let mut w = Writer::new();
    write(v, &mut w);
    let buf = w.finish();
    assert_eq!(buf.len(), width, "record width");
    let mut r = Reader::new(&buf);
    assert_eq!(read(&mut r).as_ref(), Some(v));
    assert!(r.done(), "the reader must consume exactly the record");
    // One byte short is refused.
    let mut r = Reader::new(&buf[..width - 1]);
    assert!(read(&mut r).is_none(), "a short buffer must be refused");
}

#[test]
fn addr_info_round_trips_at_seven_bytes() {
    roundtrip(&addr(), MGMT_ADDR_INFO_SIZE, AddrInfo::read, AddrInfo::write);
    assert_eq!(AddrInfo::decode(&addr().encode()), Some(addr()));
}

#[test]
fn addr_info_decode_refuses_a_trailing_byte() {
    let mut buf = addr().encode();
    buf.push(0);
    assert_eq!(AddrInfo::decode(&buf), None);
}

#[test]
fn an_address_type_outside_the_three_is_refused() {
    for t in [BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM] {
        assert!(AddrInfo::new(BdAddr::default(), t).type_is_valid(), "type {t}");
    }
    for t in [3u8, 4, 0xff] {
        assert!(!AddrInfo::new(BdAddr::default(), t).type_is_valid(), "type {t}");
    }
    assert!(!AddrInfo::new(BdAddr::default(), BDADDR_BREDR).is_le());
    assert!(AddrInfo::new(BdAddr::default(), BDADDR_LE_RANDOM).is_le());
}

#[test]
fn link_key_round_trips() {
    let v = LinkKeyInfo { addr: addr(), key_type: 4, val: [0xa5; MGMT_KEY_LEN], pin_len: 6 };
    roundtrip(&v, MGMT_LINK_KEY_INFO_SIZE, LinkKeyInfo::read, LinkKeyInfo::write);
}

#[test]
fn long_term_key_round_trips_with_its_wide_fields() {
    let v = LtkInfo {
        addr: addr(), key_type: 1, initiator: 1, enc_size: 16,
        ediv: 0xbeef, rand: 0x0102_0304_0506_0708, val: [0x5a; MGMT_KEY_LEN],
    };
    roundtrip(&v, MGMT_LTK_INFO_SIZE, LtkInfo::read, LtkInfo::write);
    // The 64-bit randomiser is little-endian like every other field.
    let mut w = Writer::new();
    v.write(&mut w);
    let buf = w.finish();
    assert_eq!(&buf[12..20], &[8, 7, 6, 5, 4, 3, 2, 1]);
}

#[test]
fn irk_and_csrk_round_trip() {
    let irk = IrkInfo { addr: addr(), val: [1; MGMT_KEY_LEN] };
    roundtrip(&irk, MGMT_IRK_INFO_SIZE, IrkInfo::read, IrkInfo::write);
    let csrk = CsrkInfo { addr: addr(), key_type: 2, val: [2; MGMT_KEY_LEN] };
    roundtrip(&csrk, MGMT_CSRK_INFO_SIZE, CsrkInfo::read, CsrkInfo::write);
}

#[test]
fn conn_param_round_trips() {
    let v = ConnParam {
        addr: addr(), min_interval: 6, max_interval: 12, latency: 0, timeout: 200,
    };
    roundtrip(&v, MGMT_CONN_PARAM_SIZE, ConnParam::read, ConnParam::write);
}

#[test]
fn blocked_key_round_trips() {
    let v = BlockedKeyInfo { key_type: 1, val: [7; MGMT_KEY_LEN] };
    roundtrip(&v, MGMT_BLOCKED_KEY_INFO_SIZE, BlockedKeyInfo::read, BlockedKeyInfo::write);
}

/// A pattern occupies its full width whatever its match length says, so a run
/// of patterns is indexable.
#[test]
fn a_pattern_is_always_its_full_width() {
    let v = AdvPattern {
        ad_type: 0x09, offset: 0, length: 4, value: [0xcd; MGMT_ADV_PATTERN_VALUE_LEN],
    };
    roundtrip(&v, MGMT_ADV_PATTERN_SIZE, AdvPattern::read, AdvPattern::write);
}

#[test]
fn a_pattern_window_must_fit_its_value_field() {
    let mk = |offset: u8, length: u8| AdvPattern {
        ad_type: 0, offset, length, value: [0; MGMT_ADV_PATTERN_VALUE_LEN],
    };
    assert!(mk(0, 31).window_is_valid());
    assert!(mk(30, 1).window_is_valid());
    assert!(!mk(0, 32).window_is_valid(), "one past the field");
    assert!(!mk(30, 2).window_is_valid(), "offset plus length one past");
    assert!(!mk(0, 0).window_is_valid(), "an empty window matches nothing");
    assert!(!mk(255, 1).window_is_valid());
}

#[test]
fn rssi_thresholds_round_trip_with_signed_fields() {
    let v = AdvRssiThresholds {
        high_threshold: -40, high_threshold_timeout: 5,
        low_threshold: -80, low_threshold_timeout: 10, sampling_period: 20,
    };
    roundtrip(&v, MGMT_ADV_RSSI_THRESHOLDS_SIZE,
              AdvRssiThresholds::read, AdvRssiThresholds::write);
}
