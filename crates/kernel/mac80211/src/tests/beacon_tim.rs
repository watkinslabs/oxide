// The traffic-indication map: which sleeping station has traffic waiting.
//
// Reading the bitmap without its offset reports ANOTHER station's traffic as
// this one's, so a station wakes for nothing while the one that really has
// traffic keeps sleeping.

use alloc::vec;

use crate::mlme::beacon::{tim_element, tim_has_multicast, tim_has_traffic};
use crate::sta_info::Sta;
use crate::tests_fixture as f;
use wireless::uapi::enums::IfType;

/// Build a map by hand: count, period, control, then the bitmap.
fn tim(offset: u8, multicast: bool, bitmap: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = vec![0u8, 2, (offset & 0xfe) | (multicast as u8)];
    out.extend_from_slice(bitmap);
    out
}

#[test]
fn a_station_with_traffic_is_named_and_others_are_not() {
    // Identifier 5 sits in byte 0, bit 5.
    let t = tim(0, false, &[1 << 5]);
    assert!(tim_has_traffic(&t, 5));
    for aid in [1u16, 2, 3, 4, 6, 7] { assert!(!tim_has_traffic(&t, aid), "aid {aid}"); }
}

#[test]
fn the_bitmap_offset_is_applied() {
    // With an offset of 2 the first bitmap byte describes identifiers 16..23.
    let t = tim(2, false, &[1 << 3]);
    assert!(tim_has_traffic(&t, 19));
    assert!(!tim_has_traffic(&t, 3), "without the offset this would read as identifier 3");
}

#[test]
fn an_identifier_below_the_offset_has_no_bit_to_read() {
    let t = tim(4, false, &[0xff]);
    assert!(!tim_has_traffic(&t, 5));
    assert!(tim_has_traffic(&t, 32));
}

#[test]
fn an_identifier_past_the_bitmap_is_not_named() {
    let t = tim(0, false, &[0xff]);
    assert!(!tim_has_traffic(&t, 100));
}

#[test]
fn identifier_zero_is_never_a_station() {
    let t = tim(0, false, &[0xff]);
    assert!(!tim_has_traffic(&t, 0));
}

#[test]
fn a_truncated_map_names_nobody() {
    for len in 0..4 { assert!(!tim_has_traffic(&vec![0u8; len], 1), "len {len}"); }
}

#[test]
fn group_traffic_has_its_own_bit_which_is_not_part_of_the_offset() {
    assert!(tim_has_multicast(&tim(0, true, &[0])));
    assert!(!tim_has_multicast(&tim(0, false, &[0])));
    // The low bit being the group indication is why the offset masks it off.
    let t = tim(2, true, &[1 << 3]);
    assert!(tim_has_multicast(&t));
    assert!(tim_has_traffic(&t, 19), "the group bit must not shift the offset");
}

#[test]
fn a_built_map_names_exactly_the_stations_holding_traffic() {
    let (local, _rec) = f::radio(f::AP);
    let sdata = f::iface(&local, IfType::Ap, "wlan-tim");
    for (addr, aid, buffered) in [(f::STA, 1u16, true), (f::PEER, 9, false),
                                  (f::OTHER, 17, true)] {
        let mut sta = Sta::new(addr, 0);
        sta.aid = aid;
        sdata.stas.insert(sta);
        if buffered { sdata.stas.with(addr, |s| s.buffer_ps(vec![0; 4], false, 0)); }
    }
    let t = tim_element(&sdata, 3);
    assert_eq!(t[1], 3, "the delivery period is carried as given");
    assert!(tim_has_traffic(&t, 1));
    assert!(!tim_has_traffic(&t, 9), "a station with nothing waiting is not named");
    assert!(tim_has_traffic(&t, 17));
    assert!(!tim_has_multicast(&t));
    f::drop_radio(&local);
}

#[test]
fn a_built_map_announces_group_traffic_when_some_is_held() {
    let (local, _rec) = f::radio(f::AP);
    let sdata = f::iface(&local, IfType::Ap, "wlan-tim2");
    let mut sta = Sta::new(f::STA, 0);
    // Identifier zero is the group pseudo-station.
    sta.aid = 0;
    sdata.stas.insert(sta);
    sdata.stas.with(f::STA, |s| s.buffer_ps(vec![0; 4], true, 0));
    let t = tim_element(&sdata, 1);
    assert!(tim_has_multicast(&t));
    f::drop_radio(&local);
}

#[test]
fn a_delivery_period_of_zero_is_reported_as_one() {
    // A period of zero would mean every beacon and no beacon at once.
    let (local, _rec) = f::radio(f::AP);
    let sdata = f::iface(&local, IfType::Ap, "wlan-tim3");
    let t = tim_element(&sdata, 0);
    assert_eq!(t[1], 1);
    f::drop_radio(&local);
}
