// Information-element walking: truncation, duplicates, extension elements,
// and the vendor elements the stack reads.
//
// Two of these are security properties, not tidiness. A stream whose last
// element declares a body past the buffer must terminate the walk instead of
// handing back a short body; and a duplicate identifier must keep the FIRST
// occurrence, because appending a second copy is how a forged element gets
// substituted for a real one.

extern crate alloc;

use alloc::vec::Vec;

use crate::ieee80211::elem::{self, id, ext_id, Elements};

/// Append one element.
fn put(out: &mut Vec<u8>, id: u8, body: &[u8]) {
    out.push(id);
    out.push(body.len() as u8);
    out.extend_from_slice(body);
}

#[test]
fn a_declared_length_past_the_end_stops_the_walk() {
    // A valid element, then one claiming eight bytes with only two present.
    let mut buf = Vec::new();
    put(&mut buf, id::SSID, b"net");
    buf.extend_from_slice(&[id::SUPP_RATES, 8, 0x82, 0x84]);
    let seen: Vec<u8> = elem::parse(&buf).map(|e| e.id).collect();
    assert_eq!(seen, alloc::vec![id::SSID], "the truncated element must not be produced");
    assert!(!elem::is_well_formed(&buf));
    assert!(elem::find(&buf, id::SUPP_RATES).is_none());
}

#[test]
fn a_one_byte_tail_is_not_an_element() {
    let mut buf = Vec::new();
    put(&mut buf, id::SSID, b"n");
    buf.push(id::TIM);
    assert_eq!(elem::parse(&buf).count(), 1);
    assert!(!elem::is_well_formed(&buf));
}

#[test]
fn a_duplicate_identifier_keeps_the_first() {
    let mut buf = Vec::new();
    put(&mut buf, id::SSID, b"real");
    put(&mut buf, id::SSID, b"forged");
    let e = Elements::parse(&buf);
    assert_eq!(e.ssid_bytes(), b"real");
    assert_eq!(elem::find(&buf, id::SSID).unwrap().body, b"real");
    // The walk still reports both, so a caller that wants to notice the
    // duplicate can; it is the resolver that picks.
    assert_eq!(elem::parse(&buf).filter(|x| x.id == id::SSID).count(), 2);
}

#[test]
fn an_extension_element_reports_its_inner_identifier_and_a_body_without_it() {
    let mut buf = Vec::new();
    put(&mut buf, id::EXTENSION, &[ext_id::HE_CAPABILITY, 1, 2, 3]);
    let e = elem::find_ext(&buf, ext_id::HE_CAPABILITY).unwrap();
    assert_eq!(e.ext_id, Some(ext_id::HE_CAPABILITY));
    assert_eq!(e.body, &[1, 2, 3]);
    assert!(elem::find_ext(&buf, ext_id::HE_OPERATION).is_none());
    assert_eq!(Elements::parse(&buf).he_capability, Some(&[1u8, 2, 3][..]));
}

#[test]
fn an_extension_element_with_an_empty_body_is_malformed() {
    // The identifier byte is mandatory, so a zero-length extension element
    // has no identifier at all.
    let buf = [id::EXTENSION, 0];
    assert!(!elem::is_well_formed(&buf));
    assert_eq!(elem::parse(&buf).count(), 0);
}

#[test]
fn a_zero_length_element_is_present_and_empty() {
    // A hidden network sends an SSID element with no body. That is a PRESENT
    // element, not an absent one, and the difference is what tells a scanner
    // the network is hiding rather than that the frame was malformed.
    let buf = [id::SSID, 0];
    assert!(elem::is_well_formed(&buf));
    let e = elem::find(&buf, id::SSID).unwrap();
    assert!(e.body.is_empty());
    assert!(Elements::parse(&buf).ssid.is_some());
    assert_eq!(Elements::parse(&buf).ssid_bytes(), b"");
}

#[test]
fn a_vendor_element_matches_only_on_its_own_identifier_and_type() {
    let mut buf = Vec::new();
    let mut wmm = Vec::from(elem::OUI_MICROSOFT);
    wmm.push(elem::OUI_TYPE_WMM);
    wmm.extend_from_slice(&[0x01, 0x80]);
    put(&mut buf, id::VENDOR_SPECIFIC, &wmm);
    let mut wpa = Vec::from(elem::OUI_MICROSOFT);
    wpa.push(elem::OUI_TYPE_WPA);
    wpa.extend_from_slice(&[0x01, 0x00]);
    put(&mut buf, id::VENDOR_SPECIFIC, &wpa);

    assert!(elem::find_vendor(&buf, elem::OUI_MICROSOFT, elem::OUI_TYPE_WMM).is_some());
    assert!(elem::find_vendor(&buf, elem::OUI_MICROSOFT, elem::OUI_TYPE_WPA).is_some());
    assert!(elem::find_vendor(&buf, elem::OUI_MICROSOFT, 99).is_none());
    assert!(elem::find_vendor(&buf, [0, 0, 0], elem::OUI_TYPE_WMM).is_none());

    let e = Elements::parse(&buf);
    assert!(e.wmm.is_some());
    assert!(e.wpa.is_some());
    assert_ne!(e.wmm, e.wpa);
}

#[test]
fn a_short_vendor_element_is_not_matched_against_a_prefix_it_does_not_have() {
    let mut buf = Vec::new();
    put(&mut buf, id::VENDOR_SPECIFIC, &[0x00, 0x50]);
    assert!(elem::find_vendor(&buf, elem::OUI_MICROSOFT, elem::OUI_TYPE_WMM).is_none());
    assert!(Elements::parse(&buf).wmm.is_none());
}

#[test]
fn the_operating_channel_comes_from_the_parameter_set_or_the_operation_element() {
    let mut buf = Vec::new();
    put(&mut buf, id::DS_PARAMS, &[11]);
    assert_eq!(Elements::parse(&buf).channel(), Some(11));

    // A band with no direct-sequence element states its channel in the
    // high-throughput operation element's first byte.
    let mut buf = Vec::new();
    put(&mut buf, id::HT_OPERATION, &[36, 0, 0, 0, 0]);
    assert_eq!(Elements::parse(&buf).channel(), Some(36));

    // With both, the parameter set wins.
    let mut buf = Vec::new();
    put(&mut buf, id::DS_PARAMS, &[6]);
    put(&mut buf, id::HT_OPERATION, &[36, 0, 0, 0, 0]);
    assert_eq!(Elements::parse(&buf).channel(), Some(6));

    assert_eq!(Elements::parse(&[]).channel(), None);
}

#[test]
fn one_walk_resolves_every_element_the_stack_reads() {
    let mut buf = Vec::new();
    put(&mut buf, id::SSID, b"oxide");
    put(&mut buf, id::SUPP_RATES, &[0x82, 0x84, 0x8b, 0x96]);
    put(&mut buf, id::DS_PARAMS, &[1]);
    put(&mut buf, id::TIM, &[0, 1, 0, 0]);
    put(&mut buf, id::COUNTRY, b"US \x01\x0b\x14");
    put(&mut buf, id::ERP_INFO, &[0x04]);
    put(&mut buf, id::HT_CAPABILITY, &[0u8; 26]);
    put(&mut buf, id::RSN, &[0x01, 0x00]);
    put(&mut buf, id::EXT_SUPP_RATES, &[0x0c, 0x12]);
    put(&mut buf, id::EXT_CAPABILITY, &[0xff]);
    let e = Elements::parse(&buf);
    assert_eq!(e.ssid_bytes(), b"oxide");
    assert_eq!(e.supp_rates, Some(&[0x82u8, 0x84, 0x8b, 0x96][..]));
    assert_eq!(e.ext_supp_rates, Some(&[0x0cu8, 0x12][..]));
    assert_eq!(e.ds_params, Some(&[1u8][..]));
    assert!(e.tim.is_some());
    assert!(e.country.is_some());
    assert_eq!(e.erp_info, Some(0x04));
    assert_eq!(e.ht_capability.map(<[u8]>::len), Some(26));
    assert!(e.rsn.is_some());
    assert!(e.ext_capability.is_some());
    assert!(e.vht_capability.is_none());
    assert!(e.he_operation.is_none());
}

#[test]
fn a_maximum_length_element_is_well_formed() {
    let body = alloc::vec![0xaau8; elem::MAX_BODY_LEN];
    let mut buf = Vec::new();
    put(&mut buf, id::SSID, &body);
    assert!(elem::is_well_formed(&buf));
    assert_eq!(elem::find(&buf, id::SSID).unwrap().body.len(), elem::MAX_BODY_LEN);
}

#[test]
fn an_empty_stream_is_well_formed_and_yields_nothing() {
    assert!(elem::is_well_formed(&[]));
    assert_eq!(elem::parse(&[]).count(), 0);
    let e = Elements::parse(&[]);
    assert!(e.ssid.is_none());
    assert_eq!(e.ssid_bytes(), b"");
}
