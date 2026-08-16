// Radio and interface state that userspace can change: the name, and the
// beaconed parameters.
//
// Both were stored-but-unconsumed at first. The name was fixed at
// registration on an `Arc`, so a rename could only be refused; the beacon
// parameters were validated and then dropped on the floor, so a request that
// succeeded changed nothing. A value userspace can set and never read back is
// the same defect either way.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::attr;

use crate::ieee80211::MacAddr;
use crate::ops::Cfg80211Ops;
use crate::uapi::attr as a;
use crate::wdev::{BssParams, BssParamsRequest, Wdev};
use crate::wiphy::{registry, Wiphy, WiphyCaps};

/// A driver that implements nothing, so every operation takes its default.
struct NoOps;
impl Cfg80211Ops for NoOps {}

fn radio() -> Arc<Wiphy> {
    let w = Wiphy::new(MacAddr([2, 0, 0, 0, 0, 1]), WiphyCaps::default(), Arc::new(NoOps));
    registry::register(w).unwrap()
}

#[test]
fn a_registered_radio_is_named_after_its_index_and_can_be_renamed() {
    let w = radio();
    let original = alloc::format!("phy{}", w.index);
    assert_eq!(w.name(), original);
    assert!(w.is_named(&original));
    assert!(registry::lookup_by_name(&original).is_some());

    let renamed = alloc::format!("wl-{}", w.index);
    w.set_name(&renamed);
    assert_eq!(w.name(), renamed);
    assert!(w.is_named(&renamed));
    assert!(!w.is_named(&original));
    // The registry finds it under the new name and not the old one.
    let found = registry::lookup_by_name(&renamed).expect("renamed radio is findable");
    assert_eq!(found.index, w.index);
    assert!(registry::lookup_by_name(&original).is_none());
    let _ = registry::unregister(w.index);
}

#[test]
fn a_rename_moves_the_generation_so_a_dump_reader_can_tell() {
    let w = radio();
    let before = w.generation();
    w.set_name("renamed-radio");
    assert_ne!(w.generation(), before);
    let _ = registry::unregister(w.index);
}

#[test]
fn two_radios_get_different_names_and_the_lowest_free_index() {
    let a = radio();
    let b = radio();
    assert_ne!(a.index, b.index);
    assert_ne!(a.name(), b.name());
    let freed = a.index;
    let _ = registry::unregister(a.index);
    // The vacated number is reused, which is what `phy<n>` numbering does.
    let c = radio();
    assert_eq!(c.index, freed);
    let _ = registry::unregister(b.index);
    let _ = registry::unregister(c.index);
}

fn iface() -> Arc<Wdev> {
    Arc::new(Wdev::new(1, 0, crate::uapi::enums::IfType::Ap,
                       alloc::string::String::from("wlan0"), MacAddr([2, 0, 0, 0, 0, 9])))
}

#[test]
fn a_beacon_parameter_a_request_omits_is_left_alone() {
    // The whole reason the request type is a set of options: a request that
    // turns protection on must not silently turn the preamble setting off.
    let mut params = BssParams { cts_protection: true, short_preamble: true,
                                 short_slot_time: true, ap_isolate: true,
                                 basic_rates: alloc::vec![0x82, 0x84],
                                 ht_opmode: Some(0x0007), p2p_ctwindow: Some(5),
                                 p2p_opp_ps: Some(true) };
    let empty = BssParamsRequest::default();
    assert!(empty.is_empty());
    let before = params.clone();
    empty.apply(&mut params);
    assert_eq!(params, before, "a request that names nothing changes nothing");

    let one = BssParamsRequest { cts_protection: Some(false), ..Default::default() };
    assert!(!one.is_empty());
    one.apply(&mut params);
    assert!(!params.cts_protection);
    assert!(params.short_preamble, "the field the request did not name is untouched");
    assert!(params.short_slot_time);
    assert!(params.ap_isolate);
    assert_eq!(params.basic_rates, alloc::vec![0x82, 0x84]);
}

#[test]
fn a_beacon_parameter_set_on_an_interface_reads_back() {
    let d = iface();
    assert_eq!(d.bss(), BssParams::default());
    let req = BssParamsRequest {
        cts_protection: Some(true),
        basic_rates: Some(alloc::vec![0x82, 0x84, 0x8b, 0x96]),
        ht_opmode: Some(0x000d),
        ..Default::default()
    };
    d.with(|w| req.apply(&mut w.bss));
    let got = d.bss();
    assert!(got.cts_protection);
    assert_eq!(got.basic_rates, alloc::vec![0x82, 0x84, 0x8b, 0x96]);
    assert_eq!(got.ht_opmode, Some(0x000d));
    assert!(!got.short_preamble);
    assert_eq!(got.p2p_ctwindow, None);
}

#[test]
fn a_sixty_four_bit_attribute_pads_with_the_namespace_it_is_written_in() {
    // The padding attribute's NUMBER is per-namespace. Writing the top-level
    // number inside a nest emits an attribute the reader interprets as
    // something else, which is why the padding type is a parameter.
    use crate::nl80211::msg;
    use crate::uapi::nested::sta_info;

    let mut out: Vec<u8> = Vec::new();
    msg::put_u64(&mut out, a::WDEV, 0x0102_0304_0506_0708, a::PAD);
    let types: Vec<u16> = attr::parse(&out).map(|x| x.ty).collect();
    assert!(types.contains(&a::WDEV));
    // The value landed and reads back whole.
    let found = attr::find(&out, a::WDEV).unwrap();
    assert_eq!(found.payload.len(), 8);
    assert_eq!(u64::from_ne_bytes(found.payload.try_into().unwrap()),
               0x0102_0304_0506_0708);

    // Written at an odd alignment, the padding attribute appears — and it is
    // the one this namespace uses, not another's.
    let mut nest: Vec<u8> = Vec::new();
    attr::put_u32(&mut nest, sta_info::SIGNAL, 0);
    msg::put_u64(&mut nest, sta_info::RX_BYTES64, 42, sta_info::PAD);
    let types: Vec<u16> = attr::parse(&nest).map(|x| x.ty).collect();
    assert!(types.contains(&sta_info::RX_BYTES64));
    if types.contains(&sta_info::PAD) {
        assert!(!types.contains(&a::PAD),
            "the top-level padding number must not appear inside a nest");
    }
    assert_eq!(u64::from_ne_bytes(
        attr::find(&nest, sta_info::RX_BYTES64).unwrap().payload.try_into().unwrap()), 42);
}
