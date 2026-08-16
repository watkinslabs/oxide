// Provenance: the route search — a direct connection beats a longer route,
// converters and pins are endpoints rather than transit nodes, the depth is
// bounded, and the widget nearest the jack owns the volume and the mute.

use super::*;
use crate::defcfg::{DEV_LINE_OUT, LOC_REAR, PORT_COMPLEX};
use crate::fixture::{self, cfg};
use crate::graph::{self, Codec};
use crate::widget;

fn codec(bus: &fixture::FakeCodec) -> Codec { graph::parse(bus, 0).expect("codec") }

#[test]
fn a_direct_connection_is_found_and_records_its_selector_index() {
    let c = codec(&fixture::qemu_duplex());
    let path = find(&c, Source::Nid(2), 3, &[]).expect("route from converter to pin");
    assert_eq!(path.source(), Some(2));
    assert_eq!(path.sink(), Some(3));
    assert_eq!(path.len(), 2);
    assert_eq!(path.hops[1].sel, Some(0));
    // A single-connection pin needs no explicit selection.
    assert!(!path.hops[1].multi);
}

#[test]
fn an_unused_converter_search_skips_the_ones_already_claimed() {
    let c = codec(&fixture::laptop_codec());
    let first = find(&c, Source::UnusedDac, 0x14, &[]).expect("route to the speaker");
    assert_eq!(first.source(), Some(2));
    // With converter 2 claimed the speaker pin has nothing else feeding it.
    assert!(find(&c, Source::UnusedDac, 0x14, &[2]).is_none());
    let hp = find(&c, Source::UnusedDac, 0x15, &[2]).expect("route to the headphone");
    assert_eq!(hp.source(), Some(3));
}

#[test]
fn a_route_runs_through_a_selector_and_marks_it_for_selection() {
    let c = codec(&fixture::laptop_codec());
    let path = find(&c, Source::Nid(0x18), 0x08, &[]).expect("route from the external mic");
    // Pin 0x18 -> selector 0x22 -> converter 0x08.
    assert_eq!(path.source(), Some(0x18));
    assert_eq!(path.sink(), Some(0x08));
    assert_eq!(path.len(), 3);
    let selector = path.hops[1];
    assert_eq!(selector.nid, 0x22);
    // The selector has two inputs, so the index has to be written to it.
    assert!(selector.multi);
    assert_eq!(selector.sel, Some(1));
}

#[test]
fn a_route_never_transits_another_converter_or_pin() {
    // Pin 0x11 lists pin 0x10 as a source; the search must not walk through
    // it to reach the converter behind it.
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    builder.pin(0x10, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 0), widget::PINCAP_OUT, &[2]);
    builder.pin(0x11, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 1), widget::PINCAP_OUT, &[0x10]);
    let c = codec(&builder.build());
    assert!(find(&c, Source::Nid(2), 0x11, &[]).is_none());
    assert!(reachable(&c, 2, 0x10));
    assert!(!reachable(&c, 2, 0x11));
}

#[test]
fn a_chain_longer_than_the_depth_limit_is_refused() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    // A chain of mixers from 0x20 upward, each feeding the next.
    let mut previous = 2u8;
    for step in 0..(MAX_PATH_DEPTH as u8 + 2) {
        let nid = 0x20 + step;
        builder.mixer(nid, &[previous]);
        previous = nid;
    }
    builder.pin(0x60, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 0), widget::PINCAP_OUT, &[previous]);
    let c = codec(&builder.build());
    assert!(find(&c, Source::Nid(2), 0x60, &[]).is_none());
    // A shorter tail of the same chain is still reachable.
    assert!(reachable(&c, 2, 0x24));
}

#[test]
fn the_widget_nearest_the_jack_owns_the_volume_and_the_mute() {
    let c = codec(&fixture::qemu_duplex());
    let path = find(&c, Source::Nid(2), 3, &[]).expect("route");
    // Only the converter has an output amplifier here, so it owns both.
    assert_eq!(volume_nid(&c, &path), Some(2));
    assert_eq!(mute_nid(&c, &path), Some((2, true)));
}

#[test]
fn a_route_with_no_amplifier_anywhere_owns_no_control() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    // A converter with no amplifier at all.
    builder.selector(2, &[]);
    builder.pin(3, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 0), widget::PINCAP_OUT, &[2]);
    let c = codec(&builder.build());
    let path = find(&c, Source::Nid(2), 3, &[]).expect("route");
    assert_eq!(volume_nid(&c, &path), None);
    assert_eq!(mute_nid(&c, &path), None);
}

#[test]
fn a_source_that_is_already_the_sink_is_a_one_hop_route() {
    let c = codec(&fixture::qemu_duplex());
    let path = find(&c, Source::Nid(3), 3, &[]).expect("degenerate route");
    assert_eq!(path.len(), 1);
    assert_eq!(path.source(), Some(3));
    assert!(path.contains(3));
    assert!(!path.is_empty());
}
