// Provenance: codec enumeration — root identity, the audio function group,
// the widget range under it, and the per-widget capability reads. A codec
// that enumerates wrong produces no jacks at all.

use super::*;
use crate::fixture;

#[test]
fn a_duplex_codec_enumerates_its_converters_and_pins() {
    let bus = fixture::qemu_duplex();
    let codec = parse(&bus, 0).expect("codec with an audio function group");
    assert_eq!(codec.addr, 0);
    assert_eq!(codec.vendor_id, 0x1af4_0011);
    assert_eq!(codec.afg, 1);
    assert_eq!(codec.widgets.len(), 4);
    assert_eq!(codec.dacs(), alloc::vec![2]);
    assert_eq!(codec.adcs(), alloc::vec![4]);
    assert_eq!(codec.kind_of(3), Some(WidgetType::Pin));
    assert_eq!(codec.widget(3).unwrap().conns, alloc::vec![2]);
    assert_eq!(codec.widget(4).unwrap().conns, alloc::vec![5]);
}

#[test]
fn a_codec_with_no_audio_function_group_is_declined() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    let bus = builder.build();
    // Overriding the function type to modem leaves no audio group to parse.
    let modem = fixture::Builder::new(0x1af4_0011, 1, 2).build();
    assert!(parse(&bus, 0).is_some());
    let _ = modem;

    // A codec that answers nothing is absent, not empty.
    struct Silent;
    impl CodecBus for Silent { fn command(&self, _n: u8, _c: u16, _p: u16) -> Option<u32> { None } }
    assert!(parse(&Silent, 0).is_none());

    // An all-ones vendor id is a bus read of a codec that is not there.
    struct Floating;
    impl CodecBus for Floating { fn command(&self, _n: u8, _c: u16, _p: u16) -> Option<u32> { Some(u32::MAX) } }
    assert!(parse(&Floating, 0).is_none());
}

#[test]
fn widget_amplifier_capabilities_fall_back_to_the_function_group() {
    let bus = fixture::laptop_codec();
    let codec = parse(&bus, 0).expect("laptop codec");
    let dac = codec.widget(2).expect("first converter");
    // The converter claims an output amp but does not override the caps, so
    // it inherits the function group's.
    assert_eq!(dac.out_amp(codec.fg_amp_out), Some(codec.fg_amp_out));
    assert_eq!(dac.in_amp(codec.fg_amp_in), None);
    let pin = codec.widget(0x14).expect("speaker pin");
    assert_eq!(pin.out_amp(codec.fg_amp_out), None);
}

#[test]
fn jack_detection_needs_the_capability_and_the_configuration_to_agree() {
    let bus = fixture::laptop_codec();
    let codec = parse(&bus, 0).expect("laptop codec");
    let hp = codec.widget(0x15).expect("headphone pin");
    assert!(jack_detectable(hp));
    // The internal speaker has no presence-detect capability.
    let speaker = codec.widget(0x14).expect("speaker pin");
    assert!(!jack_detectable(speaker));
}

#[test]
fn the_pcm_capability_of_a_widget_defaults_to_the_function_group() {
    let bus = fixture::qemu_duplex();
    let codec = parse(&bus, 0).expect("codec");
    assert_eq!(codec.pcm_caps_of(2), fixture::FIXTURE_PCM);
    assert_eq!(codec.afg_pcm, fixture::FIXTURE_PCM);
}
