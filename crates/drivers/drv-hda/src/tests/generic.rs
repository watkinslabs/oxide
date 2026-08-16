// Provenance: converter assignment and its scoring. A codec with no
// vendor-specific handling must still come out of this with a playable
// route, a capture route, and a control owner for each.

use super::*;
use crate::defcfg::{DEV_HP_OUT, DEV_LINE_OUT, DEV_SPEAKER, LOC_FRONT, LOC_INTERNAL, LOC_REAR,
                    PORT_COMPLEX, PORT_FIXED};
use crate::fixture::{self, cfg};
use crate::graph;
use crate::widget;

fn plan_of(bus: &fixture::FakeCodec) -> Plan {
    build(&graph::parse(bus, 0).expect("codec"))
}

#[test]
fn a_duplex_codec_gets_a_playback_and_a_capture_route_with_no_penalty() {
    let plan = plan_of(&fixture::qemu_duplex());
    assert_eq!(plan.badness, 0);
    let out = plan.primary().expect("playback route");
    assert_eq!(out.pin, 3);
    assert_eq!(out.dac, 2);
    assert!(!out.shared);
    assert_eq!(out.volume, Some(2));
    assert_eq!(out.mute, Some((2, true)));
    let capture = plan.primary_capture().expect("capture route");
    assert_eq!(capture.pin, 5);
    assert_eq!(capture.adc, 4);
}

#[test]
fn a_laptop_codec_drives_the_speaker_and_the_headphone_from_separate_converters() {
    let plan = plan_of(&fixture::laptop_codec());
    assert_eq!(plan.badness, 0);
    assert_eq!(plan.outputs.len(), 1);
    assert_eq!(plan.outputs[0].pin, 0x14);
    assert_eq!(plan.outputs[0].dac, 2);
    assert_eq!(plan.hp.len(), 1);
    assert_eq!(plan.hp[0].pin, 0x15);
    assert_eq!(plan.hp[0].dac, 3);
    assert!(!plan.hp[0].shared);
    assert_eq!(plan.all_outputs().count(), 2);
    assert_eq!(plan.captures.len(), 2);
}

#[test]
fn two_jacks_behind_one_converter_share_it_and_are_charged_for_it() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    builder.pin(0x14, cfg(DEV_SPEAKER, PORT_FIXED, LOC_INTERNAL, 1, 0), widget::PINCAP_OUT, &[2]);
    builder.pin(0x15, cfg(DEV_HP_OUT, PORT_COMPLEX, LOC_FRONT, 2, 0), widget::PINCAP_OUT, &[2]);
    let plan = plan_of(&builder.build());
    assert_eq!(plan.outputs[0].dac, 2);
    assert!(!plan.outputs[0].shared);
    assert_eq!(plan.hp.len(), 1);
    assert!(plan.hp[0].shared);
    assert_eq!(plan.hp[0].dac, 2);
    assert!(plan.badness >= EXTRA_OUT_BADNESS.shared_primary);
}

#[test]
fn a_pin_with_exactly_one_possible_converter_claims_it_before_the_greedy_pass() {
    // Converter 2 can reach both pins; converter 3 only reaches 0x15. The
    // greedy order would give 2 to 0x14 first, so the forced pairing has to
    // be made ahead of it for both pins to get their own converter.
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    builder.dac(3);
    builder.pin(0x14, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 0), widget::PINCAP_OUT, &[2]);
    builder.pin(0x15, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 1), widget::PINCAP_OUT, &[2, 3]);
    let plan = plan_of(&builder.build());
    assert_eq!(plan.outputs.len(), 2);
    assert_eq!(plan.outputs[0].dac, 2);
    assert_eq!(plan.outputs[1].dac, 3);
    assert!(plan.outputs.iter().all(|route| !route.shared));
    assert_eq!(plan.badness, 0);
}

#[test]
fn an_output_pin_no_converter_can_reach_is_scored_not_silently_dropped() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    builder.pin(0x14, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 0), widget::PINCAP_OUT, &[2]);
    // A second line-out fed by nothing at all.
    builder.pin(0x15, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 1), widget::PINCAP_OUT, &[]);
    let plan = plan_of(&builder.build());
    assert_eq!(plan.outputs.len(), 1);
    assert!(plan.badness >= MAIN_OUT_BADNESS.no_dac);
}

#[test]
fn a_codec_with_no_output_pins_produces_an_empty_plan_rather_than_a_wrong_one() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    let plan = plan_of(&builder.build());
    assert!(plan.primary().is_none());
    assert!(plan.primary_capture().is_none());
    assert_eq!(plan.badness, 0);
}

#[test]
fn control_ownership_is_claimed_once_per_widget() {
    // Both pins hang off the same converter, so only the first route can own
    // that converter's volume; the second is left without one.
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    builder.pin(0x14, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 0), widget::PINCAP_OUT, &[2]);
    builder.pin(0x15, cfg(DEV_HP_OUT, PORT_COMPLEX, LOC_FRONT, 2, 0), widget::PINCAP_OUT, &[2]);
    let plan = plan_of(&builder.build());
    assert_eq!(plan.outputs[0].volume, Some(2));
    assert_eq!(plan.hp[0].volume, None);
    assert_eq!(plan.hp[0].mute, None);
}
