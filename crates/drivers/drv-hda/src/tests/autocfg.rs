// Provenance: the pin-classification rules — which default-device values go
// to which group, the association/sequence ordering, the fixups that promote
// speakers or headphones when there is no line-out, and the input sort.

use super::*;
use crate::defcfg::{DEV_HP_OUT, DEV_LINE_IN, DEV_LINE_OUT, DEV_MIC_IN, DEV_SPEAKER,
                    LOC_FRONT, LOC_INTERNAL, LOC_REAR, PORT_COMPLEX, PORT_FIXED, PORT_NONE};
use crate::fixture::{self, cfg};
use crate::graph;
use crate::widget;

fn parsed(bus: &fixture::FakeCodec) -> AutoCfg {
    parse_pin_defcfg(&graph::parse(bus, 0).expect("codec"))
}

#[test]
fn a_duplex_codec_yields_one_line_out_and_one_capture_source() {
    let cfg = parsed(&fixture::qemu_duplex());
    assert_eq!(cfg.line_out, alloc::vec![3]);
    assert_eq!(cfg.line_out_type, OutType::LineOut);
    assert!(cfg.hp.is_empty());
    assert!(cfg.speaker.is_empty());
    assert_eq!(cfg.inputs.len(), 1);
    assert_eq!(cfg.inputs[0].nid, 5);
    assert_eq!(cfg.inputs[0].itype, InputType::LineIn);
}

#[test]
fn a_laptop_codec_separates_speaker_headphone_and_two_microphones() {
    let cfg = parsed(&fixture::laptop_codec());
    // No line-out at all, so the speakers become the primary output.
    assert_eq!(cfg.line_out, alloc::vec![0x14]);
    assert_eq!(cfg.line_out_type, OutType::Speaker);
    assert_eq!(cfg.hp, alloc::vec![0x15]);
    assert!(cfg.speaker.is_empty());
    assert_eq!(cfg.inputs.len(), 2);
    // Both are microphones, so discovery order breaks the tie.
    assert_eq!(cfg.inputs[0].nid, 0x12);
    assert_eq!(cfg.inputs[0].attr, PinAttr::Internal);
    assert_eq!(cfg.inputs[1].nid, 0x18);
    assert_eq!(cfg.inputs[1].attr, PinAttr::Front);
}

#[test]
fn an_unconnected_pin_is_ignored_entirely() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    builder.pin(3, cfg(DEV_LINE_OUT, PORT_NONE, LOC_REAR, 1, 0), widget::PINCAP_OUT, &[2]);
    let parsed_cfg = parsed(&builder.build());
    assert!(parsed_cfg.line_out.is_empty());
    assert!(parsed_cfg.inputs.is_empty());
}

#[test]
fn line_outs_sort_by_sequence_within_one_association() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    builder.dac(3);
    builder.dac(4);
    // Declared out of order, and one in a different association group.
    builder.pin(0x10, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 2), widget::PINCAP_OUT, &[4]);
    builder.pin(0x11, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 0), widget::PINCAP_OUT, &[2]);
    builder.pin(0x12, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 1), widget::PINCAP_OUT, &[3]);
    builder.pin(0x13, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 2, 0), widget::PINCAP_OUT, &[2]);
    let parsed_cfg = parsed(&builder.build());
    // Association 2 is dropped; the rest sort front, then the swapped pair.
    assert_eq!(parsed_cfg.line_out.len(), 3);
    assert_eq!(parsed_cfg.line_out[0], 0x11);
    // Three outputs are reordered from HDA's front/CLFE/surround to ALSA's.
    assert_eq!(parsed_cfg.line_out[1], 0x10);
    assert_eq!(parsed_cfg.line_out[2], 0x12);
}

#[test]
fn a_line_out_in_association_zero_never_joins_the_group() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    builder.pin(3, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 0, 0), widget::PINCAP_OUT, &[2]);
    assert!(parsed(&builder.build()).line_out.is_empty());
}

#[test]
fn several_headphone_jacks_and_no_line_out_become_the_line_out_group() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    builder.dac(3);
    builder.pin(0x10, cfg(DEV_HP_OUT, PORT_COMPLEX, LOC_REAR, 1, 0), widget::PINCAP_OUT, &[2]);
    builder.pin(0x11, cfg(DEV_HP_OUT, PORT_COMPLEX, LOC_REAR, 1, 1), widget::PINCAP_OUT, &[3]);
    let parsed_cfg = parsed(&builder.build());
    assert_eq!(parsed_cfg.line_out, alloc::vec![0x10, 0x11]);
    assert!(parsed_cfg.hp.is_empty());
    assert_eq!(parsed_cfg.line_out_type, OutType::Headphone);
}

#[test]
fn a_sequence_of_fifteen_marks_a_jack_that_stays_a_headphone() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    builder.dac(3);
    builder.pin(0x10, cfg(DEV_HP_OUT, PORT_COMPLEX, LOC_REAR, 1, 0xf), widget::PINCAP_OUT, &[2]);
    builder.pin(0x11, cfg(DEV_HP_OUT, PORT_COMPLEX, LOC_REAR, 1, 1), widget::PINCAP_OUT, &[3]);
    let parsed_cfg = parsed(&builder.build());
    assert_eq!(parsed_cfg.line_out, alloc::vec![0x11]);
    assert_eq!(parsed_cfg.hp, alloc::vec![0x10]);
    assert_eq!(parsed_cfg.line_out_type, OutType::LineOut);
}

#[test]
fn a_pin_whose_capabilities_contradict_its_configuration_is_dropped() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    // Declared a line-out but the pin can only take input.
    builder.pin(3, cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 0), widget::PINCAP_IN, &[2]);
    assert!(parsed(&builder.build()).line_out.is_empty());
}

#[test]
fn inputs_sort_microphone_first_then_boosted_then_discovery_order() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.adc(2, &[0x10]);
    builder.pin(0x10, cfg(DEV_LINE_IN, PORT_COMPLEX, LOC_REAR, 1, 0), widget::PINCAP_IN, &[]);
    builder.pin(0x11, cfg(DEV_MIC_IN, PORT_COMPLEX, LOC_REAR, 2, 0), widget::PINCAP_IN, &[]);
    builder.pin(0x12, cfg(DEV_MIC_IN, PORT_FIXED, LOC_INTERNAL, 3, 0), widget::PINCAP_IN, &[]);
    let parsed_cfg = parsed(&builder.build());
    let order: alloc::vec::Vec<u8> = parsed_cfg.inputs.iter().map(|input| input.nid).collect();
    assert_eq!(order, alloc::vec![0x11, 0x12, 0x10]);
}

#[test]
fn speakers_are_preferred_over_headphones_when_there_is_no_line_out() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.dac(2);
    builder.dac(3);
    builder.pin(0x14, cfg(DEV_SPEAKER, PORT_FIXED, LOC_INTERNAL, 1, 0), widget::PINCAP_OUT, &[2]);
    builder.pin(0x15, cfg(DEV_HP_OUT, PORT_COMPLEX, LOC_FRONT, 2, 0), widget::PINCAP_OUT, &[3]);
    let parsed_cfg = parsed(&builder.build());
    assert_eq!(parsed_cfg.line_out, alloc::vec![0x14]);
    assert_eq!(parsed_cfg.line_out_type, OutType::Speaker);
    assert_eq!(parsed_cfg.hp, alloc::vec![0x15]);
    assert_eq!(all_output_pins(&parsed_cfg), alloc::vec![0x14, 0x15]);
}
