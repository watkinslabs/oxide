// Provenance: which mixer and jack controls a routing plan publishes, and
// the private key each one carries back to its amplifier. A control named
// wrong is a control userspace cannot find.

use super::*;
use alloc::vec;
use crate::fixture;
use crate::generic;
use crate::graph;

fn controls_of(bus: &fixture::FakeCodec) -> Controls {
    let codec = graph::parse(bus, 0).expect("codec");
    let plan = generic::build(&codec);
    describe(&codec, &plan)
}

fn names(controls: &Controls) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    let mut out: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    for amp in controls.amps.iter() {
        if !amp.volume_name.is_empty() { out.push(amp.volume_name.clone()); }
        if amp.caps.mute { out.push(amp.switch_name.clone()); }
    }
    for jack in controls.jacks.iter() { out.push(jack.name.clone()); }
    out
}

#[test]
fn the_private_key_round_trips_node_direction_and_kind() {
    for kind in [ElemKind::Volume, ElemKind::Switch, ElemKind::Jack, ElemKind::CaptureSource,
                 ElemKind::MasterVolume, ElemKind::MasterSwitch] {
        for output in [true, false] {
            assert_eq!(unpack(pack(0x14, output, kind)), (0x14, output, kind));
        }
    }
    // A node id of 0x7f is the widest the field carries.
    assert_eq!(unpack(pack(0x7f, true, ElemKind::Volume)), (0x7f, true, ElemKind::Volume));
}

#[test]
fn a_single_output_codec_publishes_a_master_control_pair() {
    let controls = controls_of(&fixture::qemu_duplex());
    let published = names(&controls);
    assert!(published.contains(&b"Master Playback Volume".to_vec()));
    assert!(published.contains(&b"Master Playback Switch".to_vec()));
    // The capture converter's input amplifier becomes the capture pair.
    assert!(published.contains(&b"Capture Volume".to_vec()));
    assert!(published.contains(&b"Capture Switch".to_vec()));
}

#[test]
fn a_laptop_codec_publishes_speaker_headphone_and_a_headphone_jack() {
    let controls = controls_of(&fixture::laptop_codec());
    let published = names(&controls);
    assert!(published.contains(&b"Speaker Playback Volume".to_vec()));
    assert!(published.contains(&b"Headphone Playback Volume".to_vec()));
    assert!(published.contains(&b"Headphone Jack".to_vec()));
    // The internal speaker has no presence detect, so it gets no jack.
    assert!(!published.contains(&b"Speaker Jack".to_vec()));
    assert_eq!(controls.capture_sources, vec![b"Internal Mic".to_vec(), b"Front Mic".to_vec()]);
    assert!(controls.master.is_some());
}

#[test]
fn every_amplifier_control_points_at_the_widget_that_owns_it() {
    let controls = controls_of(&fixture::laptop_codec());
    let speaker = controls.amps.iter()
        .find(|amp| amp.volume_name == b"Speaker Playback Volume".to_vec())
        .expect("speaker volume");
    // The converter behind the speaker pin is node 2.
    assert_eq!(speaker.nid, 2);
    assert!(speaker.output);
    assert_eq!(unpack(pack(speaker.nid, speaker.output, ElemKind::Volume)).0, 2);
    let capture = controls.amps.iter()
        .find(|amp| amp.volume_name == b"Capture Volume".to_vec())
        .expect("capture volume");
    // A capture control lives on the converter's input amplifier.
    assert!(!capture.output);
}

#[test]
fn a_codec_with_no_amplifiers_publishes_no_mixer_controls() {
    let mut builder = fixture::Builder::new(0x1af4_0011, 1, 2);
    builder.selector(2, &[]);
    builder.pin(3, fixture::cfg(crate::defcfg::DEV_LINE_OUT, crate::defcfg::PORT_COMPLEX,
                                crate::defcfg::LOC_REAR, 1, 0),
                crate::widget::PINCAP_OUT, &[2]);
    let controls = controls_of(&builder.build());
    assert!(controls.amps.is_empty());
}

#[test]
fn the_amplifier_range_carried_into_a_control_is_the_codecs_own() {
    let controls = controls_of(&fixture::qemu_duplex());
    let master = controls.amps.iter()
        .find(|amp| amp.volume_name == b"Master Playback Volume".to_vec())
        .expect("master volume");
    assert_eq!(master.caps.num_steps, 0x4a);
    assert_eq!(master.caps.step_centibel, 75);
    assert!(master.caps.mute);
    assert_eq!(crate::widget::amp_min_centibel(&master.caps), -(0x27 * 75));
}
