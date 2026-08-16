// Provenance: ALSA mixer control names. `alsamixer` and desktop volume
// sliders find controls by these exact strings, so a renamed control is a
// silently missing one.

use super::*;
use crate::autocfg::AutoCfg;

fn plan_with(line_out: alloc::vec::Vec<u8>, hp: alloc::vec::Vec<u8>,
             speaker: alloc::vec::Vec<u8>, out_type: OutType) -> Plan {
    Plan {
        cfg: AutoCfg { line_out, hp, speaker, line_out_type: out_type, ..AutoCfg::default() },
        ..Plan::default()
    }
}

#[test]
fn a_single_output_card_names_its_control_master() {
    let plan = plan_with(alloc::vec![3], alloc::vec![], alloc::vec![], OutType::LineOut);
    assert_eq!(line_out_prefix(&plan, 0), b"Master");
    assert_eq!(playback_volume(b"Master"), b"Master Playback Volume".to_vec());
    assert_eq!(playback_switch(b"Master"), b"Master Playback Switch".to_vec());
}

#[test]
fn a_card_with_a_second_output_group_names_the_primary_by_its_kind() {
    let speaker = plan_with(alloc::vec![0x14], alloc::vec![0x15], alloc::vec![], OutType::Speaker);
    assert_eq!(line_out_prefix(&speaker, 0), b"Speaker");
    let line = plan_with(alloc::vec![3], alloc::vec![4], alloc::vec![], OutType::LineOut);
    assert_eq!(line_out_prefix(&line, 0), b"Line Out");
    let headphone = plan_with(alloc::vec![3], alloc::vec![], alloc::vec![4], OutType::Headphone);
    assert_eq!(line_out_prefix(&headphone, 0), b"Headphone");
}

#[test]
fn a_two_speaker_card_names_the_second_one_bass() {
    let plan = plan_with(alloc::vec![0x14, 0x16], alloc::vec![0x15], alloc::vec![], OutType::Speaker);
    assert_eq!(line_out_prefix(&plan, 0), b"Speaker");
    assert_eq!(line_out_prefix(&plan, 1), b"Bass Speaker");
    assert_eq!(extra_out_prefix(b"Speaker", 2, 1), b"Bass Speaker");
    assert_eq!(extra_out_prefix(b"Speaker", 2, 0), b"Speaker");
    assert_eq!(extra_out_prefix(b"Headphone", 2, 1), b"Headphone");
}

#[test]
fn multi_channel_outputs_use_the_alsa_channel_names() {
    let plan = plan_with(alloc::vec![1, 2, 3, 4], alloc::vec![], alloc::vec![], OutType::LineOut);
    assert_eq!(line_out_prefix(&plan, 0), b"Front");
    assert_eq!(line_out_prefix(&plan, 1), b"Surround");
    assert_eq!(line_out_prefix(&plan, 2), b"CLFE");
    assert_eq!(line_out_prefix(&plan, 3), b"Side");
}

#[test]
fn capture_and_jack_names_match_the_control_abi() {
    assert_eq!(tidy(capture_volume()), b"Capture Volume".to_vec());
    assert_eq!(tidy(capture_switch()), b"Capture Switch".to_vec());
    assert_eq!(tidy(capture_source()), b"Capture Source".to_vec());
    assert_eq!(tidy(jack_name(b"Headphone")), b"Headphone Jack".to_vec());
}

#[test]
fn a_name_longer_than_the_element_field_is_truncated_not_overflowed() {
    let long = [b'x'; 100];
    let name = playback_volume(&long);
    assert_eq!(name.len(), NAME_CAP);
}

#[test]
fn microphone_labels_only_carry_a_location_when_two_of_them_differ() {
    use crate::autocfg::{InputPin, InputType};
    use crate::defcfg::PinAttr;
    let internal = InputPin { nid: 0x12, itype: InputType::Mic, attr: PinAttr::Internal, boost: false, order: 0 };
    let front = InputPin { nid: 0x18, itype: InputType::Mic, attr: PinAttr::Front, boost: false, order: 1 };
    let line = InputPin { nid: 0x1a, itype: InputType::LineIn, attr: PinAttr::Rear, boost: false, order: 2 };
    assert!(inputs_need_location(&[internal, front]));
    assert!(!inputs_need_location(&[internal]));
    assert!(!inputs_need_location(&[internal, line]));
    assert_eq!(input_label(&internal, true), b"Internal Mic");
    assert_eq!(input_label(&internal, false), b"Mic");
    assert_eq!(input_label(&front, true), b"Front Mic");
    assert_eq!(input_label(&line, true), b"Line");
}
