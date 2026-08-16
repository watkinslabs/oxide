use super::*;
use crate::uapi::hci::{HCI_ACLDATA_PKT, HCI_COMMAND_PKT, HCI_EVENT_PKT};
use crate::uapi::hci_cmd::{opcode_pack, HCI_OP_RESET};
use crate::uapi::hci_evt::{HCI_EV_CMD_COMPLETE, HCI_EV_LE_META};

// A socket that received everything by default would leak another process's
// traffic, so a fresh filter passes nothing.
#[test]
fn a_fresh_filter_passes_nothing() {
    let f = Filter::new();
    assert!(!f.passes(HCI_EVENT_PKT, HCI_EV_CMD_COMPLETE as u16));
    assert!(!f.passes(HCI_ACLDATA_PKT, 0));
    assert!(!f.passes_type(HCI_COMMAND_PKT));
}

#[test]
fn a_pass_all_filter_passes_every_type_and_event() {
    let f = Filter::pass_all();
    for t in [HCI_COMMAND_PKT, HCI_ACLDATA_PKT, HCI_EVENT_PKT] { assert!(f.passes_type(t)); }
    for e in 0..=63u8 { assert!(f.passes_event(e)); }
}

#[test]
fn the_type_mask_screens_by_packet_type() {
    let mut f = Filter::new();
    f.type_mask = 1 << HCI_EVENT_PKT;
    assert!(f.passes_type(HCI_EVENT_PKT));
    assert!(!f.passes_type(HCI_ACLDATA_PKT));
}

// The event mask covers sixty-four codes across two words; the second word
// holds codes 32 and up.
#[test]
fn the_event_mask_spans_two_words() {
    let mut f = Filter::pass_all();
    f.event_mask = [0, 0];
    f.event_mask[0] = 1 << HCI_EV_CMD_COMPLETE;
    assert!(f.passes_event(HCI_EV_CMD_COMPLETE));
    assert!(!f.passes_event(HCI_EV_LE_META));
    f.event_mask[1] = 1 << (HCI_EV_LE_META - 32);
    assert!(f.passes_event(HCI_EV_LE_META));
}

// A mask is a mask, not a modulus. An event code past the mask's width must
// FAIL the screen, not wrap onto an unrelated bit — wrapping is the difference
// between a socket seeing nothing and a socket seeing the wrong traffic.
#[test]
fn an_event_code_past_the_mask_width_fails_rather_than_wrapping() {
    let mut f = Filter::pass_all();
    f.event_mask = [1, 0];
    // Code 64 would wrap onto word 0 bit 0 under a modulus.
    assert!(!f.passes_event(64));
    assert!(!f.passes_event(255));
    assert!(f.passes_event(0));
}

#[test]
fn a_packet_type_past_the_mask_width_fails_rather_than_wrapping() {
    let f = Filter::pass_all();
    assert!(!f.passes_type(32));
    assert!(!f.passes_type(0xff));
    assert!(f.passes_type(31));
}

// A filter naming no command passes every command; naming one screens on both
// halves of the opcode.
#[test]
fn a_zero_opcode_passes_every_command() {
    let mut f = Filter::pass_all();
    f.opcode = 0;
    assert!(f.passes(HCI_COMMAND_PKT, HCI_OP_RESET));
    assert!(f.passes(HCI_COMMAND_PKT, opcode_pack(8, 1)));
}

#[test]
fn a_named_opcode_screens_out_every_other_command() {
    let mut f = Filter::pass_all();
    f.opcode = HCI_OP_RESET;
    assert!(f.passes(HCI_COMMAND_PKT, HCI_OP_RESET));
    assert!(!f.passes(HCI_COMMAND_PKT, opcode_pack(8, 1)));
    // Same command index in a different group is a different command.
    assert!(!f.passes(HCI_COMMAND_PKT, opcode_pack(8, crate::uapi::hci_cmd::opcode_ocf(HCI_OP_RESET))));
}

// The typed screens apply only to their own packet type; everything else is
// decided by the type mask alone.
#[test]
fn the_event_screen_does_not_apply_to_data_packets() {
    let mut f = Filter::pass_all();
    f.event_mask = [0, 0];
    assert!(!f.passes(HCI_EVENT_PKT, HCI_EV_CMD_COMPLETE as u16));
    assert!(f.passes(HCI_ACLDATA_PKT, 0x1234));
}

#[test]
fn the_type_screen_runs_before_the_event_screen() {
    let mut f = Filter::pass_all();
    f.type_mask = 0;
    assert!(!f.passes(HCI_EVENT_PKT, HCI_EV_CMD_COMPLETE as u16));
}

#[test]
fn a_filter_round_trips_through_its_abi_form() {
    let f = Filter { type_mask: 0xdead_beef, event_mask: [0x1234_5678, 0x9abc_def0], opcode: HCI_OP_RESET };
    assert_eq!(Filter::from_wire(&f.to_wire()).unwrap(), f);
}

#[test]
fn a_short_filter_buffer_is_refused() {
    assert!(Filter::from_wire(&[0u8; 13]).is_none());
    assert!(Filter::from_wire(&[0u8; 14]).is_some());
}
