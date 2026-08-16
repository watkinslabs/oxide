use super::*;
use crate::hci::packet::build_frame;
use crate::uapi::hci_mon::{HCI_MON_HDR_SIZE, HCI_MON_NEW_INDEX_SIZE};

#[test]
fn a_record_header_carries_opcode_index_and_length() {
    let r = record(HCI_MON_EVENT_PKT, 0, &[1, 2, 3]).unwrap();
    assert_eq!(r.len(), HCI_MON_HDR_SIZE + 3);
    assert_eq!(parse_header(&r).unwrap(), (HCI_MON_EVENT_PKT, 0, 3));
    assert_eq!(&r[HCI_MON_HDR_SIZE..], &[1, 2, 3]);
}

// The prefix byte is redundant once the record opcode has named the kind, and a
// trace carrying both would decode one byte off.
#[test]
fn a_frame_record_drops_the_packet_type_prefix() {
    let frame = build_frame(crate::uapi::hci::HCI_EVENT_PKT, 0x0e, &[1, 2]).unwrap();
    let r = frame_record(3, &frame, Dir::Rx).unwrap();
    let (opcode, index, len) = parse_header(&r).unwrap();
    assert_eq!(opcode, HCI_MON_EVENT_PKT);
    assert_eq!(index, 3);
    assert_eq!(len as usize, frame.len() - 1);
    assert_eq!(&r[HCI_MON_HDR_SIZE..], &frame[1..]);
}

// Data packets carry a direction; commands and events do not, because their
// direction is implied by what they are.
#[test]
fn data_packets_select_a_directional_opcode() {
    use crate::uapi::hci::{HCI_ACLDATA_PKT, HCI_SCODATA_PKT};
    assert_eq!(opcode_for(HCI_ACLDATA_PKT, Dir::Tx), Some(HCI_MON_ACL_TX_PKT));
    assert_eq!(opcode_for(HCI_ACLDATA_PKT, Dir::Rx), Some(HCI_MON_ACL_RX_PKT));
    assert_eq!(opcode_for(HCI_SCODATA_PKT, Dir::Tx), Some(HCI_MON_SCO_TX_PKT));
    assert_eq!(opcode_for(HCI_SCODATA_PKT, Dir::Rx), Some(HCI_MON_SCO_RX_PKT));
}

#[test]
fn commands_and_events_carry_one_opcode_in_both_directions() {
    use crate::uapi::hci::{HCI_COMMAND_PKT, HCI_EVENT_PKT};
    assert_eq!(opcode_for(HCI_COMMAND_PKT, Dir::Tx), opcode_for(HCI_COMMAND_PKT, Dir::Rx));
    assert_eq!(opcode_for(HCI_EVENT_PKT, Dir::Tx), opcode_for(HCI_EVENT_PKT, Dir::Rx));
    assert_eq!(opcode_for(HCI_COMMAND_PKT, Dir::Tx), Some(HCI_MON_COMMAND_PKT));
}

#[test]
fn an_unframed_packet_type_has_no_monitor_opcode() {
    assert_eq!(opcode_for(0x77, Dir::Tx), None);
    assert!(frame_record(0, &[0x77, 1, 2], Dir::Tx).is_none());
}

// The name field is fixed width and NOT necessarily terminated: a name that
// exactly fills it has no terminator, and a longer one is cut to the width.
#[test]
fn a_new_index_name_is_bounded_by_the_field_width() {
    let p = new_index_payload(0, crate::uapi::hci::HCI_VIRTUAL, BdAddr([1, 2, 3, 4, 5, 6]), "verylongname");
    assert_eq!(p.len(), HCI_MON_NEW_INDEX_SIZE);
    assert_eq!(&p[8..16], b"verylong");
    assert_eq!(&p[2..8], &[1, 2, 3, 4, 5, 6]);
    assert_eq!(p[1], crate::uapi::hci::HCI_VIRTUAL);
}

#[test]
fn a_short_new_index_name_leaves_the_rest_of_the_field_zero() {
    let p = new_index_payload(0, 0, BdAddr::default(), "hci0");
    assert_eq!(&p[8..12], b"hci0");
    assert_eq!(&p[12..16], &[0, 0, 0, 0]);
}

#[test]
fn an_index_info_payload_carries_the_address_then_the_manufacturer() {
    let p = index_info_payload(BdAddr([9, 8, 7, 6, 5, 4]), 0x0002);
    assert_eq!(&p[0..6], &[9, 8, 7, 6, 5, 4]);
    assert_eq!(&p[6..8], &[0x02, 0x00]);
}

#[test]
fn a_short_buffer_has_no_parsable_header() {
    assert!(parse_header(&[0u8; 5]).is_none());
    assert!(parse_header(&[0u8; 6]).is_some());
}
