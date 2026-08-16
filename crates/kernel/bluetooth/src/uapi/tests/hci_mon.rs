use super::*;

#[test]
fn the_record_header_fields_tile_its_width() {
    assert_eq!(MON_HDR_OPCODE_OFF, 0);
    assert_eq!(MON_HDR_INDEX_OFF, MON_HDR_OPCODE_OFF + 2);
    assert_eq!(MON_HDR_LEN_OFF, MON_HDR_INDEX_OFF + 2);
    assert_eq!(HCI_MON_HDR_SIZE, MON_HDR_LEN_OFF + 2);
}

// Two record kinds sharing an opcode would make a trace reader decode one as
// the other.
#[test]
fn no_two_record_opcodes_collide() {
    let all = [HCI_MON_NEW_INDEX, HCI_MON_DEL_INDEX, HCI_MON_COMMAND_PKT,
        HCI_MON_EVENT_PKT, HCI_MON_ACL_TX_PKT, HCI_MON_ACL_RX_PKT,
        HCI_MON_SCO_TX_PKT, HCI_MON_SCO_RX_PKT, HCI_MON_OPEN_INDEX,
        HCI_MON_CLOSE_INDEX, HCI_MON_INDEX_INFO, HCI_MON_VENDOR_DIAG,
        HCI_MON_SYSTEM_NOTE, HCI_MON_USER_LOGGING, HCI_MON_CTRL_OPEN,
        HCI_MON_CTRL_CLOSE, HCI_MON_CTRL_COMMAND, HCI_MON_CTRL_EVENT,
        HCI_MON_ISO_TX_PKT, HCI_MON_ISO_RX_PKT];
    for (i, o) in all.iter().enumerate() {
        assert!(!all[i + 1..].contains(o), "record opcode {o} appears twice");
    }
}

#[test]
fn the_record_opcodes_are_contiguous_from_zero() {
    let ordered = [HCI_MON_NEW_INDEX, HCI_MON_DEL_INDEX, HCI_MON_COMMAND_PKT,
        HCI_MON_EVENT_PKT, HCI_MON_ACL_TX_PKT, HCI_MON_ACL_RX_PKT,
        HCI_MON_SCO_TX_PKT, HCI_MON_SCO_RX_PKT, HCI_MON_OPEN_INDEX,
        HCI_MON_CLOSE_INDEX, HCI_MON_INDEX_INFO, HCI_MON_VENDOR_DIAG,
        HCI_MON_SYSTEM_NOTE, HCI_MON_USER_LOGGING, HCI_MON_CTRL_OPEN,
        HCI_MON_CTRL_CLOSE, HCI_MON_CTRL_COMMAND, HCI_MON_CTRL_EVENT,
        HCI_MON_ISO_TX_PKT, HCI_MON_ISO_RX_PKT];
    for (i, o) in ordered.iter().enumerate() { assert_eq!(*o, i as u16); }
}

// Each direction pair must be adjacent and distinct, so a trace tells a
// transmitted frame from a received one.
#[test]
fn each_directional_pair_is_two_distinct_adjacent_opcodes() {
    for (tx, rx) in [(HCI_MON_ACL_TX_PKT, HCI_MON_ACL_RX_PKT),
        (HCI_MON_SCO_TX_PKT, HCI_MON_SCO_RX_PKT),
        (HCI_MON_ISO_TX_PKT, HCI_MON_ISO_RX_PKT)] {
        assert_ne!(tx, rx);
        assert_eq!(rx, tx + 1);
    }
}

#[test]
fn the_new_index_payload_fields_tile_its_width() {
    assert_eq!(MON_NEW_INDEX_TYPE_OFF, 0);
    assert_eq!(MON_NEW_INDEX_BUS_OFF, 1);
    assert_eq!(MON_NEW_INDEX_BDADDR_OFF, 2);
    assert_eq!(MON_NEW_INDEX_NAME_OFF, MON_NEW_INDEX_BDADDR_OFF + 6);
    assert_eq!(HCI_MON_NEW_INDEX_SIZE, MON_NEW_INDEX_NAME_OFF + MON_NEW_INDEX_NAME_LEN);
}

#[test]
fn the_index_info_payload_fields_tile_its_width() {
    assert_eq!(MON_INDEX_INFO_BDADDR_OFF, 0);
    assert_eq!(MON_INDEX_INFO_MANUFACTURER_OFF, 6);
    assert_eq!(HCI_MON_INDEX_INFO_SIZE, MON_INDEX_INFO_MANUFACTURER_OFF + 2);
}
