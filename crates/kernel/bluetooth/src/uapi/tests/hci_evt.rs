use super::*;

// Two events sharing a code would make one decode as the other.
#[test]
fn no_two_event_codes_collide() {
    let all = [HCI_EV_INQUIRY_COMPLETE, HCI_EV_INQUIRY_RESULT, HCI_EV_CONN_COMPLETE,
        HCI_EV_CONN_REQUEST, HCI_EV_DISCONN_COMPLETE, HCI_EV_AUTH_COMPLETE,
        HCI_EV_REMOTE_NAME, HCI_EV_ENCRYPT_CHANGE, HCI_EV_CHANGE_LINK_KEY_COMPLETE,
        HCI_EV_REMOTE_FEATURES, HCI_EV_REMOTE_VERSION, HCI_EV_QOS_SETUP_COMPLETE,
        HCI_EV_CMD_COMPLETE, HCI_EV_CMD_STATUS, HCI_EV_HARDWARE_ERROR,
        HCI_EV_ROLE_CHANGE, HCI_EV_NUM_COMP_PKTS, HCI_EV_MODE_CHANGE,
        HCI_EV_PIN_CODE_REQ, HCI_EV_LINK_KEY_REQ, HCI_EV_LINK_KEY_NOTIFY,
        HCI_EV_CLOCK_OFFSET, HCI_EV_PKT_TYPE_CHANGE, HCI_EV_PSCAN_REP_MODE,
        HCI_EV_INQUIRY_RESULT_WITH_RSSI, HCI_EV_REMOTE_EXT_FEATURES,
        HCI_EV_SYNC_CONN_COMPLETE, HCI_EV_SYNC_CONN_CHANGED, HCI_EV_SNIFF_SUBRATE,
        HCI_EV_EXTENDED_INQUIRY_RESULT, HCI_EV_KEY_REFRESH_COMPLETE,
        HCI_EV_IO_CAPA_REQUEST, HCI_EV_IO_CAPA_REPLY, HCI_EV_USER_CONFIRM_REQUEST,
        HCI_EV_USER_PASSKEY_REQUEST, HCI_EV_REMOTE_OOB_DATA_REQUEST,
        HCI_EV_SIMPLE_PAIR_COMPLETE, HCI_EV_USER_PASSKEY_NOTIFY,
        HCI_EV_KEYPRESS_NOTIFY, HCI_EV_REMOTE_HOST_FEATURES, HCI_EV_LE_META,
        HCI_EV_NUM_COMP_BLOCKS, HCI_EV_SYNC_TRAIN_COMPLETE, HCI_EV_VENDOR];
    for (i, e) in all.iter().enumerate() {
        assert!(!all[i + 1..].contains(e), "event {e:#04x} appears twice");
    }
}

#[test]
fn no_two_le_subevent_codes_collide() {
    let all = [HCI_EV_LE_CONN_COMPLETE, HCI_EV_LE_ADVERTISING_REPORT,
        HCI_EV_LE_CONN_UPDATE_COMPLETE, HCI_EV_LE_REMOTE_FEAT_COMPLETE,
        HCI_EV_LE_LTK_REQ, HCI_EV_LE_REMOTE_CONN_PARAM_REQ,
        HCI_EV_LE_DATA_LEN_CHANGE, HCI_EV_LE_ENHANCED_CONN_COMPLETE,
        HCI_EV_LE_DIRECT_ADV_REPORT, HCI_EV_LE_PHY_UPDATE_COMPLETE,
        HCI_EV_LE_EXT_ADV_REPORT, HCI_EV_LE_PA_SYNC_ESTABLISHED,
        HCI_EV_LE_PER_ADV_REPORT, HCI_EV_LE_PA_SYNC_LOST, HCI_EV_LE_EXT_ADV_SET_TERM];
    for (i, e) in all.iter().enumerate() {
        assert!(!all[i + 1..].contains(e), "subevent {e:#04x} appears twice");
    }
}

// A subevent code is a separate namespace from an event code, so the two may
// reuse numbers; the meta event is what distinguishes them.
#[test]
fn the_meta_event_carries_its_own_subevent_namespace() {
    assert_eq!(HCI_EV_LE_META, 0x3e);
    assert_eq!(HCI_EV_LE_CONN_COMPLETE, HCI_EV_INQUIRY_COMPLETE);
}

// The event mask covers only the first sixty-four codes. Every event the core
// acts on is inside it, so a raw socket can select all of them; the codes ABOVE
// it cannot be selected at all, which is why the filter refuses rather than
// wrapping a high code onto a low bit.
#[test]
fn every_event_the_core_acts_on_fits_inside_the_mask_width() {
    for e in [HCI_EV_CMD_COMPLETE, HCI_EV_CMD_STATUS, HCI_EV_LE_META,
        HCI_EV_CONN_COMPLETE, HCI_EV_CONN_REQUEST, HCI_EV_DISCONN_COMPLETE,
        HCI_EV_AUTH_COMPLETE, HCI_EV_ENCRYPT_CHANGE, HCI_EV_NUM_COMP_PKTS,
        HCI_EV_HARDWARE_ERROR] {
        assert!(e as u32 <= HCI_FLT_EVENT_BITS, "event {e:#04x} is past the mask");
    }
}

// The codes past the mask are unselectable. This is the mask width the ABI
// fixes, not a shortfall here — but it means a socket cannot ask for these
// events by filter, and a filter that wrapped would hand it an unrelated one
// instead.
#[test]
fn the_event_codes_past_the_mask_width_are_unselectable() {
    for e in [HCI_EV_SYNC_TRAIN_COMPLETE, HCI_EV_VENDOR] {
        assert!(e as u32 > HCI_FLT_EVENT_BITS, "event {e:#04x} would be selectable");
    }
}

#[test]
fn the_mask_widths_are_one_less_than_a_power_of_two() {
    assert_eq!(HCI_FLT_EVENT_BITS, 63);
    assert_eq!(HCI_FLT_TYPE_BITS, 31);
}

// Each fixed prefix must be at least as long as the fields the decoder reads
// out of it, or a well-formed event would be refused.
#[test]
fn each_fixed_prefix_covers_the_fields_read_from_it() {
    // status, handle word, address, link type, encryption flag.
    assert!(EV_CONN_COMPLETE_LEN >= 1 + 2 + 6 + 1 + 1);
    // address, class of device, link type.
    assert!(EV_CONN_REQUEST_LEN >= 6 + 3 + 1);
    // status, handle word, reason.
    assert!(EV_DISCONN_COMPLETE_LEN >= 1 + 2 + 1);
    // status, handle word, encryption flag.
    assert!(EV_ENCRYPT_CHANGE_LEN >= 1 + 2 + 1);
    // status, handle word.
    assert!(EV_AUTH_COMPLETE_LEN >= 1 + 2);
    // status, credit, opcode word.
    assert_eq!(EV_CMD_STATUS_LEN, 1 + 1 + 2);
    // credit, opcode word, then whatever the command returns.
    assert_eq!(EV_CMD_COMPLETE_MIN, 1 + 2);
    // status, handle word, role, address type, address, then interval fields.
    assert!(EV_LE_CONN_COMPLETE_LEN >= 1 + 2 + 1 + 1 + 6);
    assert_eq!(EV_LE_META_MIN, 1);
}
