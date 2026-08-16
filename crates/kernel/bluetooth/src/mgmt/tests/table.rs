//! The handler table's shape and its flag assignments.

use super::*;

#[test]
fn slot_zero_is_not_a_command() {
    assert!(lookup(0).is_none());
    assert!(!is_implemented(0));
}

#[test]
fn every_opcode_through_the_last_has_a_handler() {
    for op in 1..=MGMT_OP_MAX {
        assert!(is_implemented(op), "opcode {op:#06x} has no handler");
    }
}

#[test]
fn nothing_past_the_last_opcode_has_one() {
    for op in [MGMT_OP_MAX + 1, MGMT_OP_MAX + 2, 0x1000, u16::MAX] {
        assert!(lookup(op).is_none(), "opcode {op:#06x}");
    }
    assert_eq!(HANDLER_COUNT, MGMT_OP_MAX as usize + 1);
}

#[test]
fn exactly_the_read_commands_are_untrusted_safe() {
    let untrusted: alloc::vec::Vec<u16> =
        (1..=MGMT_OP_MAX).filter(|op| lookup(*op).is_some_and(|s| s.untrusted())).collect();
    assert_eq!(untrusted, alloc::vec![
        MGMT_OP_READ_VERSION,
        MGMT_OP_READ_COMMANDS,
        MGMT_OP_READ_INDEX_LIST,
        MGMT_OP_READ_INFO,
        MGMT_OP_READ_UNCONF_INDEX_LIST,
        MGMT_OP_READ_CONFIG_INFO,
        MGMT_OP_READ_EXT_INDEX_LIST,
        MGMT_OP_READ_EXT_INFO,
        MGMT_OP_READ_CONTROLLER_CAP,
        MGMT_OP_READ_EXP_FEATURES_INFO,
        MGMT_OP_READ_DEF_SYSTEM_CONFIG,
        MGMT_OP_READ_DEF_RUNTIME_CONFIG,
    ]);
}

#[test]
fn exactly_the_stackwide_commands_take_no_controller() {
    let no_hdev: alloc::vec::Vec<u16> =
        (1..=MGMT_OP_MAX).filter(|op| lookup(*op).is_some_and(|s| s.no_hdev())).collect();
    assert_eq!(no_hdev, alloc::vec![
        MGMT_OP_READ_VERSION,
        MGMT_OP_READ_COMMANDS,
        MGMT_OP_READ_INDEX_LIST,
        MGMT_OP_READ_UNCONF_INDEX_LIST,
        MGMT_OP_READ_EXT_INDEX_LIST,
    ]);
}

#[test]
fn exactly_the_configuration_commands_reach_an_unconfigured_controller() {
    let unconf: alloc::vec::Vec<u16> =
        (1..=MGMT_OP_MAX).filter(|op| lookup(*op).is_some_and(|s| s.unconfigured())).collect();
    assert_eq!(unconf, alloc::vec![
        MGMT_OP_READ_CONFIG_INFO,
        MGMT_OP_SET_EXTERNAL_CONFIG,
        MGMT_OP_SET_PUBLIC_ADDRESS,
    ]);
}

#[test]
fn exactly_two_commands_work_with_or_without_a_controller() {
    let opt: alloc::vec::Vec<u16> =
        (1..=MGMT_OP_MAX).filter(|op| lookup(*op).is_some_and(|s| s.hdev_optional())).collect();
    assert_eq!(opt, alloc::vec![MGMT_OP_READ_EXP_FEATURES_INFO, MGMT_OP_SET_EXP_FEATURE]);
}

#[test]
fn the_variable_length_commands_are_the_ones_carrying_a_count_or_a_blob() {
    let var: alloc::vec::Vec<u16> =
        (1..=MGMT_OP_MAX).filter(|op| lookup(*op).is_some_and(|s| s.var_len())).collect();
    assert_eq!(var, alloc::vec![
        MGMT_OP_LOAD_LINK_KEYS,
        MGMT_OP_LOAD_LONG_TERM_KEYS,
        MGMT_OP_ADD_REMOTE_OOB_DATA,
        MGMT_OP_LOAD_IRKS,
        MGMT_OP_LOAD_CONN_PARAM,
        MGMT_OP_START_SERVICE_DISCOVERY,
        MGMT_OP_ADD_ADVERTISING,
        MGMT_OP_SET_BLOCKED_KEYS,
        MGMT_OP_SET_EXP_FEATURE,
        MGMT_OP_SET_DEF_SYSTEM_CONFIG,
        MGMT_OP_SET_DEF_RUNTIME_CONFIG,
        MGMT_OP_ADD_ADV_PATTERNS_MONITOR,
        MGMT_OP_ADD_EXT_ADV_PARAMS,
        MGMT_OP_ADD_EXT_ADV_DATA,
        MGMT_OP_ADD_ADV_PATTERNS_MONITOR_RSSI,
        MGMT_OP_SET_MESH_RECEIVER,
        MGMT_OP_MESH_SEND,
        MGMT_OP_HCI_CMD_SYNC,
    ]);
}

/// Widths that a shared constant would silently equalise.
#[test]
fn declared_widths_match_the_wire_records() {
    let w = |op: u16| lookup(op).expect("handler").data_len as usize;
    assert_eq!(w(MGMT_OP_SET_POWERED), 1);
    assert_eq!(w(MGMT_OP_SET_DISCOVERABLE), 3);
    assert_eq!(w(MGMT_OP_SET_LOCAL_NAME), 260);
    assert_eq!(w(MGMT_OP_DISCONNECT), 7);
    assert_eq!(w(MGMT_OP_PIN_CODE_REPLY), 24);
    assert_eq!(w(MGMT_OP_PAIR_DEVICE), 8);
    assert_eq!(w(MGMT_OP_USER_PASSKEY_REPLY), 11);
    assert_eq!(w(MGMT_OP_ADD_REMOTE_OOB_DATA), 39);
    assert_eq!(w(MGMT_OP_SET_PRIVACY), 17);
    assert_eq!(w(MGMT_OP_ADD_DEVICE), 8);
    assert_eq!(w(MGMT_OP_GET_DEVICE_FLAGS), 7);
    assert_eq!(w(MGMT_OP_SET_DEVICE_FLAGS), 11);
    assert_eq!(w(MGMT_OP_ADD_ADVERTISING), 11);
    assert_eq!(w(MGMT_OP_GET_ADV_SIZE_INFO), 5);
    assert_eq!(w(MGMT_OP_ADD_EXT_ADV_PARAMS), 18);
    assert_eq!(w(MGMT_OP_ADD_ADV_PATTERNS_MONITOR_RSSI), 8);
    assert_eq!(w(MGMT_OP_SET_MESH_RECEIVER), 6);
    assert_eq!(w(MGMT_OP_MESH_SEND), 19);
    assert_eq!(w(MGMT_OP_HCI_CMD_SYNC), 6);
    assert_eq!(w(MGMT_OP_SET_EXP_FEATURE), 16);
}

/// The limited scan is the ordinary scan's twin and must carry its width.
#[test]
fn limited_discovery_matches_ordinary_discovery() {
    assert_eq!(lookup(MGMT_OP_START_LIMITED_DISCOVERY), lookup(MGMT_OP_START_DISCOVERY));
}
