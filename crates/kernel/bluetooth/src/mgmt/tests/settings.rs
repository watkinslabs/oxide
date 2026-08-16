//! The settings words.

use super::*;

#[test]
fn a_bit_cannot_be_current_unless_it_is_supported() {
    let s = Settings::new(MGMT_SETTING_POWERED | MGMT_SETTING_LE,
                          MGMT_SETTING_POWERED | MGMT_SETTING_BREDR);
    assert!(s.has(MGMT_SETTING_POWERED));
    assert!(!s.has(MGMT_SETTING_BREDR), "an unsupported bit must not survive");
}

#[test]
fn setting_an_unsupported_bit_is_a_no_op() {
    let mut s = Settings::new(MGMT_SETTING_POWERED, 0);
    s.set(MGMT_SETTING_ADVERTISING, true);
    assert!(!s.has(MGMT_SETTING_ADVERTISING));
    s.set(MGMT_SETTING_POWERED, true);
    assert!(s.has(MGMT_SETTING_POWERED));
    s.set(MGMT_SETTING_POWERED, false);
    assert!(!s.has(MGMT_SETTING_POWERED));
}

#[test]
fn the_response_payload_is_the_current_word_little_endian() {
    let s = Settings::new(u32::MAX, MGMT_SETTING_POWERED | MGMT_SETTING_BREDR);
    assert_eq!(s.current_word(), 0x81);
    assert_eq!(s.encode_current(), alloc::vec![0x81, 0x00, 0x00, 0x00]);
}

/// Bit positions are the ABI. A shifted bit silently changes what a client
/// thinks is switched on.
#[test]
fn every_settings_bit_sits_where_the_interface_says() {
    let pairs: [(u32, u32); 25] = [
        (MGMT_SETTING_POWERED, 0), (MGMT_SETTING_CONNECTABLE, 1),
        (MGMT_SETTING_FAST_CONNECTABLE, 2), (MGMT_SETTING_DISCOVERABLE, 3),
        (MGMT_SETTING_BONDABLE, 4), (MGMT_SETTING_LINK_SECURITY, 5),
        (MGMT_SETTING_SSP, 6), (MGMT_SETTING_BREDR, 7),
        (MGMT_SETTING_HS, 8), (MGMT_SETTING_LE, 9),
        (MGMT_SETTING_ADVERTISING, 10), (MGMT_SETTING_SECURE_CONN, 11),
        (MGMT_SETTING_DEBUG_KEYS, 12), (MGMT_SETTING_PRIVACY, 13),
        (MGMT_SETTING_CONFIGURATION, 14), (MGMT_SETTING_STATIC_ADDRESS, 15),
        (MGMT_SETTING_PHY_CONFIGURATION, 16), (MGMT_SETTING_WIDEBAND_SPEECH, 17),
        (MGMT_SETTING_CIS_CENTRAL, 18), (MGMT_SETTING_CIS_PERIPHERAL, 19),
        (MGMT_SETTING_ISO_BROADCASTER, 20), (MGMT_SETTING_ISO_SYNC_RECEIVER, 21),
        (MGMT_SETTING_LL_PRIVACY, 22), (MGMT_SETTING_PAST_SENDER, 23),
        (MGMT_SETTING_PAST_RECEIVER, 24),
    ];
    for (bit, pos) in pairs {
        assert_eq!(bit, 1 << pos, "bit at position {pos}");
    }
}

#[test]
fn each_mode_command_names_its_own_setting() {
    assert_eq!(setting_for_opcode(MGMT_OP_SET_POWERED), Some(MGMT_SETTING_POWERED));
    assert_eq!(setting_for_opcode(MGMT_OP_SET_LE), Some(MGMT_SETTING_LE));
    assert_eq!(setting_for_opcode(MGMT_OP_SET_BREDR), Some(MGMT_SETTING_BREDR));
    assert_eq!(setting_for_opcode(MGMT_OP_SET_WIDEBAND_SPEECH),
               Some(MGMT_SETTING_WIDEBAND_SPEECH));
    // Two commands must not claim the same bit.
    let ops = [
        MGMT_OP_SET_POWERED, MGMT_OP_SET_DISCOVERABLE, MGMT_OP_SET_CONNECTABLE,
        MGMT_OP_SET_FAST_CONNECTABLE, MGMT_OP_SET_BONDABLE, MGMT_OP_SET_LINK_SECURITY,
        MGMT_OP_SET_SSP, MGMT_OP_SET_HS, MGMT_OP_SET_LE, MGMT_OP_SET_ADVERTISING,
        MGMT_OP_SET_BREDR, MGMT_OP_SET_SECURE_CONN, MGMT_OP_SET_DEBUG_KEYS,
        MGMT_OP_SET_PRIVACY, MGMT_OP_SET_WIDEBAND_SPEECH,
    ];
    let mut seen = 0u32;
    for op in ops {
        let bit = setting_for_opcode(op).expect("a mode command has a bit");
        assert_eq!(seen & bit, 0, "opcode {op:#06x} reuses a bit");
        seen |= bit;
    }
}

#[test]
fn a_command_that_is_not_a_mode_switch_names_no_setting() {
    for op in [MGMT_OP_READ_INFO, MGMT_OP_SET_LOCAL_NAME, MGMT_OP_ADD_DEVICE, 0] {
        assert_eq!(setting_for_opcode(op), None, "opcode {op:#06x}");
    }
}
