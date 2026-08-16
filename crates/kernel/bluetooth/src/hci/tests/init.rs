use super::*;
use crate::hci::dev::{LMP_LE_BYTE, LMP_LE_BIT, LMP_NO_BREDR_BYTE, LMP_NO_BREDR_BIT,
    LMP_RSSI_INQ_BYTE, LMP_RSSI_INQ_BIT, LMP_SSP_BYTE, LMP_SSP_BIT};

fn dual_mode() -> LocalInfo {
    let mut i = LocalInfo::default();
    i.features[LMP_LE_BYTE] |= 1 << LMP_LE_BIT;
    i
}

fn le_only() -> LocalInfo {
    let mut i = dual_mode();
    i.features[LMP_NO_BREDR_BYTE] |= 1 << LMP_NO_BREDR_BIT;
    i
}

fn bredr_only() -> LocalInfo { LocalInfo::default() }

#[test]
fn stage_one_resets_then_reads_the_three_identifying_words() {
    let c = stage_one(SetupEnv::default());
    assert_eq!(c, alloc::vec![HCI_OP_RESET, HCI_OP_READ_LOCAL_FEATURES,
        HCI_OP_READ_LOCAL_VERSION, HCI_OP_READ_BD_ADDR]);
}

// A transport that resets the controller when it closes must not be reset again
// on open: the second reset races the first.
#[test]
fn a_transport_that_resets_on_close_skips_the_open_reset() {
    let env = SetupEnv { reset_on_close: true, ..SetupEnv::default() };
    let c = stage_one(env);
    assert!(!c.contains(&HCI_OP_RESET));
    assert_eq!(c.first(), Some(&HCI_OP_READ_LOCAL_FEATURES));
}

// A controller with no address cannot form a link, so configuring it further
// would set up something that can never be used.
#[test]
fn an_unconfigured_controller_reads_only_its_identity_and_stops() {
    let env = SetupEnv { unconfigured: true, ..SetupEnv::default() };
    let c = stage_one(env);
    assert_eq!(c, alloc::vec![HCI_OP_RESET, HCI_OP_READ_LOCAL_VERSION, HCI_OP_READ_BD_ADDR]);
    assert!(stops_after_stage_one(env));
    assert!(!stops_after_stage_one(SetupEnv::default()));
}

// The BR/EDR half of stage two may only be sent to a controller whose feature
// mask says it speaks BR/EDR — and the mask is not known until stage one has
// read it. This is the whole reason the sequence is staged.
#[test]
fn the_bredr_half_of_stage_two_is_gated_on_the_feature_mask() {
    let bredr = stage_two(&bredr_only(), SetupEnv::default());
    assert!(bredr.contains(&HCI_OP_READ_BUFFER_SIZE));
    assert!(bredr.contains(&HCI_OP_READ_CLASS_OF_DEV));
    assert!(!bredr.contains(&HCI_OP_LE_READ_BUFFER_SIZE));

    let le = stage_two(&le_only(), SetupEnv::default());
    assert!(!le.contains(&HCI_OP_READ_BUFFER_SIZE));
    assert!(!le.contains(&HCI_OP_READ_CLASS_OF_DEV));
    assert!(le.contains(&HCI_OP_LE_READ_BUFFER_SIZE));
}

#[test]
fn a_dual_mode_controller_gets_both_halves_of_stage_two() {
    let c = stage_two(&dual_mode(), SetupEnv::default());
    assert!(c.contains(&HCI_OP_READ_BUFFER_SIZE));
    assert!(c.contains(&HCI_OP_LE_READ_BUFFER_SIZE));
    assert!(c.contains(&HCI_OP_LE_READ_LOCAL_FEATURES));
    assert!(c.contains(&HCI_OP_LE_READ_SUPPORTED_STATES));
}

// A controller that cannot do secure simple pairing must be sent neither of the
// two pairing-mode writes.
#[test]
fn the_pairing_writes_are_gated_on_the_pairing_capability() {
    let plain = stage_two(&bredr_only(), SetupEnv::default());
    assert!(!plain.contains(&HCI_OP_WRITE_SSP_MODE));
    assert!(!plain.contains(&HCI_OP_WRITE_EIR));
}

// Exactly one of the two is sent: the mode write when pairing is being turned
// on, the inquiry-data write when it is not.
#[test]
fn exactly_one_pairing_write_is_sent_when_the_controller_can_pair() {
    let mut info = bredr_only();
    info.features[LMP_SSP_BYTE] |= 1 << LMP_SSP_BIT;
    let on = stage_two(&info, SetupEnv { ssp_enabled: true, ..SetupEnv::default() });
    assert!(on.contains(&HCI_OP_WRITE_SSP_MODE));
    assert!(!on.contains(&HCI_OP_WRITE_EIR));
    let off = stage_two(&info, SetupEnv::default());
    assert!(!off.contains(&HCI_OP_WRITE_SSP_MODE));
    assert!(off.contains(&HCI_OP_WRITE_EIR));
}

#[test]
fn the_inquiry_mode_write_is_gated_on_the_signal_strength_capability() {
    assert!(!stage_two(&bredr_only(), SetupEnv::default()).contains(&HCI_OP_WRITE_INQUIRY_MODE));
    let mut info = bredr_only();
    info.features[LMP_RSSI_INQ_BYTE] |= 1 << LMP_RSSI_INQ_BIT;
    assert!(stage_two(&info, SetupEnv::default()).contains(&HCI_OP_WRITE_INQUIRY_MODE));
}

#[test]
fn stage_two_reads_the_supported_command_bitmap_first() {
    assert_eq!(stage_two(&dual_mode(), SetupEnv::default()).first(),
        Some(&HCI_OP_READ_LOCAL_COMMANDS));
}

#[test]
fn stage_three_sets_the_event_mask_first_and_gates_its_le_half() {
    let c = stage_three(&bredr_only());
    assert_eq!(c.first(), Some(&HCI_OP_SET_EVENT_MASK));
    assert!(!c.contains(&HCI_OP_LE_SET_EVENT_MASK));
    let le = stage_three(&dual_mode());
    assert!(le.contains(&HCI_OP_LE_SET_EVENT_MASK));
    assert!(le.contains(&HCI_OP_WRITE_LE_HOST_SUPPORTED));
}

// Sending a command whose support bit is clear draws a refusal, and a refusal
// during setup is indistinguishable from a broken controller.
#[test]
fn stage_four_screens_the_optional_commands_against_the_support_bitmap() {
    let bare = stage_four(&bredr_only());
    assert!(!bare.contains(&HCI_OP_DELETE_STORED_LINK_KEY));
    assert!(!bare.contains(&HCI_OP_READ_LOCAL_CODECS));

    let mut info = bredr_only();
    info.commands[CMD_DELETE_STORED_LINK_KEY_BYTE] |= 1 << CMD_DELETE_STORED_LINK_KEY_BIT;
    info.commands[CMD_READ_LOCAL_CODECS_BYTE] |= 1 << CMD_READ_LOCAL_CODECS_BIT;
    let full = stage_four(&info);
    assert!(full.contains(&HCI_OP_DELETE_STORED_LINK_KEY));
    assert!(full.contains(&HCI_OP_READ_LOCAL_CODECS));
}

#[test]
fn stage_four_gates_its_le_half_on_the_feature_mask() {
    assert!(!stage_four(&bredr_only()).contains(&HCI_OP_LE_SET_DEFAULT_PHY));
    assert!(stage_four(&dual_mode()).contains(&HCI_OP_LE_SET_DEFAULT_PHY));
}

#[test]
fn the_stages_run_in_order_and_then_stop() {
    assert_eq!(Stage::One.next(), Some(Stage::Two));
    assert_eq!(Stage::Two.next(), Some(Stage::Three));
    assert_eq!(Stage::Three.next(), Some(Stage::Four));
    assert_eq!(Stage::Four.next(), None);
}

#[test]
fn the_stage_selector_agrees_with_each_stage_function() {
    let info = dual_mode();
    let env = SetupEnv::default();
    assert_eq!(stage_commands(Stage::One, &info, env), stage_one(env));
    assert_eq!(stage_commands(Stage::Two, &info, env), stage_two(&info, env));
    assert_eq!(stage_commands(Stage::Three, &info, env), stage_three(&info));
    assert_eq!(stage_commands(Stage::Four, &info, env), stage_four(&info));
}

// No stage may send the same command twice: a duplicate wastes a credit and, on
// a write command, applies the setting twice.
#[test]
fn no_stage_sends_the_same_command_twice() {
    let info = dual_mode();
    let env = SetupEnv::default();
    for stage in [Stage::One, Stage::Two, Stage::Three, Stage::Four] {
        let c = stage_commands(stage, &info, env);
        for (i, op) in c.iter().enumerate() {
            assert!(!c[i + 1..].contains(op), "stage {stage:?} repeats opcode {op:#06x}");
        }
    }
}
