//! Controller setup sequence.
//!
//! A controller is brought up in four stages, each a fixed command order, and
//! each stage reads capability words the previous stage established. That
//! staging is the whole point: the BR/EDR half of stage two may only be sent to
//! a controller whose feature mask says it speaks BR/EDR, and the mask is not
//! known until stage one has read it. A stage list computed from stale
//! capabilities sends a controller a command it will refuse, and a refusal
//! during setup takes the controller down.
//!
//! The stage lists are pure functions of the capability words, so the whole
//! sequence is decided and checked without a controller.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::hci_cmd::*;
use super::dev::LocalInfo;

/// Setup stage.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Stage { One, Two, Three, Four }

impl Stage {
    /// The stage after this one, or `None` when setup is complete. # C: O(1)
    pub fn next(self) -> Option<Stage> {
        match self {
            Stage::One => Some(Stage::Two),
            Stage::Two => Some(Stage::Three),
            Stage::Three => Some(Stage::Four),
            Stage::Four => None,
        }
    }
}

/// What the setup sequence needs to know beyond the capability words.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SetupEnv {
    /// Whether the transport wants the reset skipped, because it resets the
    /// controller when the transport closes instead.
    pub reset_on_close: bool,
    /// Whether secure simple pairing is to be turned on, which is a host policy
    /// decision and not a controller capability.
    pub ssp_enabled: bool,
    /// Whether the controller is unconfigured — it has no assigned address — in
    /// which case only the two identifying reads are sent.
    pub unconfigured: bool,
}

/// Command-bitmap positions the setup sequence screens on. Sending a command
/// whose support bit is clear draws a refusal, and a refusal during setup is
/// indistinguishable from a broken controller, so the screen is not optional.
pub const CMD_DELETE_STORED_LINK_KEY_BYTE: usize = 7;
pub const CMD_DELETE_STORED_LINK_KEY_BIT:  u8 = 0;
pub const CMD_READ_LOCAL_CODECS_BYTE: usize = 29;
pub const CMD_READ_LOCAL_CODECS_BIT:  u8 = 5;

/// Commands of stage one: reset the controller, then read the three words that
/// identify it and gate every later stage. # C: O(1)
pub fn stage_one(env: SetupEnv) -> Vec<u16> {
    let mut out = Vec::new();
    if !env.reset_on_close { out.push(HCI_OP_RESET); }
    if env.unconfigured {
        out.push(HCI_OP_READ_LOCAL_VERSION);
        out.push(HCI_OP_READ_BD_ADDR);
        return out;
    }
    out.push(HCI_OP_READ_LOCAL_FEATURES);
    out.push(HCI_OP_READ_LOCAL_VERSION);
    out.push(HCI_OP_READ_BD_ADDR);
    out
}

/// Commands of stage two: the host-side capability words, then the BR/EDR half
/// and the LE half, each gated on the feature mask stage one read. # C: O(1)
pub fn stage_two(info: &LocalInfo, env: SetupEnv) -> Vec<u16> {
    let mut out = Vec::new();
    out.push(HCI_OP_READ_LOCAL_COMMANDS);
    if info.ssp_capable() {
        // Only one of the two is sent: the pairing mode when it is being turned
        // on, and the inquiry-data write when it is not, because a controller
        // with pairing off still advertises its name.
        if env.ssp_enabled { out.push(HCI_OP_WRITE_SSP_MODE); } else { out.push(HCI_OP_WRITE_EIR); }
    }
    if info.rssi_inquiry_capable() { out.push(HCI_OP_WRITE_INQUIRY_MODE); }
    out.push(HCI_OP_READ_INQ_RSP_TX_POWER);
    out.push(HCI_OP_READ_LOCAL_EXT_FEATURES);
    out.push(HCI_OP_WRITE_AUTH_ENABLE);
    if info.bredr_capable() {
        out.push(HCI_OP_READ_BUFFER_SIZE);
        out.push(HCI_OP_READ_CLASS_OF_DEV);
        out.push(HCI_OP_READ_LOCAL_NAME);
        out.push(HCI_OP_READ_VOICE_SETTING);
        out.push(HCI_OP_READ_NUM_SUPPORTED_IAC);
        out.push(HCI_OP_READ_CURRENT_IAC_LAP);
        out.push(HCI_OP_SET_EVENT_FLT);
        out.push(HCI_OP_WRITE_CA_TIMEOUT);
    }
    if info.le_capable() {
        out.push(HCI_OP_LE_READ_LOCAL_FEATURES);
        out.push(HCI_OP_LE_READ_BUFFER_SIZE);
        out.push(HCI_OP_LE_READ_SUPPORTED_STATES);
    }
    out
}

/// Commands of stage three: the event masks and the scan and policy words that
/// make the controller visible and connectable. # C: O(1)
pub fn stage_three(info: &LocalInfo) -> Vec<u16> {
    let mut out = alloc::vec![
        HCI_OP_SET_EVENT_MASK,
        HCI_OP_READ_STORED_LINK_KEY,
        HCI_OP_WRITE_DEF_LINK_POLICY,
        HCI_OP_READ_PAGE_SCAN_ACTIVITY,
        HCI_OP_READ_DEF_ERR_DATA_REPORTING,
        HCI_OP_READ_PAGE_SCAN_TYPE,
        HCI_OP_READ_LOCAL_EXT_FEATURES,
    ];
    if info.le_capable() {
        out.extend_from_slice(&[
            HCI_OP_LE_SET_EVENT_MASK,
            HCI_OP_LE_READ_ADV_TX_POWER,
            HCI_OP_LE_READ_TRANSMIT_POWER,
            HCI_OP_LE_READ_ACCEPT_LIST_SIZE,
            HCI_OP_LE_CLEAR_ACCEPT_LIST,
            HCI_OP_LE_READ_RESOLV_LIST_SIZE,
            HCI_OP_LE_CLEAR_RESOLV_LIST,
            HCI_OP_LE_SET_RPA_TIMEOUT,
            HCI_OP_LE_READ_MAX_DATA_LEN,
            HCI_OP_LE_READ_DEF_DATA_LEN,
            HCI_OP_LE_READ_NUM_SUPPORTED_ADV_SETS,
            HCI_OP_WRITE_LE_HOST_SUPPORTED,
            HCI_OP_LE_SET_HOST_FEATURE,
        ]);
    }
    out
}

/// Commands of stage four: the optional words, each screened against the
/// supported-command bitmap stage two read. # C: O(1)
pub fn stage_four(info: &LocalInfo) -> Vec<u16> {
    let mut out = Vec::new();
    if info.command_supported(CMD_DELETE_STORED_LINK_KEY_BYTE, CMD_DELETE_STORED_LINK_KEY_BIT) {
        out.push(HCI_OP_DELETE_STORED_LINK_KEY);
    }
    out.push(HCI_OP_SET_EVENT_MASK_PAGE_2);
    if info.command_supported(CMD_READ_LOCAL_CODECS_BYTE, CMD_READ_LOCAL_CODECS_BIT) {
        out.push(HCI_OP_READ_LOCAL_CODECS);
    }
    out.push(HCI_OP_READ_LOCAL_PAIRING_OPTS);
    out.push(HCI_OP_GET_MWS_TRANSPORT_CONFIG);
    out.push(HCI_OP_READ_SYNC_TRAIN_PARAMS);
    out.push(HCI_OP_WRITE_SC_SUPPORT);
    out.push(HCI_OP_WRITE_DEF_ERR_DATA_REPORTING);
    if info.le_capable() {
        out.push(HCI_OP_LE_WRITE_DEF_DATA_LEN);
        out.push(HCI_OP_LE_SET_DEFAULT_PHY);
    }
    out
}

/// The command order for one stage. # C: O(1)
pub fn stage_commands(stage: Stage, info: &LocalInfo, env: SetupEnv) -> Vec<u16> {
    match stage {
        Stage::One   => stage_one(env),
        Stage::Two   => stage_two(info, env),
        Stage::Three => stage_three(info),
        Stage::Four  => stage_four(info),
    }
}

/// Whether an unconfigured controller stops after stage one. A controller with
/// no address cannot form a link, so the remaining stages would configure
/// something that can never be used. # C: O(1)
pub fn stops_after_stage_one(env: SetupEnv) -> bool { env.unconfigured }

#[cfg(test)]
#[path = "tests/init.rs"]
mod tests;
