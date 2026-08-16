//! The handler table, as data. Every opcode's parameter width and its four
//! dispatch properties live here so the validation sequence can consult one
//! table instead of a pile of match arms — the same shape the reference uses,
//! and the reason validation is a pure function of the table plus the request.

use crate::uapi::mgmt::op::*;

/// The parameter width is a minimum rather than an exact length.
pub const F_VAR_LEN: u8 = 1 << 0;
/// The command answers for the stack, not for a controller, and must arrive
/// with the no-controller index.
pub const F_NO_HDEV: u8 = 1 << 1;
/// An untrusted socket may issue the command.
pub const F_UNTRUSTED: u8 = 1 << 2;
/// The command may address a controller that is not yet configured.
pub const F_UNCONFIGURED: u8 = 1 << 3;
/// The command works either with a controller or without one, so the
/// controller-presence check is skipped for it entirely.
pub const F_HDEV_OPTIONAL: u8 = 1 << 4;

/// One opcode's contract.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HandlerSpec {
    pub data_len: u16,
    pub flags: u8,
}

impl HandlerSpec {
    /// # C: O(1)
    pub const fn var_len(&self) -> bool { self.flags & F_VAR_LEN != 0 }
    /// # C: O(1)
    pub const fn no_hdev(&self) -> bool { self.flags & F_NO_HDEV != 0 }
    /// # C: O(1)
    pub const fn untrusted(&self) -> bool { self.flags & F_UNTRUSTED != 0 }
    /// # C: O(1)
    pub const fn unconfigured(&self) -> bool { self.flags & F_UNCONFIGURED != 0 }
    /// # C: O(1)
    pub const fn hdev_optional(&self) -> bool { self.flags & F_HDEV_OPTIONAL != 0 }
}

const fn h(data_len: usize, flags: u8) -> Option<HandlerSpec> {
    Some(HandlerSpec { data_len: data_len as u16, flags })
}

/// Number of table slots. Index zero is not a command.
pub const HANDLER_COUNT: usize = MGMT_OP_MAX as usize + 1;

/// Opcode-indexed contract table. `None` means the opcode has no handler, which
/// is answered exactly like an opcode past the end of the table.
pub const HANDLERS: [Option<HandlerSpec>; HANDLER_COUNT] = [
    None, // 0x0000 is not a command
    h(MGMT_READ_VERSION_SIZE, F_NO_HDEV | F_UNTRUSTED),
    h(MGMT_READ_COMMANDS_SIZE, F_NO_HDEV | F_UNTRUSTED),
    h(MGMT_READ_INDEX_LIST_SIZE, F_NO_HDEV | F_UNTRUSTED),
    h(MGMT_READ_INFO_SIZE, F_UNTRUSTED),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_SET_DISCOVERABLE_SIZE, 0),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_SET_DEV_CLASS_SIZE, 0),
    h(MGMT_SET_LOCAL_NAME_SIZE, 0),
    h(MGMT_ADD_UUID_SIZE, 0),
    h(MGMT_REMOVE_UUID_SIZE, 0),
    h(MGMT_LOAD_LINK_KEYS_SIZE, F_VAR_LEN),
    h(MGMT_LOAD_LONG_TERM_KEYS_SIZE, F_VAR_LEN),
    h(MGMT_DISCONNECT_SIZE, 0),
    h(MGMT_GET_CONNECTIONS_SIZE, 0),
    h(MGMT_PIN_CODE_REPLY_SIZE, 0),
    h(MGMT_PIN_CODE_NEG_REPLY_SIZE, 0),
    h(MGMT_SET_IO_CAPABILITY_SIZE, 0),
    h(MGMT_PAIR_DEVICE_SIZE, 0),
    h(MGMT_CANCEL_PAIR_DEVICE_SIZE, 0),
    h(MGMT_UNPAIR_DEVICE_SIZE, 0),
    h(MGMT_USER_CONFIRM_REPLY_SIZE, 0),
    h(MGMT_USER_CONFIRM_NEG_REPLY_SIZE, 0),
    h(MGMT_USER_PASSKEY_REPLY_SIZE, 0),
    h(MGMT_USER_PASSKEY_NEG_REPLY_SIZE, 0),
    h(MGMT_READ_LOCAL_OOB_DATA_SIZE, 0),
    h(MGMT_ADD_REMOTE_OOB_DATA_SIZE, F_VAR_LEN),
    h(MGMT_REMOVE_REMOTE_OOB_DATA_SIZE, 0),
    h(MGMT_START_DISCOVERY_SIZE, 0),
    h(MGMT_STOP_DISCOVERY_SIZE, 0),
    h(MGMT_CONFIRM_NAME_SIZE, 0),
    h(MGMT_BLOCK_DEVICE_SIZE, 0),
    h(MGMT_UNBLOCK_DEVICE_SIZE, 0),
    h(MGMT_SET_DEVICE_ID_SIZE, 0),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_SET_STATIC_ADDRESS_SIZE, 0),
    h(MGMT_SET_SCAN_PARAMS_SIZE, 0),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_SET_PRIVACY_SIZE, 0),
    h(MGMT_LOAD_IRKS_SIZE, F_VAR_LEN),
    h(MGMT_GET_CONN_INFO_SIZE, 0),
    h(MGMT_GET_CLOCK_INFO_SIZE, 0),
    h(MGMT_ADD_DEVICE_SIZE, 0),
    h(MGMT_REMOVE_DEVICE_SIZE, 0),
    h(MGMT_LOAD_CONN_PARAM_SIZE, F_VAR_LEN),
    h(MGMT_READ_UNCONF_INDEX_LIST_SIZE, F_NO_HDEV | F_UNTRUSTED),
    h(MGMT_READ_CONFIG_INFO_SIZE, F_UNCONFIGURED | F_UNTRUSTED),
    h(MGMT_SET_EXTERNAL_CONFIG_SIZE, F_UNCONFIGURED),
    h(MGMT_SET_PUBLIC_ADDRESS_SIZE, F_UNCONFIGURED),
    h(MGMT_START_SERVICE_DISCOVERY_SIZE, F_VAR_LEN),
    h(MGMT_READ_LOCAL_OOB_EXT_DATA_SIZE, 0),
    h(MGMT_READ_EXT_INDEX_LIST_SIZE, F_NO_HDEV | F_UNTRUSTED),
    h(MGMT_READ_ADV_FEATURES_SIZE, 0),
    h(MGMT_ADD_ADVERTISING_SIZE, F_VAR_LEN),
    h(MGMT_REMOVE_ADVERTISING_SIZE, 0),
    h(MGMT_GET_ADV_SIZE_INFO_SIZE, 0),
    h(MGMT_START_DISCOVERY_SIZE, 0),
    h(MGMT_READ_EXT_INFO_SIZE, F_UNTRUSTED),
    h(MGMT_SET_APPEARANCE_SIZE, 0),
    h(MGMT_GET_PHY_CONFIGURATION_SIZE, 0),
    h(MGMT_SET_PHY_CONFIGURATION_SIZE, 0),
    h(MGMT_SET_BLOCKED_KEYS_SIZE, F_VAR_LEN),
    h(MGMT_SETTING_SIZE, 0),
    h(MGMT_READ_CONTROLLER_CAP_SIZE, F_UNTRUSTED),
    h(MGMT_READ_EXP_FEATURES_INFO_SIZE, F_UNTRUSTED | F_HDEV_OPTIONAL),
    h(MGMT_SET_EXP_FEATURE_SIZE, F_VAR_LEN | F_HDEV_OPTIONAL),
    h(MGMT_READ_DEF_SYSTEM_CONFIG_SIZE, F_UNTRUSTED),
    h(MGMT_SET_DEF_SYSTEM_CONFIG_SIZE, F_VAR_LEN),
    h(MGMT_READ_DEF_RUNTIME_CONFIG_SIZE, F_UNTRUSTED),
    h(MGMT_SET_DEF_RUNTIME_CONFIG_SIZE, F_VAR_LEN),
    h(MGMT_GET_DEVICE_FLAGS_SIZE, 0),
    h(MGMT_SET_DEVICE_FLAGS_SIZE, 0),
    h(MGMT_READ_ADV_MONITOR_FEATURES_SIZE, 0),
    h(MGMT_ADD_ADV_PATTERNS_MONITOR_SIZE, F_VAR_LEN),
    h(MGMT_REMOVE_ADV_MONITOR_SIZE, 0),
    h(MGMT_ADD_EXT_ADV_PARAMS_MIN_SIZE, F_VAR_LEN),
    h(MGMT_ADD_EXT_ADV_DATA_SIZE, F_VAR_LEN),
    h(MGMT_ADD_ADV_PATTERNS_MONITOR_RSSI_SIZE, F_VAR_LEN),
    h(MGMT_SET_MESH_RECEIVER_SIZE, F_VAR_LEN),
    h(MGMT_MESH_READ_FEATURES_SIZE, 0),
    h(MGMT_MESH_SEND_SIZE, F_VAR_LEN),
    h(MGMT_MESH_SEND_CANCEL_SIZE, 0),
    h(MGMT_HCI_CMD_SYNC_SIZE, F_VAR_LEN),
];

/// The contract for an opcode, or `None` when nothing serves it. # C: O(1)
pub fn lookup(opcode: u16) -> Option<HandlerSpec> {
    let i = opcode as usize;
    if i >= HANDLER_COUNT { return None; }
    HANDLERS[i]
}

/// Whether an opcode has a handler at all. What `READ_COMMANDS` advertises is a
/// shorter list than this — see `mgmt::advertised`. # C: O(1)
pub fn is_implemented(opcode: u16) -> bool { lookup(opcode).is_some() }

#[cfg(test)]
#[path = "tests/table.rs"]
mod tests;
