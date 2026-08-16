//! Widths and sentinels the management framing is measured against. A record
//! whose declared width disagrees with the constant here is malformed, so every
//! decoder compares against these rather than against a literal.

use crate::uapi::bt::BDADDR_LEN;

/// `{opcode, index, len}`, each a little-endian 16-bit field.
pub const MGMT_HDR_SIZE: usize = 6;

/// Index naming no controller. A command carrying it is answered by the stack
/// itself; any other value must name a live controller.
pub const MGMT_INDEX_NONE: u16 = 0xFFFF;

/// Protocol version and revision reported by `READ_VERSION`.
pub const MGMT_VERSION: u8 = 1;
pub const MGMT_REVISION: u16 = 23;

/// `mgmt_addr_info`: six address bytes then the address type.
pub const MGMT_ADDR_INFO_SIZE: usize = BDADDR_LEN + 1;

/// Name fields carry one byte more than the controller's own maximum so the
/// value is always NUL-terminated inside the field.
pub const MGMT_MAX_NAME_LENGTH: usize = 249;
pub const MGMT_MAX_SHORT_NAME_LENGTH: usize = 11;

/// Widths of the repeated records the load commands and the key events carry.
pub const MGMT_LINK_KEY_INFO_SIZE: usize = MGMT_ADDR_INFO_SIZE + 18;
pub const MGMT_LTK_INFO_SIZE: usize = MGMT_ADDR_INFO_SIZE + 29;
pub const MGMT_IRK_INFO_SIZE: usize = MGMT_ADDR_INFO_SIZE + 16;
pub const MGMT_CSRK_INFO_SIZE: usize = MGMT_ADDR_INFO_SIZE + 17;
pub const MGMT_CONN_PARAM_SIZE: usize = MGMT_ADDR_INFO_SIZE + 8;
pub const MGMT_BLOCKED_KEY_INFO_SIZE: usize = 17;

/// An advertising monitor pattern always occupies its full width on the wire,
/// value bytes past `length` included.
pub const MGMT_ADV_PATTERN_VALUE_LEN: usize = 31;
pub const MGMT_ADV_PATTERN_SIZE: usize = 3 + MGMT_ADV_PATTERN_VALUE_LEN;
pub const MGMT_ADV_RSSI_THRESHOLDS_SIZE: usize = 7;

/// Key material widths.
pub const MGMT_KEY_LEN: usize = 16;
pub const MGMT_UUID_LEN: usize = 16;
pub const MGMT_PIN_LEN: usize = 16;

/// Class of device, as carried by `READ_INFO` and the change event.
pub const MGMT_DEV_CLASS_LEN: usize = 3;

/// Number of mesh send handles a controller reports.
pub const MGMT_MESH_HANDLES_MAX: usize = 3;
