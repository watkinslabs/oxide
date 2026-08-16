//! Bitmasks and small enumerations the management interface exchanges: the
//! settings word, advertising flags, PHY bits, per-device flags, discovery
//! types, and the operand values commands validate against.

use crate::uapi::bt::{BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM};

/// Settings word bit positions. `READ_INFO` reports two of these words — what
/// the controller can do, and what is on right now — and every `SET_*` answers
/// with the current word.
pub const MGMT_SETTING_POWERED: u32 = 1 << 0;
pub const MGMT_SETTING_CONNECTABLE: u32 = 1 << 1;
pub const MGMT_SETTING_FAST_CONNECTABLE: u32 = 1 << 2;
pub const MGMT_SETTING_DISCOVERABLE: u32 = 1 << 3;
pub const MGMT_SETTING_BONDABLE: u32 = 1 << 4;
pub const MGMT_SETTING_LINK_SECURITY: u32 = 1 << 5;
pub const MGMT_SETTING_SSP: u32 = 1 << 6;
pub const MGMT_SETTING_BREDR: u32 = 1 << 7;
pub const MGMT_SETTING_HS: u32 = 1 << 8;
pub const MGMT_SETTING_LE: u32 = 1 << 9;
pub const MGMT_SETTING_ADVERTISING: u32 = 1 << 10;
pub const MGMT_SETTING_SECURE_CONN: u32 = 1 << 11;
pub const MGMT_SETTING_DEBUG_KEYS: u32 = 1 << 12;
pub const MGMT_SETTING_PRIVACY: u32 = 1 << 13;
pub const MGMT_SETTING_CONFIGURATION: u32 = 1 << 14;
pub const MGMT_SETTING_STATIC_ADDRESS: u32 = 1 << 15;
pub const MGMT_SETTING_PHY_CONFIGURATION: u32 = 1 << 16;
pub const MGMT_SETTING_WIDEBAND_SPEECH: u32 = 1 << 17;
pub const MGMT_SETTING_CIS_CENTRAL: u32 = 1 << 18;
pub const MGMT_SETTING_CIS_PERIPHERAL: u32 = 1 << 19;
pub const MGMT_SETTING_ISO_BROADCASTER: u32 = 1 << 20;
pub const MGMT_SETTING_ISO_SYNC_RECEIVER: u32 = 1 << 21;
pub const MGMT_SETTING_LL_PRIVACY: u32 = 1 << 22;
pub const MGMT_SETTING_PAST_SENDER: u32 = 1 << 23;
pub const MGMT_SETTING_PAST_RECEIVER: u32 = 1 << 24;

/// Configuration options a controller may be missing before it can be used.
pub const MGMT_OPTION_EXTERNAL_CONFIG: u32 = 1 << 0;
pub const MGMT_OPTION_PUBLIC_ADDRESS: u32 = 1 << 1;

/// Advertising instance flags, and the parameter-present bits that share the
/// same word in the extended-parameters command.
pub const MGMT_ADV_FLAG_CONNECTABLE: u32 = 1 << 0;
pub const MGMT_ADV_FLAG_DISCOV: u32 = 1 << 1;
pub const MGMT_ADV_FLAG_LIMITED_DISCOV: u32 = 1 << 2;
pub const MGMT_ADV_FLAG_MANAGED_FLAGS: u32 = 1 << 3;
pub const MGMT_ADV_FLAG_TX_POWER: u32 = 1 << 4;
pub const MGMT_ADV_FLAG_APPEARANCE: u32 = 1 << 5;
pub const MGMT_ADV_FLAG_LOCAL_NAME: u32 = 1 << 6;
pub const MGMT_ADV_FLAG_SEC_1M: u32 = 1 << 7;
pub const MGMT_ADV_FLAG_SEC_2M: u32 = 1 << 8;
pub const MGMT_ADV_FLAG_SEC_CODED: u32 = 1 << 9;
pub const MGMT_ADV_FLAG_CAN_SET_TX_POWER: u32 = 1 << 10;
pub const MGMT_ADV_FLAG_HW_OFFLOAD: u32 = 1 << 11;
pub const MGMT_ADV_PARAM_DURATION: u32 = 1 << 12;
pub const MGMT_ADV_PARAM_TIMEOUT: u32 = 1 << 13;
pub const MGMT_ADV_PARAM_INTERVALS: u32 = 1 << 14;
pub const MGMT_ADV_PARAM_TX_POWER: u32 = 1 << 15;
pub const MGMT_ADV_PARAM_SCAN_RSP: u32 = 1 << 16;

/// Exactly one secondary-PHY bit may be selected at a time.
pub const MGMT_ADV_FLAG_SEC_MASK: u32 =
    MGMT_ADV_FLAG_SEC_1M | MGMT_ADV_FLAG_SEC_2M | MGMT_ADV_FLAG_SEC_CODED;

/// PHY bits, as reported and selected by the PHY configuration commands.
pub const MGMT_PHY_BR_1M_1SLOT: u32 = 1 << 0;
pub const MGMT_PHY_BR_1M_3SLOT: u32 = 1 << 1;
pub const MGMT_PHY_BR_1M_5SLOT: u32 = 1 << 2;
pub const MGMT_PHY_EDR_2M_1SLOT: u32 = 1 << 3;
pub const MGMT_PHY_EDR_2M_3SLOT: u32 = 1 << 4;
pub const MGMT_PHY_EDR_2M_5SLOT: u32 = 1 << 5;
pub const MGMT_PHY_EDR_3M_1SLOT: u32 = 1 << 6;
pub const MGMT_PHY_EDR_3M_3SLOT: u32 = 1 << 7;
pub const MGMT_PHY_EDR_3M_5SLOT: u32 = 1 << 8;
pub const MGMT_PHY_LE_1M_TX: u32 = 1 << 9;
pub const MGMT_PHY_LE_1M_RX: u32 = 1 << 10;
pub const MGMT_PHY_LE_2M_TX: u32 = 1 << 11;
pub const MGMT_PHY_LE_2M_RX: u32 = 1 << 12;
pub const MGMT_PHY_LE_CODED_TX: u32 = 1 << 13;
pub const MGMT_PHY_LE_CODED_RX: u32 = 1 << 14;

pub const MGMT_PHY_BREDR_MASK: u32 = MGMT_PHY_BR_1M_1SLOT
    | MGMT_PHY_BR_1M_3SLOT
    | MGMT_PHY_BR_1M_5SLOT
    | MGMT_PHY_EDR_2M_1SLOT
    | MGMT_PHY_EDR_2M_3SLOT
    | MGMT_PHY_EDR_2M_5SLOT
    | MGMT_PHY_EDR_3M_1SLOT
    | MGMT_PHY_EDR_3M_3SLOT
    | MGMT_PHY_EDR_3M_5SLOT;
pub const MGMT_PHY_LE_TX_MASK: u32 =
    MGMT_PHY_LE_1M_TX | MGMT_PHY_LE_2M_TX | MGMT_PHY_LE_CODED_TX;
pub const MGMT_PHY_LE_RX_MASK: u32 =
    MGMT_PHY_LE_1M_RX | MGMT_PHY_LE_2M_RX | MGMT_PHY_LE_CODED_RX;
pub const MGMT_PHY_LE_MASK: u32 = MGMT_PHY_LE_TX_MASK | MGMT_PHY_LE_RX_MASK;

/// Controller capability record types, keys of the TLV `READ_CONTROLLER_CAP`
/// answers with.
pub const MGMT_CAP_SEC_FLAGS: u16 = 0x01;
pub const MGMT_CAP_MAX_ENC_KEY_SIZE: u16 = 0x02;
pub const MGMT_CAP_SMP_MAX_ENC_KEY_SIZE: u16 = 0x03;
pub const MGMT_CAP_LE_TX_PWR: u16 = 0x04;

/// Per-device flags, read and written by the device-flags commands.
pub const MGMT_DEVICE_FLAG_REMOTE_WAKEUP: u32 = 1 << 0;
pub const MGMT_DEVICE_FLAG_DEVICE_PRIVACY: u32 = 1 << 1;
pub const MGMT_DEVICE_FLAG_ADDRESS_RESOLUTION: u32 = 1 << 2;
pub const MGMT_DEVICE_FLAG_PAST: u32 = 1 << 3;

/// Advertising monitor features.
pub const MGMT_ADV_MONITOR_FEATURE_MASK_OR_PATTERNS: u32 = 1 << 0;

/// Blocked key record types.
pub const HCI_BLOCKED_KEY_TYPE_LINKKEY: u8 = 0x00;
pub const HCI_BLOCKED_KEY_TYPE_LTK: u8 = 0x01;
pub const HCI_BLOCKED_KEY_TYPE_IRK: u8 = 0x02;

/// `ADD_DEVICE` action: report the device only, connect when it directs, or
/// keep connecting to it. BR/EDR accepts only the incoming-connection action.
pub const MGMT_DEV_ACTION_BACKGROUND_SCAN: u8 = 0x00;
pub const MGMT_DEV_ACTION_ALLOW_CONNECT: u8 = 0x01;
pub const MGMT_DEV_ACTION_AUTO_CONNECT: u8 = 0x02;

/// Highest `SET_IO_CAPABILITY` operand: keyboard with display.
pub const MGMT_IO_CAPABILITY_MAX: u8 = 0x04;

/// `DEVICE_FOUND` flags.
pub const MGMT_DEV_FOUND_CONFIRM_NAME: u32 = 1 << 0;
pub const MGMT_DEV_FOUND_LEGACY_PAIRING: u32 = 1 << 1;
pub const MGMT_DEV_FOUND_NOT_CONNECTABLE: u32 = 1 << 2;
pub const MGMT_DEV_FOUND_INITIATED_CONN: u32 = 1 << 3;
pub const MGMT_DEV_FOUND_NAME_REQUEST_FAILED: u32 = 1 << 4;
pub const MGMT_DEV_FOUND_SCAN_RSP: u32 = 1 << 5;

/// Discovery type: a bitmask over address types, not an enumeration. Only three
/// combinations are meaningful, and each demands the matching transport.
pub const DISCOV_TYPE_BREDR: u8 = 1 << BDADDR_BREDR;
pub const DISCOV_TYPE_LE: u8 = (1 << BDADDR_LE_PUBLIC) | (1 << BDADDR_LE_RANDOM);
pub const DISCOV_TYPE_INTERLEAVED: u8 = DISCOV_TYPE_BREDR | DISCOV_TYPE_LE;
