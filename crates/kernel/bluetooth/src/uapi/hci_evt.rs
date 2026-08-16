//! HCI event codes, the LE meta subevent codes, and the fixed prefix widths of
//! the events whose payload the core reads.

pub const HCI_EV_INQUIRY_COMPLETE:   u8 = 0x01;
pub const HCI_EV_INQUIRY_RESULT:     u8 = 0x02;
pub const HCI_EV_CONN_COMPLETE:      u8 = 0x03;
pub const HCI_EV_CONN_REQUEST:       u8 = 0x04;
pub const HCI_EV_DISCONN_COMPLETE:   u8 = 0x05;
pub const HCI_EV_AUTH_COMPLETE:      u8 = 0x06;
pub const HCI_EV_REMOTE_NAME:        u8 = 0x07;
pub const HCI_EV_ENCRYPT_CHANGE:     u8 = 0x08;
pub const HCI_EV_CHANGE_LINK_KEY_COMPLETE: u8 = 0x09;
pub const HCI_EV_REMOTE_FEATURES:    u8 = 0x0b;
pub const HCI_EV_REMOTE_VERSION:     u8 = 0x0c;
pub const HCI_EV_QOS_SETUP_COMPLETE: u8 = 0x0d;
pub const HCI_EV_CMD_COMPLETE:       u8 = 0x0e;
pub const HCI_EV_CMD_STATUS:         u8 = 0x0f;
pub const HCI_EV_HARDWARE_ERROR:     u8 = 0x10;
pub const HCI_EV_ROLE_CHANGE:        u8 = 0x12;
pub const HCI_EV_NUM_COMP_PKTS:      u8 = 0x13;
pub const HCI_EV_MODE_CHANGE:        u8 = 0x14;
pub const HCI_EV_PIN_CODE_REQ:       u8 = 0x16;
pub const HCI_EV_LINK_KEY_REQ:       u8 = 0x17;
pub const HCI_EV_LINK_KEY_NOTIFY:    u8 = 0x18;
pub const HCI_EV_CLOCK_OFFSET:       u8 = 0x1c;
pub const HCI_EV_PKT_TYPE_CHANGE:    u8 = 0x1d;
pub const HCI_EV_PSCAN_REP_MODE:     u8 = 0x20;
pub const HCI_EV_INQUIRY_RESULT_WITH_RSSI: u8 = 0x22;
pub const HCI_EV_REMOTE_EXT_FEATURES: u8 = 0x23;
pub const HCI_EV_SYNC_CONN_COMPLETE: u8 = 0x2c;
pub const HCI_EV_SYNC_CONN_CHANGED:  u8 = 0x2d;
pub const HCI_EV_SNIFF_SUBRATE:      u8 = 0x2e;
pub const HCI_EV_EXTENDED_INQUIRY_RESULT: u8 = 0x2f;
pub const HCI_EV_KEY_REFRESH_COMPLETE: u8 = 0x30;
pub const HCI_EV_IO_CAPA_REQUEST:    u8 = 0x31;
pub const HCI_EV_IO_CAPA_REPLY:      u8 = 0x32;
pub const HCI_EV_USER_CONFIRM_REQUEST: u8 = 0x33;
pub const HCI_EV_USER_PASSKEY_REQUEST: u8 = 0x34;
pub const HCI_EV_REMOTE_OOB_DATA_REQUEST: u8 = 0x35;
pub const HCI_EV_SIMPLE_PAIR_COMPLETE: u8 = 0x36;
pub const HCI_EV_USER_PASSKEY_NOTIFY: u8 = 0x3b;
pub const HCI_EV_KEYPRESS_NOTIFY:    u8 = 0x3c;
pub const HCI_EV_REMOTE_HOST_FEATURES: u8 = 0x3d;
pub const HCI_EV_LE_META:            u8 = 0x3e;
pub const HCI_EV_NUM_COMP_BLOCKS:    u8 = 0x48;
pub const HCI_EV_SYNC_TRAIN_COMPLETE: u8 = 0x4f;
pub const HCI_EV_VENDOR:             u8 = 0xff;

/// LE meta subevent code, the first payload byte of `HCI_EV_LE_META`.
pub const HCI_EV_LE_CONN_COMPLETE:        u8 = 0x01;
pub const HCI_EV_LE_ADVERTISING_REPORT:   u8 = 0x02;
pub const HCI_EV_LE_CONN_UPDATE_COMPLETE: u8 = 0x03;
pub const HCI_EV_LE_REMOTE_FEAT_COMPLETE: u8 = 0x04;
pub const HCI_EV_LE_LTK_REQ:              u8 = 0x05;
pub const HCI_EV_LE_REMOTE_CONN_PARAM_REQ: u8 = 0x06;
pub const HCI_EV_LE_DATA_LEN_CHANGE:      u8 = 0x07;
pub const HCI_EV_LE_ENHANCED_CONN_COMPLETE: u8 = 0x0a;
pub const HCI_EV_LE_DIRECT_ADV_REPORT:    u8 = 0x0b;
pub const HCI_EV_LE_PHY_UPDATE_COMPLETE:  u8 = 0x0c;
pub const HCI_EV_LE_EXT_ADV_REPORT:       u8 = 0x0d;
pub const HCI_EV_LE_PA_SYNC_ESTABLISHED:  u8 = 0x0e;
pub const HCI_EV_LE_PER_ADV_REPORT:       u8 = 0x0f;
pub const HCI_EV_LE_PA_SYNC_LOST:         u8 = 0x10;
pub const HCI_EV_LE_EXT_ADV_SET_TERM:     u8 = 0x12;

/// Fixed prefix widths of the events the core decodes. A shorter payload is a
/// malformed event and is dropped rather than parsed short.
pub const EV_CMD_COMPLETE_MIN:   usize = 3;
pub const EV_CMD_STATUS_LEN:     usize = 4;
pub const EV_DISCONN_COMPLETE_LEN: usize = 4;
pub const EV_CONN_COMPLETE_LEN:  usize = 11;
pub const EV_CONN_REQUEST_LEN:   usize = 10;
pub const EV_ENCRYPT_CHANGE_LEN: usize = 4;
pub const EV_AUTH_COMPLETE_LEN:  usize = 3;
pub const EV_NUM_COMP_PKTS_MIN:  usize = 1;
pub const EV_LE_CONN_COMPLETE_LEN: usize = 18;
pub const EV_LE_META_MIN:        usize = 1;

/// Number of bits in the two event-mask words a raw HCI socket filters with.
pub const HCI_FLT_EVENT_BITS: u32 = 63;
/// Number of packet-type bits in a raw HCI socket's type mask.
pub const HCI_FLT_TYPE_BITS: u32 = 31;

#[cfg(test)]
#[path = "tests/hci_evt.rs"]
mod tests;
