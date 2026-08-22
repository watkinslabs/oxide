//! HCI command opcodes and the opcode packing rule.
//!
//! An opcode is an OGF/OCF pair packed into one 16-bit word: the group in the
//! top six bits, the command in the low ten. Every constant below is the packed
//! form, because that is what goes on the wire and what a filter matches.

/// Opcode-group field, the top six bits of an opcode.
pub const OGF_LINK_CTL:    u16 = 0x01;
pub const OGF_LINK_POLICY: u16 = 0x02;
pub const OGF_HOST_CTL:    u16 = 0x03;
pub const OGF_INFO_PARAM:  u16 = 0x04;
pub const OGF_STATUS_PARAM: u16 = 0x05;
pub const OGF_LE_CTL:      u16 = 0x08;
pub const OGF_VENDOR:      u16 = 0x3f;

/// Width of the opcode-command field; the group occupies the bits above it.
pub const OCF_BITS: u32 = 10;
pub const OCF_MASK: u16 = (1 << OCF_BITS) - 1;

/// Pack a group and command into the wire opcode. # C: O(1)
pub const fn opcode_pack(ogf: u16, ocf: u16) -> u16 { (ocf & OCF_MASK) | (ogf << OCF_BITS) }

/// Group half of a wire opcode. # C: O(1)
pub const fn opcode_ogf(opcode: u16) -> u16 { opcode >> OCF_BITS }

/// Command half of a wire opcode. # C: O(1)
pub const fn opcode_ocf(opcode: u16) -> u16 { opcode & OCF_MASK }

/// The opcode a command-status or command-complete event reports when the
/// credit change belongs to no command — a controller-initiated credit grant.
pub const HCI_OP_NOP: u16 = 0x0000;

// Link control (OGF 0x01).
pub const HCI_OP_INQUIRY:              u16 = 0x0401;
pub const HCI_OP_INQUIRY_CANCEL:       u16 = 0x0402;
pub const HCI_OP_CREATE_CONN:          u16 = 0x0405;
pub const HCI_OP_DISCONNECT:           u16 = 0x0406;
pub const HCI_OP_CREATE_CONN_CANCEL:   u16 = 0x0408;
pub const HCI_OP_ACCEPT_CONN_REQ:      u16 = 0x0409;
pub const HCI_OP_REJECT_CONN_REQ:      u16 = 0x040a;
pub const HCI_OP_LINK_KEY_REPLY:       u16 = 0x040b;
pub const HCI_OP_LINK_KEY_NEG_REPLY:   u16 = 0x040c;
pub const HCI_OP_PIN_CODE_REPLY:       u16 = 0x040d;
pub const HCI_OP_PIN_CODE_NEG_REPLY:   u16 = 0x040e;
pub const HCI_OP_AUTH_REQUESTED:       u16 = 0x0411;
pub const HCI_OP_SET_CONN_ENCRYPT:     u16 = 0x0413;
pub const HCI_OP_REMOTE_NAME_REQ:      u16 = 0x0419;
pub const HCI_OP_READ_REMOTE_FEATURES: u16 = 0x041b;
pub const HCI_OP_READ_REMOTE_EXT_FEATURES: u16 = 0x041c;
pub const HCI_OP_READ_REMOTE_VERSION:  u16 = 0x041d;
pub const HCI_OP_SETUP_SYNC_CONN:      u16 = 0x0428;
pub const HCI_OP_ACCEPT_SYNC_CONN_REQ: u16 = 0x0429;
pub const HCI_OP_IO_CAPABILITY_REPLY:  u16 = 0x042b;
pub const HCI_OP_USER_CONFIRM_REPLY:   u16 = 0x042c;
pub const HCI_OP_USER_CONFIRM_NEG_REPLY: u16 = 0x042d;
pub const HCI_OP_USER_PASSKEY_REPLY:   u16 = 0x042e;
pub const HCI_OP_USER_PASSKEY_NEG_REPLY: u16 = 0x042f;
pub const HCI_OP_IO_CAPABILITY_NEG_REPLY: u16 = 0x0434;
pub const HCI_OP_ENHANCED_SETUP_SYNC_CONN: u16 = 0x043d;

// Link policy (OGF 0x02).
pub const HCI_OP_SNIFF_MODE:           u16 = 0x0803;
pub const HCI_OP_EXIT_SNIFF_MODE:      u16 = 0x0804;
pub const HCI_OP_ROLE_DISCOVERY:       u16 = 0x0809;
pub const HCI_OP_SWITCH_ROLE:          u16 = 0x080b;
pub const HCI_OP_READ_LINK_POLICY:     u16 = 0x080c;
pub const HCI_OP_WRITE_LINK_POLICY:    u16 = 0x080d;
pub const HCI_OP_READ_DEF_LINK_POLICY: u16 = 0x080e;
pub const HCI_OP_WRITE_DEF_LINK_POLICY: u16 = 0x080f;

// Controller and baseband (OGF 0x03).
pub const HCI_OP_SET_EVENT_MASK:       u16 = 0x0c01;
pub const HCI_OP_RESET:                u16 = 0x0c03;
pub const HCI_OP_SET_EVENT_FLT:        u16 = 0x0c05;
pub const HCI_OP_READ_STORED_LINK_KEY: u16 = 0x0c0d;
pub const HCI_OP_DELETE_STORED_LINK_KEY: u16 = 0x0c12;
pub const HCI_OP_WRITE_LOCAL_NAME:     u16 = 0x0c13;
pub const HCI_OP_READ_LOCAL_NAME:      u16 = 0x0c14;
pub const HCI_OP_WRITE_CA_TIMEOUT:     u16 = 0x0c16;
pub const HCI_OP_WRITE_PAGE_TIMEOUT:   u16 = 0x0c18;
pub const HCI_OP_WRITE_SCAN_ENABLE:    u16 = 0x0c1a;
pub const HCI_OP_READ_PAGE_SCAN_ACTIVITY: u16 = 0x0c1b;
pub const HCI_OP_WRITE_PAGE_SCAN_ACTIVITY: u16 = 0x0c1c;
pub const HCI_OP_READ_CLASS_OF_DEV:    u16 = 0x0c23;
pub const HCI_OP_WRITE_CLASS_OF_DEV:   u16 = 0x0c24;
pub const HCI_OP_READ_VOICE_SETTING:   u16 = 0x0c25;
pub const HCI_OP_WRITE_VOICE_SETTING:  u16 = 0x0c26;
pub const HCI_OP_WRITE_AUTH_ENABLE:    u16 = 0x0c20;
pub const HCI_OP_WRITE_SYNC_FLOWCTL:   u16 = 0x0c2f;
pub const HCI_OP_READ_NUM_SUPPORTED_IAC: u16 = 0x0c38;
pub const HCI_OP_READ_CURRENT_IAC_LAP: u16 = 0x0c39;
pub const HCI_OP_WRITE_INQUIRY_MODE:   u16 = 0x0c45;
pub const HCI_OP_READ_PAGE_SCAN_TYPE:  u16 = 0x0c46;
pub const HCI_OP_WRITE_EIR:            u16 = 0x0c52;
pub const HCI_OP_WRITE_SSP_MODE:       u16 = 0x0c56;
pub const HCI_OP_READ_INQ_RSP_TX_POWER: u16 = 0x0c58;
pub const HCI_OP_READ_DEF_ERR_DATA_REPORTING:  u16 = 0x0c5a;
pub const HCI_OP_WRITE_DEF_ERR_DATA_REPORTING: u16 = 0x0c5b;
pub const HCI_OP_SET_EVENT_MASK_PAGE_2: u16 = 0x0c63;
pub const HCI_OP_WRITE_LE_HOST_SUPPORTED: u16 = 0x0c6d;
pub const HCI_OP_READ_SYNC_TRAIN_PARAMS: u16 = 0x0c77;
pub const HCI_OP_WRITE_SC_SUPPORT:     u16 = 0x0c7a;

// Informational parameters (OGF 0x04).
pub const HCI_OP_READ_LOCAL_VERSION:   u16 = 0x1001;
pub const HCI_OP_READ_LOCAL_COMMANDS:  u16 = 0x1002;
pub const HCI_OP_READ_LOCAL_FEATURES:  u16 = 0x1003;
pub const HCI_OP_READ_LOCAL_EXT_FEATURES: u16 = 0x1004;
pub const HCI_OP_READ_BUFFER_SIZE:     u16 = 0x1005;
pub const HCI_OP_READ_BD_ADDR:         u16 = 0x1009;
pub const HCI_OP_READ_LOCAL_CODECS:    u16 = 0x100b;
pub const HCI_OP_READ_LOCAL_PAIRING_OPTS: u16 = 0x100c;

// Status parameters (OGF 0x05).
pub const HCI_OP_READ_RSSI:            u16 = 0x1405;
pub const HCI_OP_READ_CLOCK:           u16 = 0x1407;
pub const HCI_OP_GET_MWS_TRANSPORT_CONFIG: u16 = 0x140c;

// LE controller (OGF 0x08).
pub const HCI_OP_LE_SET_EVENT_MASK:    u16 = 0x2001;
pub const HCI_OP_LE_READ_BUFFER_SIZE:  u16 = 0x2002;
pub const HCI_OP_LE_READ_LOCAL_FEATURES: u16 = 0x2003;
pub const HCI_OP_LE_SET_RANDOM_ADDR:   u16 = 0x2005;
pub const HCI_OP_LE_SET_ADV_PARAM:     u16 = 0x2006;
pub const HCI_OP_LE_READ_ADV_TX_POWER: u16 = 0x2007;
pub const HCI_OP_LE_SET_ADV_DATA:      u16 = 0x2008;
pub const HCI_OP_LE_SET_SCAN_RSP_DATA: u16 = 0x2009;
pub const HCI_OP_LE_SET_ADV_ENABLE:    u16 = 0x200a;
pub const HCI_OP_LE_SET_SCAN_PARAM:    u16 = 0x200b;
pub const HCI_OP_LE_SET_SCAN_ENABLE:   u16 = 0x200c;
pub const HCI_OP_LE_CREATE_CONN:       u16 = 0x200d;
pub const HCI_OP_LE_CREATE_CONN_CANCEL: u16 = 0x200e;
pub const HCI_OP_LE_READ_ACCEPT_LIST_SIZE: u16 = 0x200f;
pub const HCI_OP_LE_CLEAR_ACCEPT_LIST: u16 = 0x2010;
pub const HCI_OP_LE_ADD_TO_ACCEPT_LIST: u16 = 0x2011;
pub const HCI_OP_LE_DEL_FROM_ACCEPT_LIST: u16 = 0x2012;
pub const HCI_OP_LE_CONN_UPDATE:       u16 = 0x2013;
pub const HCI_OP_LE_READ_REMOTE_FEATURES: u16 = 0x2016;
pub const HCI_OP_LE_START_ENC:         u16 = 0x2019;
pub const HCI_OP_LE_LTK_REPLY:         u16 = 0x201a;
pub const HCI_OP_LE_LTK_NEG_REPLY:     u16 = 0x201b;
pub const HCI_OP_LE_READ_SUPPORTED_STATES: u16 = 0x201c;
pub const HCI_OP_LE_READ_DEF_DATA_LEN: u16 = 0x2023;
pub const HCI_OP_LE_WRITE_DEF_DATA_LEN: u16 = 0x2024;
pub const HCI_OP_LE_CLEAR_RESOLV_LIST: u16 = 0x2029;
pub const HCI_OP_LE_READ_RESOLV_LIST_SIZE: u16 = 0x202a;
pub const HCI_OP_LE_SET_RPA_TIMEOUT:   u16 = 0x202e;
pub const HCI_OP_LE_READ_MAX_DATA_LEN: u16 = 0x202f;
pub const HCI_OP_LE_SET_DEFAULT_PHY:   u16 = 0x2031;
pub const HCI_OP_LE_READ_NUM_SUPPORTED_ADV_SETS: u16 = 0x203b;
pub const HCI_OP_LE_READ_TRANSMIT_POWER: u16 = 0x204b;
pub const HCI_OP_LE_READ_BUFFER_SIZE_V2: u16 = 0x2060;
pub const HCI_OP_LE_SET_HOST_FEATURE:  u16 = 0x2074;

/// `HCI_OP_WRITE_SCAN_ENABLE` operand bits: page scan makes the controller
/// connectable, inquiry scan makes it discoverable.
pub const SCAN_DISABLED:   u8 = 0x00;
pub const SCAN_INQUIRY:    u8 = 0x01;
pub const SCAN_PAGE:       u8 = 0x02;

/// `HCI_OP_LE_SET_SCAN_ENABLE` operands.
pub const LE_SCAN_DISABLE: u8 = 0x00;
pub const LE_SCAN_ENABLE:  u8 = 0x01;
pub const LE_SCAN_PASSIVE: u8 = 0x00;
pub const LE_SCAN_ACTIVE:  u8 = 0x01;

/// `HCI_OP_LE_SET_ADV_ENABLE` operands.
pub const LE_ADV_DISABLE: u8 = 0x00;
pub const LE_ADV_ENABLE:  u8 = 0x01;

/// `HCI_OP_WRITE_INQUIRY_MODE` operands.
pub const HCI_INQUIRY_MODE_STANDARD: u8 = 0x00;
pub const HCI_INQUIRY_MODE_RSSI:     u8 = 0x01;
pub const HCI_INQUIRY_MODE_EXTENDED: u8 = 0x02;

#[cfg(test)]
#[path = "tests/hci_cmd.rs"]
mod tests;
