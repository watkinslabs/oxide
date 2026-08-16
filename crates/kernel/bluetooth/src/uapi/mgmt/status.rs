//! Management status byte. Every command answer carries one; the mapping from
//! a controller status and from an internal errno lives in `mgmt::status`.

pub const MGMT_STATUS_SUCCESS:           u8 = 0x00;
pub const MGMT_STATUS_UNKNOWN_COMMAND:   u8 = 0x01;
pub const MGMT_STATUS_NOT_CONNECTED:     u8 = 0x02;
pub const MGMT_STATUS_FAILED:            u8 = 0x03;
pub const MGMT_STATUS_CONNECT_FAILED:    u8 = 0x04;
pub const MGMT_STATUS_AUTH_FAILED:       u8 = 0x05;
pub const MGMT_STATUS_NOT_PAIRED:        u8 = 0x06;
pub const MGMT_STATUS_NO_RESOURCES:      u8 = 0x07;
pub const MGMT_STATUS_TIMEOUT:           u8 = 0x08;
pub const MGMT_STATUS_ALREADY_CONNECTED: u8 = 0x09;
pub const MGMT_STATUS_BUSY:              u8 = 0x0a;
pub const MGMT_STATUS_REJECTED:          u8 = 0x0b;
pub const MGMT_STATUS_NOT_SUPPORTED:     u8 = 0x0c;
pub const MGMT_STATUS_INVALID_PARAMS:    u8 = 0x0d;
pub const MGMT_STATUS_DISCONNECTED:      u8 = 0x0e;
pub const MGMT_STATUS_NOT_POWERED:       u8 = 0x0f;
pub const MGMT_STATUS_CANCELLED:         u8 = 0x10;
pub const MGMT_STATUS_INVALID_INDEX:     u8 = 0x11;
pub const MGMT_STATUS_RFKILLED:          u8 = 0x12;
pub const MGMT_STATUS_ALREADY_PAIRED:    u8 = 0x13;
pub const MGMT_STATUS_PERMISSION_DENIED: u8 = 0x14;
