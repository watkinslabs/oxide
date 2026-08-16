//! Raw HCI socket ABI: the address, the channels, the filter, the options and
//! the device-management ioctls.

/// `struct sockaddr_hci`: family, device index, channel. Padded to the family's
/// address width by the socket layer, never by this module.
pub const SOCKADDR_HCI_LEN: usize = 6;
pub const SOCKADDR_HCI_DEV_OFF: usize = 2;
pub const SOCKADDR_HCI_CHANNEL_OFF: usize = 4;

/// Device index meaning "no controller", used by the monitor and control
/// channels which are not bound to one.
pub const HCI_DEV_NONE: u16 = 0xffff;

/// Socket channel, the third field of the address. The channel decides what the
/// socket carries and is fixed at bind.
pub const HCI_CHANNEL_RAW:     u16 = 0;
pub const HCI_CHANNEL_USER:    u16 = 1;
pub const HCI_CHANNEL_MONITOR: u16 = 2;
pub const HCI_CHANNEL_CONTROL: u16 = 3;
pub const HCI_CHANNEL_LOGGING: u16 = 4;

/// `SOL_HCI` option numbers.
pub const HCI_DATA_DIR:   u32 = 1;
pub const HCI_FILTER:     u32 = 2;
pub const HCI_TIME_STAMP: u32 = 3;

/// Ancillary data a raw socket attaches when the matching option is on.
pub const HCI_CMSG_DIR:    u32 = 0x01;
pub const HCI_CMSG_TSTAMP: u32 = 0x02;

/// `struct hci_ufilter`: a 32-bit packet-type mask, two 32-bit event-mask words,
/// then the opcode a command filter matches.
pub const HCI_UFILTER_LEN: usize = 14;
pub const HCI_UFILTER_TYPE_MASK_OFF:  usize = 0;
pub const HCI_UFILTER_EVENT_MASK_OFF: usize = 4;
pub const HCI_UFILTER_OPCODE_OFF:     usize = 12;

/// Filter field widths, as bit counts. A bit index past the width is ignored
/// rather than wrapping, which is what makes the mask a mask and not a modulus.
pub const HCI_FLT_TYPE_BITS:  u32 = 31;
pub const HCI_FLT_EVENT_BITS: u32 = 63;
pub const HCI_FLT_OGF_BITS:   u32 = 63;
pub const HCI_FLT_OCF_BITS:   u32 = 127;

/// Device-management ioctls. The numbers are the `'H'`-typed sequence the
/// device-management tooling issues.
pub const HCIDEVUP:       u32 = 201;
pub const HCIDEVDOWN:     u32 = 202;
pub const HCIDEVRESET:    u32 = 203;
pub const HCIDEVRESTAT:   u32 = 204;
pub const HCIGETDEVLIST:  u32 = 210;
pub const HCIGETDEVINFO:  u32 = 211;
pub const HCIGETCONNLIST: u32 = 212;
pub const HCIGETCONNINFO: u32 = 213;
pub const HCIGETAUTHINFO: u32 = 215;
pub const HCISETRAW:      u32 = 220;
pub const HCISETSCAN:     u32 = 221;
pub const HCISETAUTH:     u32 = 222;
pub const HCISETENCRYPT:  u32 = 223;
pub const HCISETPTYPE:    u32 = 224;
pub const HCISETLINKPOL:  u32 = 225;
pub const HCISETLINKMODE: u32 = 226;
pub const HCISETACLMTU:   u32 = 227;
pub const HCISETSCOMTU:   u32 = 228;
pub const HCIBLOCKADDR:   u32 = 230;
pub const HCIUNBLOCKADDR: u32 = 231;
pub const HCIINQUIRY:     u32 = 240;

/// `struct hci_dev_stats`: ten 32-bit counters.
pub const HCI_DEV_STATS_LEN: usize = 40;

/// `struct hci_dev_info` field offsets and total width.
pub const HCI_DEV_INFO_LEN: usize = 92;
pub const DEV_INFO_DEV_ID_OFF:      usize = 0;
pub const DEV_INFO_NAME_OFF:        usize = 2;
pub const DEV_INFO_NAME_LEN:        usize = 8;
pub const DEV_INFO_BDADDR_OFF:      usize = 10;
pub const DEV_INFO_FLAGS_OFF:       usize = 16;
pub const DEV_INFO_TYPE_OFF:        usize = 20;
pub const DEV_INFO_FEATURES_OFF:    usize = 21;
pub const DEV_INFO_FEATURES_LEN:    usize = 8;
pub const DEV_INFO_PKT_TYPE_OFF:    usize = 32;
pub const DEV_INFO_LINK_POLICY_OFF: usize = 36;
pub const DEV_INFO_LINK_MODE_OFF:   usize = 40;
pub const DEV_INFO_ACL_MTU_OFF:     usize = 44;
pub const DEV_INFO_ACL_PKTS_OFF:    usize = 46;
pub const DEV_INFO_SCO_MTU_OFF:     usize = 48;
pub const DEV_INFO_SCO_PKTS_OFF:    usize = 50;
pub const DEV_INFO_STAT_OFF:        usize = 52;

/// `struct hci_dev_req`: index then a 32-bit option operand.
pub const HCI_DEV_REQ_LEN: usize = 6;

/// `struct hci_conn_info`: handle, address, type, direction, state, link mode.
pub const HCI_CONN_INFO_LEN: usize = 16;
pub const CONN_INFO_HANDLE_OFF:    usize = 0;
pub const CONN_INFO_BDADDR_OFF:    usize = 2;
pub const CONN_INFO_TYPE_OFF:      usize = 8;
pub const CONN_INFO_OUT_OFF:       usize = 9;
pub const CONN_INFO_STATE_OFF:     usize = 10;
pub const CONN_INFO_LINK_MODE_OFF: usize = 12;

/// Device-state flag bits reported by `HCIGETDEVINFO`.
pub const HCI_UP:      u32 = 0;
pub const HCI_INIT:    u32 = 1;
pub const HCI_RUNNING: u32 = 2;
pub const HCI_PSCAN:   u32 = 3;
pub const HCI_ISCAN:   u32 = 4;
pub const HCI_AUTH:    u32 = 5;
pub const HCI_ENCRYPT: u32 = 6;
pub const HCI_INQUIRY: u32 = 7;
pub const HCI_RAW:     u32 = 8;
pub const HCI_RESET:   u32 = 9;

#[cfg(test)]
#[path = "tests/hci_sock.rs"]
mod tests;
