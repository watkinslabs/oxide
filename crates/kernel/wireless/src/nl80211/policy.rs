// Per-command attribute policies. These are what the controller reports for
// a policy dump, and what a caller checks a request against before reading
// any of its attributes.
//
// A policy is not decoration: `wpa_supplicant` asks the controller for them
// and adapts, so a policy that claims a type the handler does not really
// accept makes userspace send something the kernel then rejects.

use netlink::genetlink::family::PolicyEntry;
use netlink::genetlink::uapi::policy_type as t;

use crate::ieee80211::{ADDR_LEN, MAX_SSID_LEN};
use crate::uapi::attr as a;

/// Fixed-width entry for an integer attribute.
const fn int(attr: u16, kind: u32, width: u32) -> PolicyEntry {
    PolicyEntry { attr, kind, min_len: width, max_len: width }
}
/// Variable-width entry for a byte string.
const fn bin(attr: u16, min_len: u32, max_len: u32) -> PolicyEntry {
    PolicyEntry { attr, kind: t::NL_ATTR_TYPE_BINARY, min_len, max_len }
}
/// A flag attribute, which carries no payload at all.
const fn flag(attr: u16) -> PolicyEntry {
    PolicyEntry { attr, kind: t::NL_ATTR_TYPE_FLAG, min_len: 0, max_len: 0 }
}
/// A NUL-terminated string.
const fn text(attr: u16, max_len: u32) -> PolicyEntry {
    PolicyEntry { attr, kind: t::NL_ATTR_TYPE_NUL_STRING, min_len: 0, max_len }
}
/// A nested container.
const fn nest(attr: u16) -> PolicyEntry {
    PolicyEntry { attr, kind: t::NL_ATTR_TYPE_NESTED, min_len: 0, max_len: u32::MAX }
}
/// An address.
const fn mac(attr: u16) -> PolicyEntry { bin(attr, ADDR_LEN as u32, ADDR_LEN as u32) }

const U8: u32 = t::NL_ATTR_TYPE_U8;
const U16: u32 = t::NL_ATTR_TYPE_U16;
const U32: u32 = t::NL_ATTR_TYPE_U32;
const U64: u32 = t::NL_ATTR_TYPE_U64;

/// Longest interface name the kernel accepts, including the terminator.
pub const IFNAMSIZ: u32 = 16;
/// Longest physical-radio name accepted by `SET_WIPHY`, excluding the terminator.
pub const WIPHY_NAME_MAX_LEN: usize = 19;
/// Longest element blob a request may attach.
pub const MAX_IE_LEN: u32 = 4096;

/// The three attributes that address a radio or an interface. Every command
/// accepts them, so every policy starts with them.
const ADDRESSING: [PolicyEntry; 4] = [
    int(a::WIPHY, U32, 4),
    int(a::IFINDEX, U32, 4),
    int(a::WDEV, U64, 8),
    text(a::IFNAME, IFNAMSIZ),
];

/// A command taking no attributes beyond the addressing.
pub const EMPTY: &[PolicyEntry] = &ADDRESSING;

/// `GET_WIPHY` and `SET_WIPHY`.
pub const WIPHY: &[PolicyEntry] = &[
    ADDRESSING[0], ADDRESSING[1], ADDRESSING[2], ADDRESSING[3],
    text(a::WIPHY_NAME, WIPHY_NAME_MAX_LEN as u32),
    int(a::WIPHY_TXQ_PARAMS, U32, 4),
    int(a::WIPHY_FREQ, U32, 4),
    int(a::WIPHY_FREQ_OFFSET, U32, 4),
    int(a::WIPHY_CHANNEL_TYPE, U32, 4),
    int(a::CHANNEL_WIDTH, U32, 4),
    int(a::CENTER_FREQ1, U32, 4),
    int(a::CENTER_FREQ2, U32, 4),
    int(a::WIPHY_RETRY_SHORT, U8, 1),
    int(a::WIPHY_RETRY_LONG, U8, 1),
    int(a::WIPHY_FRAG_THRESHOLD, U32, 4),
    int(a::WIPHY_RTS_THRESHOLD, U32, 4),
    int(a::WIPHY_COVERAGE_CLASS, U8, 1),
    int(a::WIPHY_TX_POWER_SETTING, U32, 4),
    int(a::WIPHY_TX_POWER_LEVEL, U32, 4),
    int(a::WIPHY_ANTENNA_TX, U32, 4),
    int(a::WIPHY_ANTENNA_RX, U32, 4),
    int(a::TXQ_LIMIT, U32, 4),
    int(a::TXQ_MEMORY_LIMIT, U32, 4),
    int(a::TXQ_QUANTUM, U32, 4),
    flag(a::SPLIT_WIPHY_DUMP),
];

/// The interface commands.
pub const IFACE: &[PolicyEntry] = &[
    ADDRESSING[0], ADDRESSING[1], ADDRESSING[2], ADDRESSING[3],
    int(a::IFTYPE, U32, 4),
    mac(a::MAC),
    int(a::_4ADDR, U8, 1),
    nest(a::MNTR_FLAGS),
    flag(a::SOCKET_OWNER),
    int(a::PS_STATE, U32, 4),
    nest(a::CQM),
    int(a::WIPHY_FREQ, U32, 4),
    int(a::CHANNEL_WIDTH, U32, 4),
    int(a::CENTER_FREQ1, U32, 4),
    int(a::CENTER_FREQ2, U32, 4),
    int(a::WIPHY_CHANNEL_TYPE, U32, 4),
];

/// The key commands.
pub const KEY: &[PolicyEntry] = &[
    ADDRESSING[0], ADDRESSING[1], ADDRESSING[2], ADDRESSING[3],
    nest(a::KEY),
    bin(a::KEY_DATA, 0, crate::uapi::ciphers::MAX_KEY_LEN as u32),
    int(a::KEY_IDX, U8, 1),
    int(a::KEY_CIPHER, U32, 4),
    bin(a::KEY_SEQ, 0, crate::uapi::ciphers::MAX_PN_LEN as u32),
    flag(a::KEY_DEFAULT),
    flag(a::KEY_DEFAULT_MGMT),
    int(a::KEY_TYPE, U32, 4),
    nest(a::KEY_DEFAULT_TYPES),
    mac(a::MAC),
    int(a::VLAN_ID, U16, 2),
];

/// The scan commands.
pub const SCAN: &[PolicyEntry] = &[
    ADDRESSING[0], ADDRESSING[1], ADDRESSING[2], ADDRESSING[3],
    nest(a::SCAN_SSIDS),
    nest(a::SCAN_FREQUENCIES),
    bin(a::IE, 0, MAX_IE_LEN),
    int(a::SCAN_FLAGS, U32, 4),
    mac(a::MAC),
    mac(a::MAC_MASK),
    int(a::MEASUREMENT_DURATION, U16, 2),
    flag(a::MEASUREMENT_DURATION_MANDATORY),
    mac(a::BSSID),
];

/// The connect and management-exchange commands.
pub const CONNECT: &[PolicyEntry] = &[
    ADDRESSING[0], ADDRESSING[1], ADDRESSING[2], ADDRESSING[3],
    bin(a::SSID, 0, MAX_SSID_LEN as u32),
    mac(a::MAC),
    mac(a::BSSID),
    mac(a::MAC_HINT),
    mac(a::PREV_BSSID),
    int(a::WIPHY_FREQ, U32, 4),
    int(a::WIPHY_FREQ_HINT, U32, 4),
    int(a::AUTH_TYPE, U32, 4),
    flag(a::PRIVACY),
    int(a::WPA_VERSIONS, U32, 4),
    int(a::CIPHER_SUITE_GROUP, U32, 4),
    bin(a::CIPHER_SUITES_PAIRWISE, 0, u32::MAX),
    bin(a::AKM_SUITES, 0, u32::MAX),
    bin(a::IE, 0, MAX_IE_LEN),
    bin(a::AUTH_DATA, 0, MAX_IE_LEN),
    int(a::USE_MFP, U32, 4),
    int(a::REASON_CODE, U16, 2),
    flag(a::LOCAL_STATE_CHANGE),
    flag(a::WANT_1X_4WAY_HS),
    flag(a::CONTROL_PORT),
    int(a::CONTROL_PORT_ETHERTYPE, U16, 2),
    flag(a::CONTROL_PORT_NO_ENCRYPT),
    flag(a::CONTROL_PORT_OVER_NL80211),
];

/// The station commands.
pub const STATION: &[PolicyEntry] = &[
    ADDRESSING[0], ADDRESSING[1], ADDRESSING[2], ADDRESSING[3],
    mac(a::MAC),
    int(a::STA_AID, U16, 2),
    nest(a::STA_FLAGS2),
    nest(a::STA_FLAGS),
    int(a::STA_LISTEN_INTERVAL, U16, 2),
    bin(a::STA_SUPPORTED_RATES, 0, 32),
    bin(a::HT_CAPABILITY, 0, 26),
    bin(a::VHT_CAPABILITY, 0, 12),
    int(a::STA_PLINK_ACTION, U8, 1),
    int(a::STA_PLINK_STATE, U8, 1),
    int(a::VLAN_ID, U16, 2),
    int(a::REASON_CODE, U16, 2),
    int(a::STA_CAPABILITY, U16, 2),
    bin(a::STA_EXT_CAPABILITY, 0, u32::MAX),
    int(a::AIRTIME_WEIGHT, U16, 2),
    int(a::OPMODE_NOTIF, U8, 1),
];

/// The regulatory commands.
pub const REG: &[PolicyEntry] = &[
    ADDRESSING[0], ADDRESSING[1], ADDRESSING[2], ADDRESSING[3],
    bin(a::REG_ALPHA2, 2, 3),
    nest(a::REG_RULES),
    int(a::DFS_REGION, U8, 1),
    int(a::USER_REG_HINT_TYPE, U32, 4),
    flag(a::REG_INDOOR),
];

/// The access-point commands.
pub const AP: &[PolicyEntry] = &[
    ADDRESSING[0], ADDRESSING[1], ADDRESSING[2], ADDRESSING[3],
    bin(a::BEACON_HEAD, 0, u32::MAX),
    bin(a::BEACON_TAIL, 0, u32::MAX),
    int(a::BEACON_INTERVAL, U32, 4),
    int(a::DTIM_PERIOD, U32, 4),
    bin(a::SSID, 0, MAX_SSID_LEN as u32),
    int(a::HIDDEN_SSID, U32, 4),
    flag(a::PRIVACY),
    int(a::AUTH_TYPE, U32, 4),
    int(a::INACTIVITY_TIMEOUT, U16, 2),
    bin(a::IE_PROBE_RESP, 0, MAX_IE_LEN),
    bin(a::IE_ASSOC_RESP, 0, MAX_IE_LEN),
    int(a::WIPHY_FREQ, U32, 4),
    int(a::CHANNEL_WIDTH, U32, 4),
    int(a::CENTER_FREQ1, U32, 4),
    int(a::CENTER_FREQ2, U32, 4),
    int(a::BSS_CTS_PROT, U8, 1),
    int(a::BSS_SHORT_PREAMBLE, U8, 1),
    int(a::BSS_SHORT_SLOT_TIME, U8, 1),
    bin(a::BSS_BASIC_RATES, 0, 32),
    int(a::AP_ISOLATE, U8, 1),
    int(a::BSS_HT_OPMODE, U16, 2),
];

/// The management-frame commands.
pub const MGMT: &[PolicyEntry] = &[
    ADDRESSING[0], ADDRESSING[1], ADDRESSING[2], ADDRESSING[3],
    int(a::FRAME_TYPE, U16, 2),
    bin(a::FRAME_MATCH, 0, MAX_IE_LEN),
    bin(a::FRAME, 0, u32::MAX),
    int(a::WIPHY_FREQ, U32, 4),
    int(a::DURATION, U32, 4),
    flag(a::OFFCHANNEL_TX_OK),
    flag(a::TX_NO_CCK_RATE),
    flag(a::DONT_WAIT_FOR_ACK),
    int(a::COOKIE, U64, 8),
    flag(a::RECEIVE_MULTICAST),
];
