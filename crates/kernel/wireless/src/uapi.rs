// nl80211 ABI numbers — the wire contract `wpa_supplicant`, `iw` and
// NetworkManager speak. Nothing here decides anything; every value is a
// number userspace already knows.
//
// Module manifest:
// - `cmd`:     `NL80211_CMD_*` command numbers and the family identity.
// - `attr`:    `NL80211_ATTR_*` top-level attribute numbers.
// - `nested`:  the nested attribute spaces (bss, sta_info, band, freq, key, …).
// - `enums`:   value enumerations carried inside attributes (iftype, width, …).
// - `ciphers`: cipher and AKM suite selectors.

#[path = "uapi/cmd.rs"]
pub mod cmd;
#[path = "uapi/attr.rs"]
pub mod attr;
#[path = "uapi/nested.rs"]
pub mod nested;
#[path = "uapi/enums.rs"]
pub mod enums;
#[path = "uapi/ciphers.rs"]
pub mod ciphers;

pub use cmd::{NL80211_FAMILY_NAME, NL80211_FAMILY_VERSION};
