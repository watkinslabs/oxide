// The nl80211 generic-netlink family: the whole interface `wpa_supplicant`,
// `iw` and NetworkManager use.
//
// Module manifest:
// - `msg`:      message framing and the attribute writers shared by commands.
// - `family`:   the op table, the multicast groups, and registration.
// - `policy`:   per-command attribute policies reported by the controller.
// - `resolve`:  turning the radio/interface attributes into the objects.
// - `wiphy_cmd`:   radio query and configuration.
// - `iface_cmd`:   interface creation, query, change and removal.
// - `scan_cmd`:    scan trigger, results and abort.
// - `connect_cmd`: connect, disconnect, and the raw management exchanges.
// - `key_cmd`:     key installation and default selection.
// - `station_cmd`: station query and modification, and channel surveys.
// - `reg_cmd`:     regulatory query and hints.
// - `ap_cmd`:      access-point start and stop.
// - `mgmt_cmd`:    management frame registration and transmission.
// - `event`:       the multicast notifications the stack raises.

#[path = "nl80211/msg.rs"]
pub mod msg;
#[path = "nl80211/policy.rs"]
pub mod policy;
#[path = "nl80211/family.rs"]
pub mod family;
#[path = "nl80211/resolve.rs"]
pub mod resolve;
#[path = "nl80211/wiphy_cmd.rs"]
pub mod wiphy_cmd;
#[path = "nl80211/iface_cmd.rs"]
pub mod iface_cmd;
#[path = "nl80211/scan_cmd.rs"]
pub mod scan_cmd;
#[path = "nl80211/connect_cmd.rs"]
pub mod connect_cmd;
#[path = "nl80211/key_cmd.rs"]
pub mod key_cmd;
#[path = "nl80211/station_cmd.rs"]
pub mod station_cmd;
#[path = "nl80211/reg_cmd.rs"]
pub mod reg_cmd;
#[path = "nl80211/ap_cmd.rs"]
pub mod ap_cmd;
#[path = "nl80211/mgmt_cmd.rs"]
pub mod mgmt_cmd;
#[path = "nl80211/event.rs"]
pub mod event;

pub use family::{family_id, init, mcast_group};
