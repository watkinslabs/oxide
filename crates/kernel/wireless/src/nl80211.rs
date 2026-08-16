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
// - `chandef`:     the channel definition three command groups share.

#[path = "nl80211/msg.rs"]
pub mod msg;
#[path = "nl80211/policy.rs"]
pub mod policy;
#[path = "nl80211/family.rs"]
pub mod family;
#[path = "nl80211/resolve.rs"]
pub mod resolve;
#[path = "nl80211/chandef.rs"]
pub mod chandef;
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

// Hosted tests for the command handlers. Each child is declared with its own
// explicit path: a bare declaration would bind the name to the implementation
// file of the same name in this directory instead of to the test.
#[cfg(test)]
#[path = "nl80211/tests/support.rs"] mod tests_support;
#[cfg(test)]
#[path = "nl80211/tests/wiphy.rs"] mod tests_wiphy;
#[cfg(test)]
#[path = "nl80211/tests/iface.rs"] mod tests_iface;
#[cfg(test)]
#[path = "nl80211/tests/scan.rs"] mod tests_scan;
#[cfg(test)]
#[path = "nl80211/tests/key.rs"] mod tests_key;
#[cfg(test)]
#[path = "nl80211/tests/connect.rs"] mod tests_connect;
#[cfg(test)]
#[path = "nl80211/tests/station.rs"] mod tests_station;
#[cfg(test)]
#[path = "nl80211/tests/reg.rs"] mod tests_reg;
#[cfg(test)]
#[path = "nl80211/tests/ap.rs"] mod tests_ap;
#[cfg(test)]
#[path = "nl80211/tests/mgmt.rs"] mod tests_mgmt;
