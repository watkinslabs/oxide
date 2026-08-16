// IEEE 802.11 frame formats, shared by cfg80211 and mac80211 so there is one
// parser for the air format and not one per layer.
//
// Module manifest:
// - `fctl`:   frame-control, sequence-control and QoS-control bit layout.
// - `hdr`:    the MAC header — addressing, length, and the DS-bit address map.
// - `mgmt`:   management frame bodies (beacon, auth, assoc, deauth, action).
// - `elem`:   information-element walking and the elements the stack reads.
// - `status`: status and reason codes.
// - `build`:  frame construction for the frames this stack transmits.

#[path = "ieee80211/fctl.rs"]
pub mod fctl;
#[path = "ieee80211/hdr.rs"]
pub mod hdr;
#[path = "ieee80211/mgmt.rs"]
pub mod mgmt;
#[path = "ieee80211/elem.rs"]
pub mod elem;
#[path = "ieee80211/status.rs"]
pub mod status;
#[path = "ieee80211/build.rs"]
pub mod build;

pub use elem::{Element, ElementIter, Elements};
pub use hdr::{MacAddr, MacHeader, ADDR_LEN, MAX_MAC_HDR_LEN, MIN_MAC_HDR_LEN};
pub use status::{ReasonCode, StatusCode};

/// Longest SSID the standard allows.
pub const MAX_SSID_LEN: usize = 32;
/// Longest MSDU a station may send before fragmentation.
pub const MAX_DATA_LEN: usize = 2304;
/// Largest management frame body this stack accepts.
pub const MAX_MGMT_LEN: usize = 2352;
