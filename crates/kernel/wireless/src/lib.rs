// cfg80211 — the wireless configuration layer (`62`).
//
// Everything userspace knows about wireless comes through here: `iw`,
// `wpa_supplicant` and NetworkManager speak nl80211 and nothing else, and a
// radio that is not registered here does not exist to them however well its
// driver works.
//
// Module manifest:
// - `uapi`:       the nl80211 wire numbers, in one place, decided by nobody.
// - `ieee80211`:  802.11 frame formats, elements, and frame construction.
// - `chan`:       channel numbering, channel state, channel definitions.
// - `reg`:        regulatory rules, domains, hint arbitration, country elements.
// - `scan`:       scan requests and the BSS cache with its expiry.
// - `sme`:        the station management entity's connect state machine.
// - `keys`:       key installation rules and the per-interface key ring.
// - `sta`:        per-station reporting.
// - `wiphy`:      one radio: capabilities, configuration, the radio registry.
// - `wdev`:       one virtual interface on a radio.
// - `ops`:        the operations a radio's driver provides.
// - `events`:     what a driver reports upward, and where it goes.
// - `nl80211`:    the generic-netlink family, its commands and its events.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod chan;
pub mod events;
pub mod ieee80211;
pub mod keys;
pub mod nl80211;
pub mod ops;
pub mod reg;
pub mod scan;
pub mod sme;
pub mod sta;
pub mod uapi;
pub mod wdev;
pub mod wiphy;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub use chan::{ChanDef, Channel};
pub use ieee80211::MacAddr;
pub use ops::Cfg80211Ops;
pub use reg::RegDomain;
pub use uapi::enums::{Band, ChanWidth, IfType};
pub use wdev::Wdev;
pub use wiphy::{Wiphy, WiphyBand, WiphyCaps};

/// Bring cfg80211 up: register the nl80211 family so userspace can find it,
/// before any radio registers and tries to announce itself. # C: O(1)
pub fn init() { nl80211::init(); }
