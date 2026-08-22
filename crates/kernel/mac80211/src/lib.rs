// mac80211 — the softmac 802.11 layer (`62`).
//
// A radio that only sends and receives frames is not a Wi-Fi station. What
// makes it one is everything here: the management exchange that joins a
// network, the ciphers that protect the link, the reorder windows that keep
// an aggregated stream in order, the conversion that lets the rest of the
// network stack see an ordinary Ethernet interface. A driver below this layer
// implements `ops::Ieee80211Ops` and nothing else.
//
// Module manifest:
// - `uapi`:     wire numbers — EtherTypes, access categories, cipher widths.
// - `flags`:    hardware, key, transmit, receive and change bit flags.
// - `limits`:   bounds, counts and durations.
// - `ops`:      the driver-facing operations trait and its parameter types.
// - `hw`:       what a driver registers, and the radio instance itself.
// - `cfg_ops`:  the bridge from the configuration layer down to here.
// - `iface`:    virtual interfaces and their configuration.
// - `netdev`:   the network device an interface is published as, and the
//               conversion between the two frame formats.
// - `sta_info`: the station table and the state ladder.
// - `key`:      installed keys and the choice of which one a frame uses.
// - `crypto`:   the link ciphers, each with its own replay rule.
// - `rx`:       the receive handler chain.
// - `tx`:       the transmit handler chain.
// - `agg`:      block-ack aggregation.
// - `mlme`:     the management exchange, both sides of it.
// - `ps`:       power save.
// - `rate`:     rate selection.
// - `scan`:     the software scan.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod agg;
pub mod cfg_ops;
pub mod crypto;
pub mod flags;
pub mod hw;
pub mod iface;
pub mod key;
pub mod limits;
pub mod mlme;
pub mod netdev;
pub mod ops;
pub mod ps;
pub mod rate;
pub mod rx;
pub mod scan;
pub mod sta_info;
pub mod tx;
pub mod uapi;

pub use hw::{alloc_hw, register_hw, unregister_hw, Ieee80211Hw, Local};
pub use iface::Sdata;
pub use key::{Key, KeySet};
pub use ops::{Errno, Ieee80211Ops, RxStatus, StaState, TxInfo, Vif};
pub use rx::rx;
pub use sta_info::{Sta, StaTable};

/// Bring the layer up. Nothing here needs doing before a driver registers, so
/// this exists to give the boot sequence one call to make rather than a
/// per-driver ordering rule. # C: O(1)
pub fn init() {}

#[cfg(test)]
#[path = "tests/fixture.rs"] mod tests_fixture;
#[cfg(test)]
#[path = "tests/agg_window.rs"] mod tests_agg_window;
#[cfg(test)]
#[path = "tests/agg_reorder.rs"] mod tests_agg_reorder;
#[cfg(test)]
#[path = "tests/replay.rs"] mod tests_replay;
#[cfg(test)]
#[path = "tests/cipher_ccmp.rs"] mod tests_cipher_ccmp;
#[cfg(test)]
#[path = "tests/cipher_gcmp.rs"] mod tests_cipher_gcmp;
#[cfg(test)]
#[path = "tests/cipher_tkip.rs"] mod tests_cipher_tkip;
#[cfg(test)]
#[path = "tests/keys.rs"] mod tests_keys;
#[cfg(test)]
#[path = "tests/port.rs"] mod tests_port;
#[cfg(test)]
#[path = "tests/mfp.rs"] mod tests_mfp;
#[cfg(test)]
#[path = "tests/mlme_state.rs"] mod tests_mlme_state;
#[cfg(test)]
#[path = "tests/convert.rs"] mod tests_convert;
#[cfg(test)]
#[path = "tests/sta_state.rs"] mod tests_sta_state;
#[cfg(test)]
#[path = "tests/defrag.rs"] mod tests_defrag;
#[cfg(test)]
#[path = "tests/frag.rs"] mod tests_frag;
#[cfg(test)]
#[path = "tests/rate.rs"] mod tests_rate;
#[cfg(test)]
#[path = "tests/agg_action.rs"] mod tests_agg_action;
#[cfg(test)]
#[path = "tests/beacon_tim.rs"] mod tests_beacon_tim;
#[cfg(test)]
#[path = "tests/rx_chain.rs"] mod tests_rx_chain;
#[cfg(test)]
#[path = "tests/cfg_bss.rs"] mod tests_cfg_bss;
