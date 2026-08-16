// The wiphy: one physical radio, everything it can do, and everything the
// stack has configured on it.
//
// Module manifest:
// - `caps`:     the capability advertisement — bands, channels, rates, ciphers.
// - `config`:   the writable device configuration and its validation.
// - `registry`: the global radio list, registration and lookup.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use sync::{Spinlock, Wiphy as WiphyLockClass};

use crate::ieee80211::MacAddr;
use crate::ops::Cfg80211Ops;
use crate::reg::RegDomain;
use crate::scan::{BssCache, ScanState};
use crate::wdev::Wdev;

#[path = "wiphy/caps.rs"]
pub mod caps;
#[path = "wiphy/config.rs"]
pub mod config;
#[path = "wiphy/registry.rs"]
pub mod registry;

pub use caps::{Bitrate, WiphyBand, WiphyCaps};
pub use config::WiphyConfig;
pub use registry::{
    for_each, lookup, lookup_by_name, next_index, register, snapshot, unregister,
};

/// State a wiphy owns that changes after registration. Capabilities do not
/// live here: a radio's channel list and cipher set are decided once, at
/// registration, and a caller that could rewrite them could make the
/// advertisement disagree with what the driver will accept.
pub struct WiphyState {
    /// `phy<n>` at registration, and whatever a rename made it since. The
    /// registry allocates the first one; userspace owns it afterwards.
    pub name: String,
    pub config: WiphyConfig,
    /// Interfaces created on this radio, in creation order.
    pub wdevs: Vec<alloc::sync::Arc<Wdev>>,
    /// Regulatory domain in force on this radio.
    pub regdom: RegDomain,
    /// Networks this radio has heard.
    pub bss: BssCache,
    /// Scan in progress, if any. One radio runs at most one scan: a second
    /// request while one is live is `EBUSY`, not a queue.
    pub scan: Option<ScanState>,
    /// Counter the next interface identifier is built from.
    pub next_wdev_seq: u32,
    /// Bumped on every change userspace can observe through a dump, so a
    /// reader can tell a stale dump from a current one.
    pub generation: u32,
}

/// One registered radio.
pub struct Wiphy {
    /// Index userspace addresses the radio by, and the number in its name.
    pub index: u32,
    /// Permanent hardware address; every interface address is derived from it.
    pub perm_addr: MacAddr,
    /// Mask of the address bits a driver may vary per interface.
    pub addr_mask: MacAddr,
    /// What the radio can do. Immutable after registration.
    pub caps: WiphyCaps,
    /// The driver behind the radio.
    pub ops: alloc::sync::Arc<dyn Cfg80211Ops>,
    /// Network namespace the radio and all its interfaces live in.
    pub net_ns: core::sync::atomic::AtomicU64,
    state: Spinlock<WiphyState, WiphyLockClass>,
}

impl Wiphy {
    /// Build an unregistered radio. `register` gives it its index and name.
    /// # C: O(1)
    pub fn new(perm_addr: MacAddr, caps: WiphyCaps,
               ops: alloc::sync::Arc<dyn Cfg80211Ops>) -> Self {
        Self {
            index: 0, perm_addr, addr_mask: MacAddr::ZERO,
            caps, ops,
            net_ns: core::sync::atomic::AtomicU64::new(0),
            state: Spinlock::new(WiphyState {
                name: String::new(),
                config: WiphyConfig::default(),
                wdevs: Vec::new(),
                regdom: RegDomain::world(),
                bss: BssCache::default(),
                scan: None,
                next_wdev_seq: 0,
                generation: 0,
            }),
        }
    }

    /// Run `f` against the mutable state under the device lock. # C: O(f)
    pub fn with_state<R>(&self, f: impl FnOnce(&mut WiphyState) -> R) -> R {
        f(&mut self.state.lock())
    }

    /// Name under `/sys/class/ieee80211`. # C: O(len)
    pub fn name(&self) -> String { self.state.lock().name.clone() }

    /// Whether the radio is called this. Answered without allocating, so a
    /// registry scan over every radio does not allocate once per radio.
    /// # C: O(len)
    pub fn is_named(&self, name: &str) -> bool { self.state.lock().name == name }

    /// Rename the radio. # C: O(len)
    pub fn set_name(&self, name: &str) {
        let mut g = self.state.lock();
        g.name.clear();
        g.name.push_str(name);
        g.generation = g.generation.wrapping_add(1);
    }

    /// Snapshot the configuration. # C: O(1)
    pub fn config(&self) -> WiphyConfig { self.state.lock().config }

    /// Snapshot the regulatory domain in force. # C: O(rules)
    pub fn regdom(&self) -> RegDomain { self.state.lock().regdom.clone() }

    /// Current generation counter. # C: O(1)
    pub fn generation(&self) -> u32 { self.state.lock().generation }

    /// Mark the radio changed. # C: O(1)
    pub fn bump_generation(&self) {
        let mut g = self.state.lock();
        g.generation = g.generation.wrapping_add(1);
    }

    /// Interfaces on this radio. # C: O(N interfaces)
    pub fn wdevs(&self) -> Vec<alloc::sync::Arc<Wdev>> { self.state.lock().wdevs.clone() }

    /// Interface with this identifier, if it is on this radio. # C: O(N interfaces)
    pub fn wdev(&self, id: u64) -> Option<alloc::sync::Arc<Wdev>> {
        self.state.lock().wdevs.iter().find(|w| w.identifier == id).cloned()
    }

    /// Channel at this centre frequency in MHz, in whichever band holds it.
    /// # C: O(N channels)
    pub fn channel(&self, freq_mhz: u32) -> Option<crate::chan::Channel> {
        self.caps.bands.iter().flat_map(|b| b.channels.iter())
            .find(|c| c.center_freq == freq_mhz).copied()
    }

    /// Whether the radio advertises a cipher suite. A key request naming a
    /// suite the radio never advertised is refused, because a driver that
    /// silently installs a cipher it does not implement leaves traffic in the
    /// clear while userspace believes it is protected. # C: O(N suites)
    pub fn has_cipher(&self, suite: u32) -> bool { self.caps.cipher_suites.contains(&suite) }

    /// Take the next interface identifier for this radio. # C: O(1)
    pub fn next_wdev_identifier(&self) -> u64 {
        let mut g = self.state.lock();
        g.next_wdev_seq = g.next_wdev_seq.wrapping_add(1);
        crate::wdev::make_identifier(self.index, g.next_wdev_seq)
    }

    /// Attach an interface to the radio. # C: O(1)
    pub fn add_wdev(&self, wdev: alloc::sync::Arc<Wdev>) {
        let mut g = self.state.lock();
        g.wdevs.push(wdev);
        g.generation = g.generation.wrapping_add(1);
    }

    /// Detach an interface. Reports whether it was there. # C: O(N interfaces)
    pub fn remove_wdev(&self, identifier: u64) -> bool {
        let mut g = self.state.lock();
        let before = g.wdevs.len();
        g.wdevs.retain(|w| w.identifier != identifier);
        let removed = g.wdevs.len() != before;
        if removed { g.generation = g.generation.wrapping_add(1); }
        removed
    }

    /// Whether the radio supports an interface type. # C: O(1)
    pub fn supports_iftype(&self, ty: crate::uapi::enums::IfType) -> bool {
        self.caps.interface_modes & (1u32 << ty.as_u32()) != 0
    }
}
