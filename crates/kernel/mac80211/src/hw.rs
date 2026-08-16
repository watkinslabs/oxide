// What a driver registers, and the device instance the whole layer hangs off.
//
// Registration is where a driver's radio becomes a radio userspace can see:
// `register_hw` builds the cfg80211 device from what the driver advertised,
// installs the bridge that turns configuration requests into driver calls,
// and publishes it. Until then the driver's radio exists only to the driver.

extern crate alloc;

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Spinlock, Wiphy as WiphyLock};
use syscall::errno::Errno;
use wireless::ieee80211::MacAddr;
use wireless::uapi::enums::IfType;
use wireless::wiphy::{WiphyBand, WiphyCaps};
use wireless::Wiphy;

use crate::iface::Sdata;
use crate::ops::{Conf, OpsRef, TxQueueParams};
use crate::{flags, limits, uapi};

/// What a driver advertises about its radio. Immutable once registered: a
/// capability that could change after userspace read it would let a
/// supplicant plan a connection the radio can no longer make.
#[derive(Clone, Debug)]
pub struct Ieee80211Hw {
    /// Permanent address; interface addresses are derived from it.
    pub addr: MacAddr,
    /// Bits of the address a driver may vary between interfaces.
    pub addr_mask: MacAddr,
    /// Bands, channels and rates.
    pub bands: Vec<WiphyBand>,
    /// Cipher suites the radio's own engines implement. Software ciphers are
    /// added on top of these at registration.
    pub hw_ciphers: Vec<u32>,
    /// Bits from `flags::hw`.
    pub flags: u32,
    /// Interface types the radio supports, as a mask over `IfType`.
    pub iftypes: u32,
    /// Hardware transmit queues, one per access category at minimum.
    pub queues: u8,
    /// Extra head and tail room the driver needs on every frame.
    pub extra_tx_headroom: usize,
    pub extra_tx_tailroom: usize,
    /// Stations the radio can hold state for.
    pub max_stations: u16,
    /// Largest reorder buffer the radio will agree to.
    pub max_rx_aggregation_subframes: u16,
    pub max_tx_aggregation_subframes: u16,
    /// Radio's name for itself, used only in diagnostics.
    pub driver_name: String,
}

impl Default for Ieee80211Hw {
    fn default() -> Self {
        Self {
            addr: MacAddr::ZERO, addr_mask: MacAddr::ZERO, bands: Vec::new(),
            hw_ciphers: Vec::new(), flags: 0, iftypes: 0,
            queues: uapi::ac::COUNT as u8,
            extra_tx_headroom: 0, extra_tx_tailroom: 0,
            max_stations: limits::MAX_STATIONS as u16,
            max_rx_aggregation_subframes: limits::MAX_AGG_BUF_SIZE_HT,
            max_tx_aggregation_subframes: limits::MAX_AGG_BUF_SIZE_HT,
            driver_name: String::new(),
        }
    }
}

impl Ieee80211Hw {
    /// Whether a hardware flag is set. # C: O(1)
    pub fn has(&self, flag: u32) -> bool { self.flags & flag != 0 }
    /// Total headroom every transmit path reserves. # C: O(1)
    pub fn tx_headroom(&self) -> usize { limits::TX_HEADROOM + self.extra_tx_headroom }
    /// Total tailroom every transmit path reserves. # C: O(1)
    pub fn tx_tailroom(&self) -> usize { limits::TX_TAILROOM + self.extra_tx_tailroom }
}

/// Cipher suites this layer implements in software, offered by every radio
/// whatever its own engines do. A radio with no cipher engine still runs a
/// protected link; it just does the arithmetic here.
pub const SOFTWARE_CIPHERS: [u32; 6] = [
    wireless::uapi::ciphers::cipher::CCMP,
    wireless::uapi::ciphers::cipher::CCMP_256,
    wireless::uapi::ciphers::cipher::GCMP,
    wireless::uapi::ciphers::cipher::GCMP_256,
    wireless::uapi::ciphers::cipher::TKIP,
    wireless::uapi::ciphers::cipher::AES_CMAC,
];

/// Runtime state of one radio.
pub struct LocalState {
    /// Whether the driver's radio is running.
    pub started: bool,
    /// Interfaces on this radio.
    pub ifaces: Vec<Arc<Sdata>>,
    /// Device-wide configuration as last applied to the driver.
    pub conf: Conf,
    /// Contention parameters per access category.
    pub tx_params: [TxQueueParams; uapi::ac::COUNT],
    /// Receive filter last applied.
    pub filter: u32,
    /// Interfaces created so far, for the per-interface identifier.
    pub next_iface_id: u32,
    /// Software scan in progress.
    pub scan: Option<crate::scan::SwScan>,
    /// Fragmentation threshold; above it nothing is fragmented.
    pub frag_threshold: u32,
    /// Request-to-send threshold.
    pub rts_threshold: u32,
    /// Monotonic time the layer last saw, so a hosted test can drive it.
    pub now_ns: u64,
}

/// One radio, as this layer runs it.
pub struct Local {
    pub hw: Ieee80211Hw,
    pub ops: OpsRef,
    /// The cfg80211 device, once registered.
    pub wiphy: Spinlock<Option<Arc<Wiphy>>, WiphyLock>,
    state: Spinlock<LocalState, WiphyLock>,
}

impl Local {
    /// Run `f` against the runtime state under the device lock. # C: O(f)
    pub fn with<R>(&self, f: impl FnOnce(&mut LocalState) -> R) -> R { f(&mut self.state.lock()) }

    /// The registered cfg80211 device. # C: O(1)
    pub fn wiphy(&self) -> Option<Arc<Wiphy>> { self.wiphy.lock().clone() }

    /// Interfaces on this radio. # C: O(N interfaces)
    pub fn ifaces(&self) -> Vec<Arc<Sdata>> { self.state.lock().ifaces.clone() }

    /// The interface with this address, if there is one. # C: O(N interfaces)
    pub fn iface_by_addr(&self, addr: MacAddr) -> Option<Arc<Sdata>> {
        self.state.lock().ifaces.iter().find(|s| s.addr == addr).cloned()
    }

    /// The interface with this identifier. # C: O(N interfaces)
    pub fn iface_by_id(&self, id: u32) -> Option<Arc<Sdata>> {
        self.state.lock().ifaces.iter().find(|s| s.id == id).cloned()
    }

    /// The interface with this cfg80211 identifier. # C: O(N interfaces)
    pub fn iface_by_wdev(&self, identifier: u64) -> Option<Arc<Sdata>> {
        self.state.lock().ifaces.iter().find(|s| s.wdev.identifier == identifier).cloned()
    }

    /// Current monotonic time as this layer knows it. # C: O(1)
    pub fn now_ns(&self) -> u64 { self.state.lock().now_ns }
    /// Advance the layer's notion of time. A hosted test drives this; on a
    /// running kernel the tick does. # C: O(1)
    pub fn set_now_ns(&self, ns: u64) { self.state.lock().now_ns = ns; }
}

/// Build an unregistered radio from what a driver advertised. # C: O(bands)
pub fn alloc_hw(hw: Ieee80211Hw, ops: OpsRef) -> Arc<Local> {
    Arc::new(Local {
        hw, ops,
        wiphy: Spinlock::new(None),
        state: Spinlock::new(LocalState {
            started: false, ifaces: Vec::new(), conf: Conf::default(),
            tx_params: [TxQueueParams::default(); uapi::ac::COUNT],
            filter: 0, next_iface_id: 0, scan: None,
            frag_threshold: limits::FRAG_THRESHOLD_OFF,
            rts_threshold: limits::RTS_THRESHOLD_OFF,
            now_ns: 0,
        }),
    })
}

/// Advertise the radio to cfg80211 and publish it. Nothing above this layer
/// can see the radio before this returns, and everything can after — which is
/// why the capability set is complete before the device is registered rather
/// than filled in afterwards. # C: O(bands + channels)
pub fn register_hw(local: &Arc<Local>) -> Result<Arc<Wiphy>, Errno> {
    if local.wiphy().is_some() { return Err(Errno::Eexist); }
    let caps = build_caps(&local.hw);
    let bridge: Arc<dyn wireless::ops::Cfg80211Ops> =
        Arc::new(crate::cfg_ops::Bridge::new(Arc::downgrade(local)));
    let mut wiphy = Wiphy::new(local.hw.addr, caps, bridge);
    wiphy.addr_mask = local.hw.addr_mask;
    let wiphy = wireless::wiphy::register(wiphy)?;
    *local.wiphy.lock() = Some(wiphy.clone());
    Ok(wiphy)
}

/// Take the radio away again: every interface goes first, then the device.
/// # C: O(N interfaces)
pub fn unregister_hw(local: &Arc<Local>) {
    for sdata in local.ifaces() { crate::iface::remove(local, &sdata); }
    let Some(wiphy) = local.wiphy.lock().take() else { return; };
    if local.with(|s| core::mem::replace(&mut s.started, false)) {
        local.ops.stop(&local.hw);
    }
    let _ = wireless::wiphy::unregister(wiphy.index);
}

/// Translate what a driver advertised into what userspace is told. The cipher
/// list is the union of the radio's engines and this layer's software
/// ciphers, in that order, because a radio that can do a suite in hardware
/// should be offered it first. # C: O(bands + ciphers)
pub fn build_caps(hw: &Ieee80211Hw) -> WiphyCaps {
    let mut caps = WiphyCaps { bands: hw.bands.clone(), ..Default::default() };
    caps.interface_modes = hw.iftypes;
    // Every mode this layer runs is run in software; the radio only moves
    // frames.
    caps.software_iftypes = hw.iftypes;
    caps.cipher_suites = hw.hw_ciphers.clone();
    for suite in SOFTWARE_CIPHERS {
        if !caps.cipher_suites.contains(&suite) { caps.cipher_suites.push(suite); }
    }
    caps.signal_dbm = hw.has(flags::hw::SIGNAL_DBM);
    caps.ap_sme = hw.has(flags::hw::AP_SME);
    caps.max_ap_assoc_sta = hw.max_stations;
    caps.max_scan_ssids = wireless::scan::MAX_SCAN_SSIDS as u8;
    caps.mgmt_stypes = mgmt_stypes(hw.iftypes);
    caps
}

/// Which management subtypes each supported interface type may transmit and
/// register for. A station sends the four exchange frames and action frames;
/// an access point additionally answers probes and sends the response halves.
/// # C: O(N types)
fn mgmt_stypes(iftypes: u32) -> Vec<wireless::wiphy::caps::MgmtStypes> {
    use wireless::ieee80211::fctl::mgmt_stype as st;
    const fn bit(subtype: u16) -> u16 { 1 << (subtype >> 4) }
    let station_tx = bit(st::AUTH) | bit(st::DEAUTH) | bit(st::DISASSOC)
        | bit(st::ASSOC_REQ) | bit(st::REASSOC_REQ) | bit(st::PROBE_REQ) | bit(st::ACTION);
    let station_rx = bit(st::AUTH) | bit(st::DEAUTH) | bit(st::DISASSOC)
        | bit(st::ASSOC_RESP) | bit(st::REASSOC_RESP) | bit(st::PROBE_RESP)
        | bit(st::BEACON) | bit(st::ACTION);
    let ap_tx = station_tx | bit(st::ASSOC_RESP) | bit(st::REASSOC_RESP)
        | bit(st::PROBE_RESP) | bit(st::BEACON);
    let ap_rx = station_rx | bit(st::ASSOC_REQ) | bit(st::REASSOC_REQ) | bit(st::PROBE_REQ);
    let mut out = Vec::new();
    for ty in [IfType::Station, IfType::Ap, IfType::Adhoc, IfType::Monitor] {
        if iftypes & (1u32 << ty.as_u32()) == 0 { continue; }
        let (tx, rx) = match ty {
            IfType::Ap => (ap_tx, ap_rx),
            IfType::Monitor => (0, station_rx | ap_rx),
            _ => (station_tx, station_rx),
        };
        out.push(wireless::wiphy::caps::MgmtStypes { iftype: ty.as_u32(), tx, rx });
    }
    out
}

/// Bring the driver's radio up if it is not already. Called on the first
/// interface that comes up, and never twice. # C: driver-dependent
pub fn start_hw(local: &Arc<Local>) -> Result<(), Errno> {
    if local.with(|s| s.started) { return Ok(()); }
    local.ops.start(&local.hw)?;
    local.with(|s| s.started = true);
    Ok(())
}

/// Take the driver's radio down once the last interface went down.
/// # C: driver-dependent
pub fn stop_hw(local: &Arc<Local>) {
    let any_up = local.ifaces().iter().any(|s| s.is_up());
    if any_up { return; }
    if local.with(|s| core::mem::replace(&mut s.started, false)) { local.ops.stop(&local.hw); }
}

/// A weak handle to a radio, held by anything the radio also holds.
pub type LocalRef = Weak<Local>;
