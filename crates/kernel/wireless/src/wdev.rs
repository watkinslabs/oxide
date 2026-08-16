// The wireless device: one virtual interface on a radio. A wdev exists for
// every interface type, including the two that carry no netdev at all, which
// is why userspace addresses it by a wireless identifier and only sometimes
// by a network-interface index.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use sync::{Spinlock, Wiphy as WiphyLockClass};

use crate::chan::ChanDef;
use crate::ieee80211::MacAddr;
use crate::keys::KeyRing;
use crate::sme::ConnState;
use crate::uapi::enums::IfType;

/// Registration of interest in a management frame subtype, so a received
/// frame that matches goes to the socket that asked for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MgmtRegistration {
    /// Netlink port that asked, and that the frame is delivered to.
    pub portid: u32,
    /// Frame-control type and subtype the registration matches.
    pub frame_type: u16,
    /// Prefix the frame body must start with; an empty prefix matches all.
    pub match_prefix: Vec<u8>,
    /// Whether the socket also wants frames from unassociated stations.
    pub multicast_rx: bool,
}

impl MgmtRegistration {
    /// Whether a received management frame matches this registration.
    /// # C: O(prefix)
    pub fn matches(&self, frame_type: u16, body: &[u8]) -> bool {
        self.frame_type == frame_type && body.starts_with(&self.match_prefix)
    }
}

/// The beaconed BSS parameters an access-point interface advertises. Every
/// field is a tri-state on the wire — absent, off, on — so a request that
/// omits one must leave it alone rather than clear it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BssParams {
    /// Protect high-rate frames with a request-to-send exchange.
    pub cts_protection: bool,
    pub short_preamble: bool,
    pub short_slot_time: bool,
    /// Rates a station must support to associate, in the on-air encoding.
    pub basic_rates: Vec<u8>,
    /// Refuse to bridge frames between two associated stations.
    pub ap_isolate: bool,
    /// High-throughput operation mode advertised in the beacon.
    pub ht_opmode: Option<u16>,
    /// Peer-to-peer client traffic window and opportunistic power save.
    pub p2p_ctwindow: Option<u8>,
    pub p2p_opp_ps: Option<bool>,
}

/// One field of a `SET_BSS`. Absent means "leave alone"; the wire spells that
/// as a negative byte, which is why a parsed request carries `Option` and not
/// a value with a sentinel. # C: O(1)
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BssParamsRequest {
    pub cts_protection: Option<bool>,
    pub short_preamble: Option<bool>,
    pub short_slot_time: Option<bool>,
    pub basic_rates: Option<Vec<u8>>,
    pub ap_isolate: Option<bool>,
    pub ht_opmode: Option<u16>,
    pub p2p_ctwindow: Option<u8>,
    pub p2p_opp_ps: Option<bool>,
}

impl BssParamsRequest {
    /// Whether the request asks for nothing. # C: O(1)
    pub fn is_empty(&self) -> bool {
        self.cts_protection.is_none() && self.short_preamble.is_none()
            && self.short_slot_time.is_none() && self.basic_rates.is_none()
            && self.ap_isolate.is_none() && self.ht_opmode.is_none()
            && self.p2p_ctwindow.is_none() && self.p2p_opp_ps.is_none()
    }
    /// Apply the fields the request named, leaving the rest. # C: O(rates)
    pub fn apply(&self, params: &mut BssParams) {
        if let Some(v) = self.cts_protection { params.cts_protection = v; }
        if let Some(v) = self.short_preamble { params.short_preamble = v; }
        if let Some(v) = self.short_slot_time { params.short_slot_time = v; }
        if let Some(v) = &self.basic_rates { params.basic_rates = v.clone(); }
        if let Some(v) = self.ap_isolate { params.ap_isolate = v; }
        if self.ht_opmode.is_some() { params.ht_opmode = self.ht_opmode; }
        if self.p2p_ctwindow.is_some() { params.p2p_ctwindow = self.p2p_ctwindow; }
        if self.p2p_opp_ps.is_some() { params.p2p_opp_ps = self.p2p_opp_ps; }
    }
}

/// Connection-quality monitoring configuration for one interface.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CqmConfig {
    /// Signal threshold in dBm; zero means the RSSI trigger is off.
    pub rssi_thold: i32,
    /// Hysteresis in dB the signal must cross back through before the
    /// opposite event fires.
    pub rssi_hyst: u32,
    /// Consecutive beacon misses before a beacon-loss event.
    pub beacon_loss_count: u32,
    /// Last event reported, so the same edge is not reported twice.
    pub last_rssi_event: Option<u32>,
}

/// Mutable interface state.
pub struct WdevInner {
    pub iftype: IfType,
    /// Network-interface name, empty for an interface with no netdev.
    pub name: String,
    /// Network-interface index, absent for an interface with no netdev.
    pub ifindex: Option<u32>,
    pub addr: MacAddr,
    /// Whether the interface is administratively up.
    pub up: bool,
    /// Whether four-address frames are used, for a bridged client.
    pub use_4addr: bool,
    /// Power save requested for this interface.
    pub ps: bool,
    /// Idle time before entering power save, in milliseconds; negative means
    /// the driver chooses.
    pub ps_timeout_ms: i32,
    /// Channel the interface is operating on, once it has one.
    pub chandef: Option<ChanDef>,
    /// SSID of the network this interface serves or is joined to.
    pub ssid: Vec<u8>,
    /// Beacon interval for a beaconing interface, in time units.
    pub beacon_interval: u16,
    /// Delivery-traffic-indication period for a beaconing interface.
    pub dtim_period: u8,
    /// The station-side connection state machine.
    pub conn: ConnState,
    /// Keys installed on this interface.
    pub keys: KeyRing,
    pub mgmt_regs: Vec<MgmtRegistration>,
    pub cqm: CqmConfig,
    /// Netlink port that owns the interface, when it was created with the
    /// socket-owner flag: the interface is destroyed when that socket closes.
    pub owner_portid: Option<u32>,
    /// Monitor-mode capture flags.
    pub mntr_flags: u32,
    /// Whether the interface is currently beaconing.
    pub beaconing: bool,
    /// The beaconed parameters an access-point interface advertises.
    pub bss: BssParams,
}

/// One virtual interface.
pub struct Wdev {
    /// Identifier userspace addresses the interface by. The radio index is in
    /// the top half so an identifier names its radio without a lookup, which
    /// is what makes a dump able to group interfaces by radio in one pass.
    pub identifier: u64,
    pub wiphy_index: u32,
    inner: Spinlock<WdevInner, WiphyLockClass>,
}

/// Build an interface identifier from a radio index and a per-radio counter.
/// # C: O(1)
pub const fn make_identifier(wiphy_index: u32, seq: u32) -> u64 {
    ((wiphy_index as u64) << 32) | seq as u64
}

/// Radio index an interface identifier names. # C: O(1)
pub const fn identifier_wiphy(identifier: u64) -> u32 { (identifier >> 32) as u32 }

impl Wdev {
    /// Build an interface. # C: O(1)
    pub fn new(identifier: u64, wiphy_index: u32, iftype: IfType, name: String,
               addr: MacAddr) -> Self {
        Self {
            identifier, wiphy_index,
            inner: Spinlock::new(WdevInner {
                iftype, name, ifindex: None, addr, up: false, use_4addr: false,
                ps: false, ps_timeout_ms: -1, chandef: None, ssid: Vec::new(),
                beacon_interval: 0, dtim_period: 0,
                conn: ConnState::default(), keys: KeyRing::default(),
                mgmt_regs: Vec::new(), cqm: CqmConfig::default(),
                owner_portid: None, mntr_flags: 0, beaconing: false,
                bss: BssParams::default(),
            }),
        }
    }

    /// Run `f` against the interface state under its lock. # C: O(f)
    pub fn with<R>(&self, f: impl FnOnce(&mut WdevInner) -> R) -> R { f(&mut self.inner.lock()) }

    /// Interface type. # C: O(1)
    pub fn iftype(&self) -> IfType { self.inner.lock().iftype }
    /// Interface name. # C: O(len)
    pub fn name(&self) -> String { self.inner.lock().name.clone() }
    /// Network-interface index, if the type carries one. # C: O(1)
    pub fn ifindex(&self) -> Option<u32> { self.inner.lock().ifindex }
    /// Interface address. # C: O(1)
    pub fn addr(&self) -> MacAddr { self.inner.lock().addr }
    /// Whether the interface is up. # C: O(1)
    pub fn is_up(&self) -> bool { self.inner.lock().up }
    /// Operating channel, if it has one. # C: O(1)
    pub fn chandef(&self) -> Option<ChanDef> { self.inner.lock().chandef }
    /// SSID currently in use. # C: O(len)
    pub fn ssid(&self) -> Vec<u8> { self.inner.lock().ssid.clone() }
    /// Beaconed parameter snapshot. # C: O(rates)
    pub fn bss(&self) -> BssParams { self.inner.lock().bss.clone() }

    /// Connection state snapshot. # C: O(1)
    pub fn conn(&self) -> ConnState { self.inner.lock().conn.clone() }

    /// Register interest in a management frame subtype. A second registration
    /// from the same port for the same subtype replaces the first rather than
    /// stacking, so a socket cannot be delivered one frame twice. # C: O(N regs)
    pub fn register_mgmt(&self, reg: MgmtRegistration) {
        let mut g = self.inner.lock();
        if let Some(existing) = g.mgmt_regs.iter_mut()
            .find(|r| r.portid == reg.portid && r.frame_type == reg.frame_type
                   && r.match_prefix == reg.match_prefix)
        { *existing = reg; return; }
        g.mgmt_regs.push(reg);
    }

    /// Drop every registration a netlink port made. # C: O(N regs)
    pub fn release_mgmt_port(&self, portid: u32) {
        self.inner.lock().mgmt_regs.retain(|r| r.portid != portid);
    }

    /// Ports that asked for a management frame of this type and body. A frame
    /// matching several registrations goes to each port once. # C: O(N regs)
    pub fn mgmt_targets(&self, frame_type: u16, body: &[u8]) -> Vec<u32> {
        let g = self.inner.lock();
        let mut out: Vec<u32> = Vec::new();
        for reg in g.mgmt_regs.iter() {
            if reg.matches(frame_type, body) && !out.contains(&reg.portid) {
                out.push(reg.portid);
            }
        }
        out
    }
}
