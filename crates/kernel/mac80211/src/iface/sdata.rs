// One virtual interface: everything that is per-interface rather than
// per-radio or per-peer.
//
// The transmit sequence counter lives here and not on the station, for
// management frames and for any interface with no peer yet: an authenticate
// goes out before a station record exists, and it still needs a sequence
// number the peer's duplicate detection will accept.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Wiphy as WiphyLock};
use wireless::chan::ChanDef;
use wireless::ieee80211::MacAddr;
use wireless::uapi::enums::IfType;
use wireless::Wdev;

use crate::hw::{Local, LocalRef};
use crate::key::KeySet;
use crate::limits;
use crate::mlme::state::MlmeState;
use crate::ops::{BssConf, Vif};
use crate::rx::defrag::DefragCache;
use crate::sta_info::StaTable;

/// Running counters one interface keeps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IfaceStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_dropped: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_dropped: u64,
    /// Frames refused because the controlled port was not yet open. Counted
    /// separately from other drops: a link that looks connected but passes no
    /// traffic is almost always this.
    pub tx_port_blocked: u64,
    /// Frames that failed decryption or their replay check.
    pub rx_crypto_failed: u64,
    /// Frames dropped as duplicates.
    pub rx_duplicate: u64,
}

/// Mutable interface state.
pub struct SdataState {
    pub iftype: IfType,
    pub name: String,
    pub up: bool,
    /// Configuration of the network this interface serves or joined.
    pub bss: BssConf,
    /// Channel the interface operates on.
    pub chandef: Option<ChanDef>,
    /// Keys installed on the interface, with their live cipher counters.
    pub keys: KeySet,
    /// The client-side management state machine.
    pub mlme: MlmeState,
    /// Sequence counter for frames that are not attributed to a station.
    pub seq: u16,
    /// Partially reassembled frames.
    pub frags: DefragCache,
    pub stats: IfaceStats,
    /// Beacon body an access-point interface transmits, elements included.
    pub beacon: Option<Vec<u8>>,
    /// Extra elements appended to a probe response.
    pub proberesp_ies: Vec<u8>,
    /// Extra elements appended to an association response.
    pub assocresp_ies: Vec<u8>,
    /// Whether four-address frames are in use.
    pub use_4addr: bool,
    /// Whether an access point may bridge frames between associated peers.
    pub ap_isolate: bool,
    /// Monitor capture flags.
    pub mntr_flags: u32,
    /// Whether power save is requested on this interface.
    pub ps: bool,
    /// Radio timing value the interface counts beacons from.
    pub tsf: u64,
}

/// One virtual interface.
pub struct Sdata {
    /// The radio the interface belongs to. Weak because the radio holds the
    /// interface: a strong reference in both directions frees neither.
    pub local: LocalRef,
    /// The configuration-layer interface this one is published as.
    pub wdev: Arc<Wdev>,
    /// Per-radio interface number, stable for the interface's life.
    pub id: u32,
    pub addr: MacAddr,
    /// Peers this interface talks to.
    pub stas: StaTable,
    /// Where converted frames go once the receive chain is done with them.
    /// Installed when the interface is published to the network stack; an
    /// interface with none — a monitor, or one not yet registered — drops
    /// them rather than queueing them for a consumer that will never come.
    pub deliver: Spinlock<Option<Arc<dyn crate::netdev::RxDeliver>>, WiphyLock>,
    state: Spinlock<SdataState, WiphyLock>,
}

impl Sdata {
    /// Build an interface. # C: O(1)
    pub fn new(local: LocalRef, wdev: Arc<Wdev>, id: u32, iftype: IfType, name: String,
               addr: MacAddr) -> Self {
        Self {
            local, wdev, id, addr,
            stas: StaTable::default(),
            deliver: Spinlock::new(None),
            state: Spinlock::new(SdataState {
                iftype, name, up: false,
                bss: BssConf { beacon_int: limits::DEFAULT_BEACON_INT_TU,
                               dtim_period: limits::DEFAULT_DTIM_PERIOD, ..Default::default() },
                chandef: None, keys: KeySet::default(), mlme: MlmeState::default(),
                seq: 0, frags: DefragCache::default(), stats: IfaceStats::default(),
                beacon: None, proberesp_ies: Vec::new(), assocresp_ies: Vec::new(),
                use_4addr: false, ap_isolate: false, mntr_flags: 0, ps: false, tsf: 0,
            }),
        }
    }

    /// Run `f` against the interface state. # C: O(f)
    pub fn with<R>(&self, f: impl FnOnce(&mut SdataState) -> R) -> R { f(&mut self.state.lock()) }

    /// The radio, if it is still there. # C: O(1)
    pub fn local(&self) -> Option<Arc<Local>> { self.local.upgrade() }

    /// Interface type. # C: O(1)
    pub fn iftype(&self) -> IfType { self.state.lock().iftype }
    /// Interface name. # C: O(len)
    pub fn name(&self) -> String { self.state.lock().name.clone() }
    /// Whether the interface is up. # C: O(1)
    pub fn is_up(&self) -> bool { self.state.lock().up }
    /// Operating channel. # C: O(1)
    pub fn chandef(&self) -> Option<ChanDef> { self.state.lock().chandef }
    /// Address of the network this interface belongs to. # C: O(1)
    pub fn bssid(&self) -> Option<MacAddr> { self.state.lock().bss.bssid }
    /// Whether the interface is associated. # C: O(1)
    pub fn is_assoc(&self) -> bool { self.state.lock().bss.assoc }
    /// Whether the controlled port is open. # C: O(1)
    pub fn port_authorized(&self) -> bool { self.state.lock().bss.port_authorized }
    /// Whether management frames on this link are protected. # C: O(1)
    pub fn mfp(&self) -> bool { self.state.lock().bss.protected_mgmt }

    /// The interface as a driver sees it. # C: O(1)
    pub fn vif(&self) -> Vif {
        let g = self.state.lock();
        Vif { id: self.id, iftype: g.iftype, addr: self.addr, beaconing: g.bss.enable_beacon }
    }

    /// Take the next sequence number for a frame not attributed to a peer.
    /// # C: O(1)
    pub fn next_seq(&self) -> u16 {
        let mut g = self.state.lock();
        let s = g.seq;
        g.seq = crate::agg::window::sn_inc(s);
        s
    }

    /// Snapshot the network configuration. # C: O(len)
    pub fn bss_conf(&self) -> BssConf { self.state.lock().bss.clone() }

    /// Snapshot the counters. # C: O(1)
    pub fn stats(&self) -> IfaceStats { self.state.lock().stats }
}
