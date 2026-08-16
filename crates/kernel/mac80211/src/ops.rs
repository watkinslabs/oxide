// The driver-facing operations. A softmac driver implements this and nothing
// else: everything above it — the frame chains, the management exchange, the
// station table, the ciphers — is this layer's work, and a driver that starts
// making those decisions has become a second implementation of them.
//
// Each call names the interface it applies to by value (`Vif`) rather than by
// a handle into this layer's state, so a driver cannot reach back into the
// interface table and observe it mid-update.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

/// The error type every operation reports through, re-exported so a driver
/// crate needs no dependency of its own to name it.
pub use syscall::errno::Errno;

use wireless::chan::ChanDef;
use wireless::ieee80211::MacAddr;
use wireless::uapi::enums::IfType;

use crate::hw::Ieee80211Hw;

/// The interface one operation applies to, as the driver sees it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vif {
    /// Stable per-radio index the driver may use to key its own state.
    pub id: u32,
    pub iftype: IfType,
    pub addr: MacAddr,
    /// Whether the interface carries a beaconed network.
    pub beaconing: bool,
}

/// Device-wide configuration. Everything here applies to the radio, not to
/// one interface.
#[derive(Clone, Copy, Debug, Default)]
pub struct Conf {
    /// Channel the radio is tuned to, once something has asked for one.
    pub chandef: Option<ChanDef>,
    /// Transmit power ceiling in dBm.
    pub power_level: i32,
    /// Whether the radio may sleep between beacons.
    pub ps: bool,
    /// Beacon intervals a sleeping station skips.
    pub listen_interval: u16,
    /// Whether every interface is idle, so the radio may power down.
    pub idle: bool,
    /// Retries for a frame short enough not to need request-to-send.
    pub short_frame_max_tx_count: u8,
    pub long_frame_max_tx_count: u8,
    /// Whether a monitor interface exists, so the radio must not filter.
    pub monitor: bool,
}

/// Per-interface network configuration: what the interface has agreed with
/// the network it is part of.
#[derive(Clone, Debug, Default)]
pub struct BssConf {
    /// Whether the interface is associated.
    pub assoc: bool,
    /// Address of the network the interface serves or is joined to.
    pub bssid: Option<MacAddr>,
    /// Association identifier, for a joined station.
    pub aid: u16,
    pub beacon_int: u16,
    pub dtim_period: u8,
    /// Rates every member of the network must support, as a bit mask over
    /// the band's rate table.
    pub basic_rates: u32,
    /// Whether the network runs quality of service, so data frames carry a
    /// QoS control field.
    pub qos: bool,
    pub use_cts_prot: bool,
    pub use_short_preamble: bool,
    pub use_short_slot: bool,
    /// Whether this interface transmits beacons.
    pub enable_beacon: bool,
    /// Whether management frames on this link are protected, which decides
    /// whether an unprotected teardown may be acted on at all.
    pub protected_mgmt: bool,
    pub ssid: Vec<u8>,
    /// Whether the interface's controlled port is authorized.
    pub port_authorized: bool,
}

/// Contention parameters for one access category.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TxQueueParams {
    /// Arbitration inter-frame spacing, in slots.
    pub aifs: u8,
    /// Contention-window bounds, as the exponent minus one form the wire uses.
    pub cw_min: u16,
    pub cw_max: u16,
    /// Transmit-opportunity limit in 32-microsecond units.
    pub txop: u16,
    /// Whether admission control is mandatory for this category.
    pub acm: bool,
    /// Whether unscheduled power-save delivery is enabled for it.
    pub uapsd: bool,
}

/// The station state ladder. A station climbs it one step at a time and
/// descends it one step at a time; a driver that sees a jump has been handed
/// a state change this layer built wrong.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StaState {
    /// Not in the table at all.
    NotExist,
    /// In the table but not yet authenticated.
    None,
    /// The authentication exchange completed.
    Auth,
    /// The association exchange completed.
    Assoc,
    /// The controlled port is open and data may flow.
    Authorized,
}

/// One key as the driver receives it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyConf {
    pub cipher: u32,
    pub key: Vec<u8>,
    pub idx: u8,
    pub pairwise: bool,
    /// Peer the key belongs to; a group key has none.
    pub peer: Option<MacAddr>,
    /// Bits from `flags::key`.
    pub flags: u32,
}

/// What an aggregation request asks the driver to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmpduAction {
    /// Start receiving an aggregated stream on a traffic identifier.
    RxStart { tid: u8, ssn: u16, buf_size: u16 },
    RxStop { tid: u8 },
    /// Begin negotiating an outgoing aggregated stream.
    TxStart { tid: u8, ssn: u16 },
    /// The negotiation succeeded and the stream may carry frames.
    TxOperational { tid: u8, buf_size: u16 },
    TxStop { tid: u8 },
    /// The negotiation failed and any partial state is discarded.
    TxFlush { tid: u8 },
}

/// What accompanies one frame handed to the driver.
#[derive(Clone, Copy, Debug, Default)]
pub struct TxInfo {
    /// Bits from `flags::tx`.
    pub flags: u32,
    /// Hardware queue the frame belongs in, one per access category.
    pub queue: u8,
    /// Traffic identifier the frame carries.
    pub tid: u8,
    /// Rate index into the band's rate table, when software picked one.
    pub rate_idx: Option<u8>,
    /// Number of transmit attempts allowed.
    pub max_tries: u8,
    /// Cookie a management-frame status report must carry back.
    pub cookie: u64,
}

/// What a driver reports about a frame it received.
#[derive(Clone, Copy, Debug, Default)]
pub struct RxStatus {
    /// Centre frequency in MHz the frame was heard on.
    pub freq: u32,
    /// Signal strength in dBm.
    pub signal: i8,
    /// Rate index the frame arrived at.
    pub rate_idx: u8,
    /// Bits from `flags::rx`.
    pub flags: u32,
    /// Monotonic nanoseconds the frame arrived at.
    pub now_ns: u64,
    /// Radio timing value at reception.
    pub mactime: u64,
}

/// Statistics a driver keeps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HwStats {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_failed: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_dropped: u64,
}

/// What a driver implements. Every method has a default that reports the
/// operation is not supported rather than silently succeeding: a driver that
/// has not implemented power save must not appear to have entered it.
pub trait Ieee80211Ops: Send + Sync {
    /// Bring the radio up. Nothing else is called before this succeeds.
    /// # C: driver-dependent
    fn start(&self, _hw: &Ieee80211Hw) -> Result<(), Errno> { Ok(()) }
    /// Take the radio down. # C: driver-dependent
    fn stop(&self, _hw: &Ieee80211Hw) {}

    /// A virtual interface was created. # C: driver-dependent
    fn add_interface(&self, _hw: &Ieee80211Hw, _vif: &Vif) -> Result<(), Errno> { Ok(()) }
    /// A virtual interface changed type in place. # C: driver-dependent
    fn change_interface(&self, _hw: &Ieee80211Hw, _vif: &Vif, _new: IfType)
        -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// A virtual interface went away. # C: driver-dependent
    fn remove_interface(&self, _hw: &Ieee80211Hw, _vif: &Vif) {}

    /// Device-wide configuration changed; `changed` names which parts.
    /// # C: driver-dependent
    fn config(&self, _hw: &Ieee80211Hw, _conf: &Conf, _changed: u32) -> Result<(), Errno> {
        Ok(())
    }
    /// The receive filter changed. # C: driver-dependent
    fn configure_filter(&self, _hw: &Ieee80211Hw, _total: u32, _multicast: u64) {}
    /// One interface's network configuration changed. # C: driver-dependent
    fn bss_info_changed(&self, _hw: &Ieee80211Hw, _vif: &Vif, _conf: &BssConf,
                        _changed: u32) {}
    /// Contention parameters for one access category changed.
    /// # C: driver-dependent
    fn conf_tx(&self, _hw: &Ieee80211Hw, _vif: &Vif, _ac: u8, _params: &TxQueueParams)
        -> Result<(), Errno> { Ok(()) }

    /// Install or remove a key in the hardware cipher engine. A driver
    /// without one refuses, and the software path encrypts instead — which is
    /// why refusing is correct and pretending to accept is not.
    /// # C: driver-dependent
    fn set_key(&self, _hw: &Ieee80211Hw, _vif: &Vif, _remove: bool, _key: &KeyConf)
        -> Result<(), Errno> { Err(Errno::Eopnotsupp) }

    /// A station moved one step along the state ladder. # C: driver-dependent
    fn sta_state(&self, _hw: &Ieee80211Hw, _vif: &Vif, _sta: MacAddr, _old: StaState,
                 _new: StaState) -> Result<(), Errno> { Ok(()) }

    /// Run a scan in the hardware. A driver without this gets the software
    /// scan. # C: driver-dependent
    fn hw_scan(&self, _hw: &Ieee80211Hw, _vif: &Vif, _freqs: &[u32], _ssids: &[Vec<u8>])
        -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Abort a hardware scan. # C: driver-dependent
    fn cancel_hw_scan(&self, _hw: &Ieee80211Hw, _vif: &Vif) {}

    /// Transmit one complete 802.11 frame. This is the only path frames leave
    /// by. # C: O(len)
    fn tx(&self, _hw: &Ieee80211Hw, _vif: Option<&Vif>, _info: &TxInfo, _frame: &[u8]);

    /// Set up or tear down an aggregation session. # C: driver-dependent
    fn ampdu_action(&self, _hw: &Ieee80211Hw, _vif: &Vif, _sta: MacAddr,
                    _action: AmpduAction) -> Result<(), Errno> { Err(Errno::Eopnotsupp) }

    /// Wait for queued frames to drain. # C: driver-dependent
    fn flush(&self, _hw: &Ieee80211Hw, _drop: bool) {}
    /// Radio timing value. # C: driver-dependent
    fn get_tsf(&self, _hw: &Ieee80211Hw, _vif: &Vif) -> u64 { 0 }
    /// Set the radio timing value. # C: driver-dependent
    fn set_tsf(&self, _hw: &Ieee80211Hw, _vif: &Vif, _tsf: u64) {}
    /// Driver counters. # C: driver-dependent
    fn get_stats(&self, _hw: &Ieee80211Hw) -> HwStats { HwStats::default() }
    /// Occupancy of the channel at an index, for a survey. # C: driver-dependent
    fn get_survey(&self, _hw: &Ieee80211Hw, _idx: usize)
        -> Option<wireless::ops::SurveyInfo> { None }
}

/// A driver handle, shared by the layer and by whatever registered it.
pub type OpsRef = Arc<dyn Ieee80211Ops>;
