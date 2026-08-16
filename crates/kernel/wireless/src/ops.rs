// The operations a radio's driver provides. Everything nl80211 accepts ends
// up as one call on this trait, and a command whose operation is absent is
// `EOPNOTSUPP` — which is why the trait's default bodies return exactly that
// rather than pretending to succeed.
//
// A softmac driver does not implement this directly; the softmac layer does,
// and the driver implements the lower interface instead.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::chan::ChanDef;
use crate::ieee80211::MacAddr;
use crate::keys::KeyParams;
use crate::scan::ScanRequest;
use crate::sme::ConnectParams;
use crate::sta::{StationInfo, StationParams};
use crate::uapi::enums::IfType;
use crate::wdev::Wdev;
use crate::wiphy::Wiphy;

/// What an interface-creation request asks for.
#[derive(Clone, Debug)]
pub struct NewIfaceParams {
    pub name: String,
    pub iftype: IfType,
    /// Address the request asks for, when it named one.
    pub addr: Option<MacAddr>,
    /// Whether the interface uses four-address frames.
    pub use_4addr: Option<bool>,
    /// Monitor-mode capture flags.
    pub mntr_flags: u32,
}

/// What a `START_AP` asks for.
#[derive(Clone, Debug, Default)]
pub struct ApSettings {
    pub chandef: Option<ChanDef>,
    pub beacon_head: Vec<u8>,
    pub beacon_tail: Vec<u8>,
    pub beacon_interval: u16,
    pub dtim_period: u8,
    pub ssid: Vec<u8>,
    pub hidden_ssid: u32,
    pub privacy: bool,
    pub auth_type: u32,
    pub inactivity_timeout: u16,
    pub proberesp_ies: Vec<u8>,
    pub assocresp_ies: Vec<u8>,
}

/// What an `AUTHENTICATE` asks for.
#[derive(Clone, Debug)]
pub struct AuthRequest {
    pub bssid: MacAddr,
    pub freq: u32,
    pub ssid: Vec<u8>,
    pub auth_type: u32,
    pub ie: Vec<u8>,
    pub auth_data: Vec<u8>,
    /// Whether only the local state changes and no frame goes out.
    pub local_state_change: bool,
}

/// What an `ASSOCIATE` asks for.
#[derive(Clone, Debug)]
pub struct AssocRequest {
    pub bssid: MacAddr,
    pub freq: u32,
    pub ssid: Vec<u8>,
    pub ie: Vec<u8>,
    pub prev_bssid: Option<MacAddr>,
    pub use_mfp: u32,
    pub crypto_ciphers_pairwise: Vec<u32>,
    pub crypto_cipher_group: Option<u32>,
    pub crypto_akm_suites: Vec<u32>,
}

/// One transmitted management frame request.
#[derive(Clone, Debug)]
pub struct MgmtTxRequest {
    pub chandef: Option<ChanDef>,
    pub offchan: bool,
    pub wait_ms: u32,
    pub frame: Vec<u8>,
    pub no_cck: bool,
    pub dont_wait_for_ack: bool,
}

/// The driver-facing configuration surface.
pub trait Cfg80211Ops: Send + Sync {
    /// Create a virtual interface. # C: driver-dependent
    fn add_virtual_intf(&self, _wiphy: &Arc<Wiphy>, _params: &NewIfaceParams)
        -> Result<Arc<Wdev>, Errno> { Err(Errno::Eopnotsupp) }
    /// Destroy a virtual interface. # C: driver-dependent
    fn del_virtual_intf(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>)
        -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Change an interface's type. # C: driver-dependent
    fn change_virtual_intf(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _ty: IfType)
        -> Result<(), Errno> { Err(Errno::Eopnotsupp) }

    /// Install a key. # C: driver-dependent
    fn add_key(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _idx: u8, _pairwise: bool,
               _peer: Option<MacAddr>, _params: &KeyParams) -> Result<(), Errno> {
        Err(Errno::Eopnotsupp)
    }
    /// Remove a key. # C: driver-dependent
    fn del_key(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _idx: u8, _pairwise: bool,
               _peer: Option<MacAddr>) -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Select the default transmit key. # C: driver-dependent
    fn set_default_key(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _idx: u8, _uni: bool,
                       _multi: bool) -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Select the default management key. # C: driver-dependent
    fn set_default_mgmt_key(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _idx: u8)
        -> Result<(), Errno> { Err(Errno::Eopnotsupp) }

    /// Start a scan. Completion is reported back through `events`.
    /// # C: driver-dependent
    fn scan(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _req: &ScanRequest)
        -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Abort a scan in progress. # C: driver-dependent
    fn abort_scan(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>) -> Result<(), Errno> {
        Err(Errno::Eopnotsupp)
    }

    /// Run the whole connect sequence in the driver. A driver without this
    /// gets the software state machine instead. # C: driver-dependent
    fn connect(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _params: &ConnectParams)
        -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Tear a connection down. # C: driver-dependent
    fn disconnect(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _reason: u16)
        -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Send an authenticate. # C: driver-dependent
    fn auth(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _req: &AuthRequest)
        -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Send an associate. # C: driver-dependent
    fn assoc(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _req: &AssocRequest)
        -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Send a deauthenticate. # C: driver-dependent
    fn deauth(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _peer: MacAddr, _reason: u16,
              _local_state_change: bool) -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Send a disassociate. # C: driver-dependent
    fn disassoc(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _peer: MacAddr, _reason: u16,
                _local_state_change: bool) -> Result<(), Errno> { Err(Errno::Eopnotsupp) }

    /// Report one station. # C: driver-dependent
    fn get_station(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _peer: MacAddr)
        -> Result<StationInfo, Errno> { Err(Errno::Eopnotsupp) }
    /// Report the station at an index, for a dump. # C: driver-dependent
    fn dump_station(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _idx: usize)
        -> Result<StationInfo, Errno> { Err(Errno::Eopnotsupp) }
    /// Add a station. # C: driver-dependent
    fn add_station(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _peer: MacAddr,
                   _params: &StationParams) -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Change a station. # C: driver-dependent
    fn change_station(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _peer: MacAddr,
                      _params: &StationParams) -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Remove a station. # C: driver-dependent
    fn del_station(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _peer: Option<MacAddr>,
                   _reason: u16) -> Result<(), Errno> { Err(Errno::Eopnotsupp) }

    /// Start beaconing. # C: driver-dependent
    fn start_ap(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _settings: &ApSettings)
        -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Stop beaconing. # C: driver-dependent
    fn stop_ap(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>) -> Result<(), Errno> {
        Err(Errno::Eopnotsupp)
    }
    /// Apply the beaconed BSS parameters after they changed. # C: driver-dependent
    fn change_bss(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>,
                  _params: &crate::wdev::BssParams) -> Result<(), Errno> {
        Err(Errno::Eopnotsupp)
    }

    /// Apply device configuration that changed. # C: driver-dependent
    fn set_wiphy_params(&self, _wiphy: &Arc<Wiphy>) -> Result<(), Errno> { Ok(()) }
    /// Set the operating channel of an interface with no association.
    /// # C: driver-dependent
    fn set_monitor_channel(&self, _wiphy: &Arc<Wiphy>, _def: &ChanDef) -> Result<(), Errno> {
        Err(Errno::Eopnotsupp)
    }
    /// Turn power save on or off. # C: driver-dependent
    fn set_power_mgmt(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _enabled: bool,
                      _timeout_ms: i32) -> Result<(), Errno> { Err(Errno::Eopnotsupp) }
    /// Transmit a management frame. Returns the cookie the status event will
    /// carry. # C: driver-dependent
    fn mgmt_tx(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _req: &MgmtTxRequest)
        -> Result<u64, Errno> { Err(Errno::Eopnotsupp) }
    /// Apply a regulatory domain the core decided on. # C: driver-dependent
    fn set_regdom(&self, _wiphy: &Arc<Wiphy>) -> Result<(), Errno> { Ok(()) }
    /// Report one channel's occupancy, for a survey dump. # C: driver-dependent
    fn dump_survey(&self, _wiphy: &Arc<Wiphy>, _wdev: &Arc<Wdev>, _idx: usize)
        -> Result<SurveyInfo, Errno> { Err(Errno::Eopnotsupp) }
}

/// One channel's occupancy report.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SurveyInfo {
    /// Centre frequency in MHz.
    pub freq: u32,
    /// Noise floor in dBm.
    pub noise: Option<i8>,
    /// Whether the radio is currently on this channel.
    pub in_use: bool,
    /// Milliseconds the radio has spent on this channel.
    pub time_ms: Option<u64>,
    pub time_busy_ms: Option<u64>,
    pub time_ext_busy_ms: Option<u64>,
    pub time_rx_ms: Option<u64>,
    pub time_tx_ms: Option<u64>,
    pub time_scan_ms: Option<u64>,
}
