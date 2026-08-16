// The operations the softmac layer calls on a virtual radio.
//
// There is no hardware to program, so most of these only record what was
// asked for — but recording it is not nothing: the channel is what decides
// which other radios hear a frame, and the running flag is what decides
// whether this one hears anything at all.

extern crate alloc;

use mac80211::hw::Ieee80211Hw;
use mac80211::ops::{AmpduAction, Conf, HwStats, Ieee80211Ops, StaState, TxInfo, Vif};
use mac80211::{flags, RxStatus};
use mac80211::Errno;
use wireless::ieee80211::MacAddr;
use wireless::uapi::enums::IfType;

use crate::medium;

/// What a virtual radio advertises it can do. It reports signal strength in
/// dBm, it runs the access-point exchange itself — there being no userspace
/// daemon behind a virtual radio — and it has no cipher engine, so every
/// cipher runs in the layer above and is exercised by every frame.
pub const HW_FLAGS: u32 = flags::hw::SIGNAL_DBM
    | flags::hw::AP_SME
    | flags::hw::REPORTS_TX_ACK_STATUS
    | flags::hw::SUPPORTS_DYNAMIC_PS;

/// The driver behind one virtual radio.
pub struct HwsimOps {
    /// Which radio this is. The radio itself lives on the medium; holding it
    /// here would be a reference cycle through the softmac device.
    pub index: u32,
}

impl HwsimOps {
    /// Build the driver for a radio index. # C: O(1)
    pub fn new(index: u32) -> Self { Self { index } }
}

impl Ieee80211Ops for HwsimOps {
    /// # C: O(N radios)
    fn start(&self, _hw: &Ieee80211Hw) -> Result<(), Errno> {
        let Some(radio) = medium::radio(self.index) else { return Err(Errno::Enodev); };
        *radio.started.lock() = true;
        Ok(())
    }

    /// # C: O(N radios)
    fn stop(&self, _hw: &Ieee80211Hw) {
        let Some(radio) = medium::radio(self.index) else { return; };
        *radio.started.lock() = false;
    }

    /// # C: O(1)
    fn add_interface(&self, _hw: &Ieee80211Hw, _vif: &Vif) -> Result<(), Errno> { Ok(()) }

    /// A virtual radio has no per-interface hardware state, so a type change
    /// costs nothing and is allowed rather than refused. # C: O(1)
    fn change_interface(&self, _hw: &Ieee80211Hw, _vif: &Vif, _new: IfType)
        -> Result<(), Errno> { Ok(()) }

    /// # C: O(N radios)
    fn config(&self, _hw: &Ieee80211Hw, conf: &Conf, changed: u32) -> Result<(), Errno> {
        if changed & flags::conf_changed::CHANNEL == 0 { return Ok(()); }
        let Some(radio) = medium::radio(self.index) else { return Err(Errno::Enodev); };
        *radio.chan.lock() = conf.chandef;
        Ok(())
    }

    /// # C: O(1)
    fn sta_state(&self, _hw: &Ieee80211Hw, _vif: &Vif, _sta: MacAddr, _old: StaState,
                 _new: StaState) -> Result<(), Errno> { Ok(()) }

    /// A virtual radio holds no key: refusing here is what makes the layer
    /// above run its own ciphers, which is the whole reason this driver
    /// exists. # C: O(1)
    fn set_key(&self, _hw: &Ieee80211Hw, _vif: &Vif, _remove: bool,
               _key: &mac80211::ops::KeyConf) -> Result<(), Errno> {
        Err(Errno::Eopnotsupp)
    }

    /// Aggregation needs nothing of the radio; the layer above keeps the
    /// windows. # C: O(1)
    fn ampdu_action(&self, _hw: &Ieee80211Hw, _vif: &Vif, _sta: MacAddr,
                    _action: AmpduAction) -> Result<(), Errno> { Ok(()) }

    /// Put the frame on the medium. # C: O(N radios × len)
    fn tx(&self, _hw: &Ieee80211Hw, _vif: Option<&Vif>, _info: &TxInfo, frame: &[u8]) {
        medium::transmit(self.index, frame);
    }

    /// # C: O(1)
    fn get_tsf(&self, _hw: &Ieee80211Hw, _vif: &Vif) -> u64 { medium::now_ns() / 1000 }

    /// # C: O(N radios)
    fn get_stats(&self, _hw: &Ieee80211Hw) -> HwStats {
        use core::sync::atomic::Ordering;
        let Some(radio) = medium::radio(self.index) else { return HwStats::default(); };
        HwStats {
            tx_packets: radio.stats.tx_frames.load(Ordering::Relaxed),
            tx_bytes: radio.stats.tx_bytes.load(Ordering::Relaxed),
            tx_failed: radio.stats.tx_unheard.load(Ordering::Relaxed),
            rx_packets: radio.stats.rx_frames.load(Ordering::Relaxed),
            rx_bytes: radio.stats.rx_bytes.load(Ordering::Relaxed),
            rx_dropped: 0,
        }
    }

    /// # C: O(N channels)
    fn get_survey(&self, hw: &Ieee80211Hw, idx: usize) -> Option<wireless::ops::SurveyInfo> {
        let chan = hw.bands.iter().flat_map(|b| b.channels.iter()).nth(idx)?;
        let current = medium::radio(self.index).and_then(|r| r.channel());
        Some(wireless::ops::SurveyInfo {
            freq: chan.center_freq,
            noise: Some(NOISE_FLOOR_DBM),
            in_use: current.is_some_and(|c| c.chan.center_freq == chan.center_freq),
            ..Default::default()
        })
    }
}

/// Noise floor the virtual radios report.
const NOISE_FLOOR_DBM: i8 = -95;

/// The receive status a frame carried into the layer above. Exposed so a
/// caller injecting a frame directly, rather than through another radio, uses
/// the same shape the medium does. # C: O(1)
pub fn rx_status(freq: u32, now_ns: u64) -> RxStatus {
    RxStatus { freq, signal: crate::limits::SIGNAL_DBM, rate_idx: 0, flags: 0, now_ns,
               mactime: now_ns / 1000 }
}
