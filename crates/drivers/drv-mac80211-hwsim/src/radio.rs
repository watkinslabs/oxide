// One virtual radio.
//
// Its address is derived from its index with the locally administered bit
// set, so several radios never claim the same address and none of them claims
// an address a real manufacturer might have assigned.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU64, Ordering};

use mac80211::hw::Ieee80211Hw;
use mac80211::Local;
use sync::{Devices as MediumLock, Spinlock};
use wireless::chan::{ChanDef, Channel};
use wireless::ieee80211::MacAddr;
use wireless::uapi::enums::{Band, IfType};
use wireless::wiphy::{caps::standard_bitrates, WiphyBand};

use crate::limits;

/// Address of the radio at `index`. # C: O(1)
pub fn radio_addr(index: u32) -> MacAddr {
    let mut a = limits::ADDR_PREFIX;
    a[4] = (index >> 8) as u8;
    a[5] = index as u8;
    MacAddr(a)
}

/// Counters one radio keeps.
#[derive(Default)]
pub struct RadioStats {
    pub tx_frames: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_frames: AtomicU64,
    pub rx_bytes: AtomicU64,
    /// Frames transmitted while no other radio was listening on the channel.
    pub tx_unheard: AtomicU64,
}

/// One virtual radio and its attachment to the softmac layer.
pub struct Radio {
    pub index: u32,
    pub addr: MacAddr,
    pub local: Arc<Local>,
    /// Channel the radio is tuned to. A frame is only heard by a radio on the
    /// same one, which is what makes a scan across channels mean anything.
    pub chan: Spinlock<Option<ChanDef>, MediumLock>,
    /// Whether the radio is running.
    pub started: Spinlock<bool, MediumLock>,
    pub stats: RadioStats,
}

impl Radio {
    /// Current channel. # C: O(1)
    pub fn channel(&self) -> Option<ChanDef> { *self.chan.lock() }
    /// Whether the radio is running. # C: O(1)
    pub fn is_running(&self) -> bool { *self.started.lock() }
    /// Note a transmitted frame. # C: O(1)
    pub fn note_tx(&self, len: usize) {
        self.stats.tx_frames.fetch_add(1, Ordering::Relaxed);
        self.stats.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
    }
    /// Note a received frame. # C: O(1)
    pub fn note_rx(&self, len: usize) {
        self.stats.rx_frames.fetch_add(1, Ordering::Relaxed);
        self.stats.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
    }
}

/// The 2.4 GHz channels every virtual radio offers. # C: O(N channels)
pub fn channels_2ghz() -> Vec<Channel> {
    (1..=limits::CHANNELS_2GHZ)
        .map(|n| Channel::new(wireless::chan::channel_to_freq(n as i32, Band::Band2Ghz),
                              Band::Band2Ghz, limits::MAX_POWER_DBM))
        .collect()
}

/// The 5 GHz channels every virtual radio offers. # C: O(N channels)
pub fn channels_5ghz() -> Vec<Channel> {
    limits::CHANNELS_5GHZ.iter()
        .map(|&n| Channel::new(wireless::chan::channel_to_freq(n, Band::Band5Ghz),
                               Band::Band5Ghz, limits::MAX_POWER_DBM))
        .collect()
}

/// What one virtual radio advertises. # C: O(N channels)
pub fn hw_for(index: u32) -> Ieee80211Hw {
    let mut iftypes = 0u32;
    for ty in [IfType::Station, IfType::Ap, IfType::Adhoc, IfType::Monitor] {
        iftypes |= 1u32 << ty.as_u32();
    }
    Ieee80211Hw {
        addr: radio_addr(index),
        addr_mask: MacAddr([0, 0, 0, 0, 0, 0xff]),
        bands: alloc::vec![
            WiphyBand::new(Band::Band2Ghz, channels_2ghz(), standard_bitrates(Band::Band2Ghz)),
            WiphyBand::new(Band::Band5Ghz, channels_5ghz(), standard_bitrates(Band::Band5Ghz)),
        ],
        // The radio has no cipher engine: every cipher runs in software,
        // which is the point of a radio that exists to exercise the layer
        // above it.
        hw_ciphers: Vec::new(),
        flags: crate::ops::HW_FLAGS,
        iftypes,
        queues: mac80211::uapi::ac::COUNT as u8,
        extra_tx_headroom: 0,
        extra_tx_tailroom: 0,
        max_stations: limits::MAX_STATIONS,
        max_rx_aggregation_subframes: limits::MAX_AGG_SUBFRAMES,
        max_tx_aggregation_subframes: limits::MAX_AGG_SUBFRAMES,
        driver_name: String::from(limits::DRIVER_NAME),
    }
}
