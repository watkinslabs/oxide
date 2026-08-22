// Shared fixtures for the test suites: addresses, frame headers, and a radio
// with a driver that records what it was asked to transmit.

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Wiphy as WiphyLock};
use wireless::chan::{ChanDef, Channel};
use wireless::ieee80211::{fctl, hdr::MacHeader, MacAddr};
use wireless::uapi::enums::{Band, IfType};
use wireless::wiphy::{caps::standard_bitrates, WiphyBand};

use crate::hw::{alloc_hw, Ieee80211Hw, Local};
use crate::iface::Sdata;
use crate::netdev::convert::EthFrame;
use crate::netdev::RxDeliver;
use crate::ops::{BssConf, Ieee80211Ops, TxInfo, Vif};

/// Addresses used throughout, chosen so no two share a byte pattern that
/// could make a mixed-up address map look correct.
pub const AP: MacAddr = MacAddr([0x02, 0x00, 0xaa, 0xaa, 0xaa, 0x01]);
pub const STA: MacAddr = MacAddr([0x02, 0x00, 0xbb, 0xbb, 0xbb, 0x02]);
pub const PEER: MacAddr = MacAddr([0x02, 0x00, 0xcc, 0xcc, 0xcc, 0x03]);
pub const OTHER: MacAddr = MacAddr([0x02, 0x00, 0xdd, 0xdd, 0xdd, 0x04]);

/// A 2.4 GHz channel every fixture operates on.
pub fn chandef() -> ChanDef {
    ChanDef::new_20(Channel::new(2412, Band::Band2Ghz, 20))
}

/// Build a three-address data-frame header travelling from the distribution
/// system, as an access point sends to a station. # C: O(1)
pub fn data_hdr_from_ds(da: MacAddr, bssid: MacAddr, sa: MacAddr, tid: Option<u8>,
                        protected: bool) -> Vec<u8> {
    let mut out = Vec::new();
    wireless::ieee80211::build::data_header_from_ds(&mut out, da, bssid, sa, tid, protected);
    out
}

/// The same, travelling toward the distribution system. # C: O(1)
pub fn data_hdr_to_ds(bssid: MacAddr, sa: MacAddr, da: MacAddr, tid: Option<u8>,
                      protected: bool) -> Vec<u8> {
    let mut out = Vec::new();
    wireless::ieee80211::build::data_header_to_ds(&mut out, bssid, sa, da, tid, protected);
    out
}

/// Parse a header the fixtures built. # C: O(1)
pub fn parse(hdr: &[u8]) -> MacHeader { MacHeader::parse(hdr).expect("fixture header parses") }

/// Set the sequence-control field of a built header. # C: O(1)
pub fn with_seq(mut hdr: Vec<u8>, sn: u16, frag: u16) -> Vec<u8> {
    wireless::ieee80211::build::set_seq_ctrl(&mut hdr, fctl::sn_to_seq(sn, frag));
    hdr
}

/// A driver that records every frame it was handed.
pub struct Recorder {
    pub frames: Spinlock<Vec<Vec<u8>>, WiphyLock>,
    pub bss: Spinlock<Vec<(BssConf, u32)>, WiphyLock>,
}

impl Recorder {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        Arc::new(Self { frames: Spinlock::new(Vec::new()), bss: Spinlock::new(Vec::new()) })
    }
    /// Frames transmitted so far. # C: O(N frames)
    pub fn taken(&self) -> Vec<Vec<u8>> { core::mem::take(&mut self.frames.lock()) }
    /// How many frames went out. # C: O(1)
    pub fn count(&self) -> usize { self.frames.lock().len() }
}

impl Ieee80211Ops for Recorder {
    /// # C: O(len)
    fn tx(&self, _hw: &Ieee80211Hw, _vif: Option<&Vif>, _info: &TxInfo, frame: &[u8]) {
        self.frames.lock().push(frame.to_vec());
    }
    fn bss_info_changed(&self, _hw: &Ieee80211Hw, _vif: &Vif, conf: &BssConf, changed: u32) {
        self.bss.lock().push((conf.clone(), changed));
    }
}

/// A delivery hook that records every converted frame. # C: O(1)
pub struct Collector {
    pub eth: Spinlock<Vec<EthFrame>, WiphyLock>,
}

impl Collector {
    /// # C: O(1)
    pub fn new() -> Arc<Self> { Arc::new(Self { eth: Spinlock::new(Vec::new()) }) }
    /// Frames delivered so far. # C: O(N frames)
    pub fn taken(&self) -> Vec<EthFrame> { core::mem::take(&mut self.eth.lock()) }
}

impl RxDeliver for Collector {
    /// # C: O(len)
    fn deliver_eth(&self, eth: &EthFrame) { self.eth.lock().push(eth.clone()); }
}

/// A radio with the recording driver, registered so it has a configuration
/// device. # C: O(channels)
pub fn radio(addr: MacAddr) -> (Arc<Local>, Arc<Recorder>) {
    let rec = Recorder::new();
    let hw = Ieee80211Hw {
        addr,
        bands: alloc::vec![WiphyBand::new(Band::Band2Ghz,
            alloc::vec![Channel::new(2412, Band::Band2Ghz, 20)],
            standard_bitrates(Band::Band2Ghz))],
        iftypes: (1 << IfType::Station.as_u32()) | (1 << IfType::Ap.as_u32())
            | (1 << IfType::Monitor.as_u32()),
        flags: crate::flags::hw::SIGNAL_DBM | crate::flags::hw::AP_SME,
        ..Default::default()
    };
    let local = alloc_hw(hw, rec.clone());
    crate::hw::register_hw(&local).expect("fixture radio registers");
    (local, rec)
}

/// An interface on a radio, up and on the fixture channel. # C: O(1)
pub fn iface(local: &Arc<Local>, iftype: IfType, name: &str) -> Arc<Sdata> {
    let sdata = crate::iface::add(local, iftype, alloc::string::String::from(name), None)
        .expect("fixture interface is created");
    crate::iface::up(local, &sdata).expect("fixture interface comes up");
    crate::iface::set_channel(local, &sdata, chandef());
    sdata
}

/// Tear a fixture radio down so the global registry does not accumulate.
/// # C: O(N interfaces)
pub fn drop_radio(local: &Arc<Local>) { crate::hw::unregister_hw(local); }
