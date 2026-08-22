// Fixtures every nl80211 command test shares: a radio with two bands, a
// driver that records what it was asked to do, request builders and reply
// readers.
//
// The radio registry is one global list, so every test here takes the same
// lock before touching it. Without that, two tests running at once would see
// each other's interfaces and the failures would look like ordering bugs in
// the code under test.
//
// Module manifest:
// - `ops_mod`:  the fake driver and the calls it records.
// - `wire_mod`: request building and reply reading.

extern crate alloc;
extern crate std;

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::chan::Channel;
use crate::ieee80211::MacAddr;
use crate::ops::{Cfg80211Ops, NewIfaceParams};
use crate::sta::StationInfo;
use crate::uapi::ciphers::cipher;
use crate::uapi::enums::{feature_flags, Band, IfType};
use crate::wdev::Wdev;
use crate::wiphy::caps::{standard_bitrates, MgmtStypes, WiphyBand, WiphyCaps};
use crate::wiphy::{registry, Wiphy};

#[path = "support/ops.rs"]
mod ops_mod;
#[path = "support/wire.rs"]
mod wire_mod;

pub use ops_mod::{Call, FakeOps};
pub use wire_mod::{children, find, has, mgmt_frame, u16_of, u32_of, u8_of, Req};

/// Port a test's requests come from.
pub const PORT: u32 = 4242;
/// A second port, for the tests that need two readers.
pub const PORT_B: u32 = 4343;
/// Namespace every fixture radio lives in.
pub const NS: u64 = 0;

/// Serialises every test that touches the global radio list. # C: O(1)
pub fn lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    let m = L.get_or_init(|| Mutex::new(()));
    let g = m.lock().unwrap_or_else(|e| e.into_inner());
    registry::reset_for_tests();
    g
}

/// A station report with a field of every shape the emitter handles.
/// # C: O(1)
pub fn station_report(mac: MacAddr) -> StationInfo {
    use crate::sta::{rate_gen, RateInfo, StaFlags};
    use crate::uapi::enums::ChanWidth;
    use crate::uapi::nested::sta_flag;
    let mut flags = StaFlags::default();
    flags.put(sta_flag::AUTHORIZED, true);
    flags.put(sta_flag::AUTHENTICATED, true);
    flags.put(sta_flag::WME, false);
    StationInfo {
        mac, generation: 7,
        inactive_time: Some(120), rx_bytes: Some(4096), tx_bytes: Some(8192),
        signal: Some(-42),
        tx_bitrate: Some(RateInfo { bitrate: 650, mcs: Some(7), nss: None,
                                    width: ChanWidth::Width40, short_gi: true,
                                    generation: rate_gen::HT }),
        rx_bitrate: Some(RateInfo { bitrate: 866_7, mcs: Some(9), nss: Some(2),
                                    width: ChanWidth::Width80, short_gi: false,
                                    generation: rate_gen::VHT }),
        sta_flags: Some(flags),
        ..Default::default()
    }
}

/// Capabilities every fixture radio advertises. # C: O(1)
pub fn caps() -> WiphyCaps {
    let chans_2g: Vec<Channel> = (1..=13)
        .map(|n| Channel::new(2407 + n * 5, Band::Band2Ghz, 20)).collect();
    let mut chans_5g: Vec<Channel> = [5180u32, 5200, 5220, 5240, 5260, 5280]
        .iter().map(|&f| Channel::new(f, Band::Band5Ghz, 23)).collect();
    // One channel is barred outright and one needs a radar check, so a test
    // can tell a written flag from an omitted one.
    chans_5g[4].flags |= crate::chan::chan_flags::DISABLED;
    chans_5g[5].flags |= crate::chan::chan_flags::RADAR | crate::chan::chan_flags::NO_IR;
    chans_5g[5].dfs_cac_ms = 60_000;

    let mut band_2g = WiphyBand::new(Band::Band2Ghz, chans_2g,
                                     standard_bitrates(Band::Band2Ghz));
    band_2g.ht_cap = Some([0x2c; 26]);
    let mut band_5g = WiphyBand::new(Band::Band5Ghz, chans_5g,
                                     standard_bitrates(Band::Band5Ghz));
    band_5g.ht_cap = Some([0x2c; 26]);
    band_5g.vht_cap = Some([0x11; 12]);

    let mut caps = WiphyCaps {
        bands: alloc::vec![band_2g, band_5g],
        cipher_suites: alloc::vec![cipher::WEP40, cipher::WEP104, cipher::TKIP,
                                   cipher::CCMP, cipher::AES_CMAC],
        max_scan_ssids: 4,
        max_scan_ie_len: 256,
        max_num_pmkids: 16,
        available_antennas_tx: 3,
        available_antennas_rx: 3,
        features: feature_flags::SCAN_FLUSH | feature_flags::LOW_PRIORITY_SCAN
            | feature_flags::SCAN_RANDOM_MAC_ADDR | feature_flags::SAE,
        flags: crate::wiphy::flags::OFFCHAN_TX,
        mgmt_stypes: alloc::vec![
            MgmtStypes { iftype: IfType::Station.as_u32(), tx: 0xffff, rx: 0xffff },
            MgmtStypes { iftype: IfType::Ap.as_u32(), tx: 0xffff, rx: 0xffff },
            MgmtStypes { iftype: IfType::Monitor.as_u32(), tx: 0, rx: 0 },
        ],
        ..Default::default()
    };
    for ty in [IfType::Station, IfType::Ap, IfType::Monitor, IfType::P2pClient,
               IfType::P2pGo, IfType::P2pDevice] {
        caps.add_iftype(ty);
    }
    caps.add_ext_feature(crate::uapi::enums::ext_feature::MFP_OPTIONAL);
    caps
}

/// A registered radio and the driver behind it. # C: O(N radios)
pub fn radio() -> (Arc<Wiphy>, Arc<FakeOps>) {
    radio_from_caps(caps())
}

/// A registered radio with a caller-selected immutable advertisement. # C: O(N radios)
pub fn radio_from_caps(caps: WiphyCaps) -> (Arc<Wiphy>, Arc<FakeOps>) {
    let ops = Arc::new(FakeOps::default());
    let wiphy = Wiphy::new(MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]), caps,
                           ops.clone());
    (registry::register(wiphy).expect("register"), ops)
}

/// A radio with one interface of a given type already on it.
/// # C: O(N radios)
pub fn radio_with(iftype: IfType) -> (Arc<Wiphy>, Arc<FakeOps>, Arc<Wdev>) {
    radio_with_caps(caps(), iftype)
}

/// A caller-selected radio with one interface already on it. # C: O(N radios)
pub fn radio_with_caps(caps: WiphyCaps, iftype: IfType)
    -> (Arc<Wiphy>, Arc<FakeOps>, Arc<Wdev>)
{
    let (wiphy, ops) = radio_from_caps(caps);
    let params = NewIfaceParams {
        name: "wlan0".to_string(), iftype, addr: None, use_4addr: None, mntr_flags: 0,
    };
    let wdev = ops.add_virtual_intf(&wiphy, &params).expect("add iface");
    wiphy.add_wdev(wdev.clone());
    ops.calls.lock().unwrap().clear();
    (wiphy, ops, wdev)
}
