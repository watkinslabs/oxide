// Two virtual radios associating over the simulated medium, end to end.
//
// This is the acceptance evidence for the whole stack. An access point on one
// radio and a station on another, on the same channel, run the real
// authenticate and associate exchange as real frames across the medium — no
// injected state, no shortcut — and then carry a data frame between them.
// Every layer is exercised: the frame builders, the transmit chain, the
// medium, the receive chain, the management dispatch, both halves of the
// management entity, the station tables and the conversion.

extern crate std;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use std::sync::{Mutex, MutexGuard};

use mac80211::netdev::convert::EthFrame;
use mac80211::netdev::RxDeliver;
use mac80211::ops::StaState;
use mac80211::{Local, Sdata};
use sync::{Spinlock, Wiphy as WiphyLock};
use wireless::chan::{ChanDef, Channel};
use wireless::uapi::enums::{Band, IfType};

use crate::{medium, radio_addr};

/// The medium and the radio registry are global, so the suites that use them
/// run one at a time.
static MEDIUM: Mutex<()> = Mutex::new(());

/// A radio index base per test, so a leaked radio from one cannot be mistaken
/// for another's.
const AP_INDEX: u32 = 0;
const STA_INDEX: u32 = 1;

const SSID: &[u8] = b"oxide-test";
const ETH_P_IP: u16 = 0x0800;

/// Where the access point's converted frames are collected.
struct Sink {
    frames: Spinlock<Vec<EthFrame>, WiphyLock>,
}

impl Sink {
    fn new() -> Arc<Self> { Arc::new(Self { frames: Spinlock::new(Vec::new()) }) }
    fn taken(&self) -> Vec<EthFrame> { core::mem::take(&mut self.frames.lock()) }
}

impl RxDeliver for Sink {
    /// # C: O(len)
    fn deliver_eth(&self, eth: &EthFrame) { self.frames.lock().push(eth.clone()); }
}

fn chandef() -> ChanDef { ChanDef::new_20(Channel::new(2412, Band::Band2Ghz, 20)) }

/// Build the two radios and their interfaces, both on the same channel.
struct Pair {
    ap_local: Arc<Local>,
    ap: Arc<Sdata>,
    sta_local: Arc<Local>,
    sta: Arc<Sdata>,
    _guard: MutexGuard<'static, ()>,
}

fn pair() -> Pair {
    let guard = MEDIUM.lock().unwrap_or_else(|e| e.into_inner());
    // Whatever a previous suite left behind goes first: the medium and the
    // radio registry are global.
    crate::shutdown();
    medium::clear();
    medium::set_now_ns(0);

    let ap_radio = crate::add_radio(AP_INDEX).expect("the access-point radio registers");
    let sta_radio = crate::add_radio(STA_INDEX).expect("the station radio registers");

    let ap_local = ap_radio.local.clone();
    let sta_local = sta_radio.local.clone();

    let ap = mac80211::iface::add(&ap_local, IfType::Ap, "hwap0".into(), None)
        .expect("the access-point interface is created");
    mac80211::iface::up(&ap_local, &ap).expect("it comes up");
    mac80211::iface::set_channel(&ap_local, &ap, chandef());
    mac80211::iface::update_bss(&ap_local, &ap, |bss| {
        bss.ssid = SSID.to_vec();
        bss.bssid = Some(ap.addr);
        bss.enable_beacon = true;
    });

    let sta = mac80211::iface::add(&sta_local, IfType::Station, "hwsta0".into(), None)
        .expect("the station interface is created");
    mac80211::iface::up(&sta_local, &sta).expect("it comes up");
    mac80211::iface::set_channel(&sta_local, &sta, chandef());

    Pair { ap_local, ap, sta_local, sta, _guard: guard }
}

impl Drop for Pair {
    fn drop(&mut self) {
        crate::shutdown();
        medium::clear();
    }
}

/// Run the join the way userspace would ask for it.
fn join(p: &Pair) {
    mac80211::mlme::run::start(&p.sta_local, &p.sta, p.ap.addr, SSID.to_vec(),
                               wireless::ieee80211::mgmt::auth_alg::OPEN, Vec::new(), false);
}

#[test]
fn two_radios_reach_the_associated_state_over_the_medium() {
    let p = pair();
    assert_eq!(medium::count(), 2);
    assert_eq!(p.ap.addr, radio_addr(AP_INDEX));
    assert_eq!(p.sta.addr, radio_addr(STA_INDEX));
    assert_ne!(p.ap.addr, p.sta.addr);

    join(&p);

    // The station's own view.
    assert!(p.sta.is_assoc(), "the station did not associate");
    assert_eq!(p.sta.bssid(), Some(p.ap.addr));
    let aid = p.sta.with(|s| s.mlme.aid);
    assert!(aid > 0, "the network handed out no association identifier");
    assert_eq!(p.sta.stas.state(p.ap.addr), StaState::Authorized,
               "an open network opens the port on association");

    // The access point's view of the same link.
    assert!(p.ap.stas.contains(p.sta.addr), "the access point has no record of the station");
    assert_eq!(p.ap.stas.state(p.sta.addr), StaState::Authorized);
    assert_eq!(p.ap.stas.with(p.sta.addr, |s| s.aid), Some(aid),
               "the two ends disagree about the association identifier");
}

#[test]
fn the_exchange_really_crossed_the_medium() {
    let p = pair();
    let before_tx = medium::radio(STA_INDEX).unwrap().stats.tx_frames
        .load(core::sync::atomic::Ordering::Relaxed);
    join(&p);
    let sta_radio = medium::radio(STA_INDEX).unwrap();
    let ap_radio = medium::radio(AP_INDEX).unwrap();
    use core::sync::atomic::Ordering::Relaxed;
    // Two frames out of the station (authenticate, associate) and two back.
    assert!(sta_radio.stats.tx_frames.load(Relaxed) - before_tx >= 2);
    assert!(ap_radio.stats.tx_frames.load(Relaxed) >= 2);
    assert!(sta_radio.stats.rx_frames.load(Relaxed) >= 2);
    assert!(ap_radio.stats.rx_frames.load(Relaxed) >= 2);
    assert_eq!(sta_radio.stats.tx_unheard.load(Relaxed), 0,
               "every frame the station sent was heard");
}

#[test]
fn a_data_frame_sent_by_the_station_arrives_at_the_access_point() {
    let p = pair();
    join(&p);
    assert!(p.sta.is_assoc());

    let sink = Sink::new();
    *p.ap.deliver.lock() = Some(sink.clone());

    let payload: Vec<u8> = (0u8..64).collect();
    let eth = EthFrame {
        dst: wireless::ieee80211::MacAddr([0x02, 0x00, 0x11, 0x22, 0x33, 0x44]),
        src: p.sta.addr,
        proto: ETH_P_IP,
        payload: payload.clone(),
    };
    assert!(mac80211::tx::xmit_eth(&p.sta_local, &p.sta, &eth), "the frame was refused");

    let got = sink.taken();
    assert_eq!(got.len(), 1, "the access point did not receive the frame");
    assert_eq!(got[0].dst, eth.dst, "the destination did not survive the conversion");
    assert_eq!(got[0].src, p.sta.addr, "the source did not survive the conversion");
    assert_eq!(got[0].proto, ETH_P_IP);
    assert_eq!(got[0].payload, payload);
}

#[test]
fn a_data_frame_sent_by_the_access_point_arrives_at_the_station() {
    let p = pair();
    join(&p);

    let sink = Sink::new();
    *p.sta.deliver.lock() = Some(sink.clone());

    let payload = vec![0xa5u8; 100];
    let eth = EthFrame {
        dst: p.sta.addr,
        src: wireless::ieee80211::MacAddr([0x02, 0x00, 0x55, 0x66, 0x77, 0x88]),
        proto: ETH_P_IP,
        payload: payload.clone(),
    };
    assert!(mac80211::tx::xmit_eth(&p.ap_local, &p.ap, &eth));

    let got = sink.taken();
    assert_eq!(got.len(), 1, "the station did not receive the frame");
    assert_eq!(got[0].dst, p.sta.addr);
    assert_eq!(got[0].src, eth.src);
    assert_eq!(got[0].payload, payload);
}

#[test]
fn radios_on_different_channels_do_not_hear_each_other() {
    // The channel filter is what makes a scan mean anything; without it every
    // radio hears every frame and a channel walk finds the same networks
    // everywhere.
    let p = pair();
    let other = ChanDef::new_20(Channel::new(2437, Band::Band2Ghz, 20));
    mac80211::iface::set_channel(&p.sta_local, &p.sta, other);
    join(&p);
    assert!(!p.sta.is_assoc(), "the station associated to a network on another channel");
    assert!(!p.ap.stas.contains(p.sta.addr));
    use core::sync::atomic::Ordering::Relaxed;
    assert!(medium::radio(STA_INDEX).unwrap().stats.tx_unheard.load(Relaxed) > 0,
            "the frames should have gone unheard");
}

#[test]
fn a_station_that_never_authenticated_is_refused_association() {
    let p = pair();
    // Send an association request with no authentication before it. The
    // access point must say so rather than admit the station, because a
    // supplicant branches on that answer and starts again.
    let elements = {
        let mut e = Vec::new();
        wireless::ieee80211::build::element(&mut e, 0, SSID);
        e
    };
    let frame = wireless::ieee80211::build::assoc_req(p.ap.addr, p.sta.addr,
        wireless::ieee80211::mgmt::capability::ESS, 10, None, &elements);
    let status = crate::ops::rx_status(2412, medium::now_ns());
    mac80211::rx(&p.ap_local, &status, &frame);
    assert!(!p.ap.stas.contains(p.sta.addr));
}

#[test]
fn the_link_ends_when_the_station_deauthenticates() {
    let p = pair();
    join(&p);
    assert!(p.sta.is_assoc());

    mac80211::mlme::deauth::deauth_peer(&p.sta_local, &p.sta, p.ap.addr,
        wireless::ieee80211::status::reason::DEAUTH_LEAVING, false);

    assert!(!p.sta.is_assoc(), "the station still believes it is associated");
    assert!(!p.sta.stas.contains(p.ap.addr));
    assert!(!p.ap.stas.contains(p.sta.addr),
            "the access point still holds a station that left");
}

#[test]
fn the_access_point_answers_a_probe_for_its_own_network_and_not_another() {
    let p = pair();
    use core::sync::atomic::Ordering::Relaxed;
    let ap_radio = medium::radio(AP_INDEX).unwrap();
    let before = ap_radio.stats.tx_frames.load(Relaxed);

    let probe = wireless::ieee80211::build::probe_req(p.sta.addr, p.ap.addr, SSID, &[]);
    let status = crate::ops::rx_status(2412, medium::now_ns());
    mac80211::rx(&p.ap_local, &status, &probe);
    let after_ours = ap_radio.stats.tx_frames.load(Relaxed);
    assert!(after_ours > before, "the network did not answer a probe for itself");

    let other = wireless::ieee80211::build::probe_req(p.sta.addr, p.ap.addr,
                                                      b"somebody-else", &[]);
    mac80211::rx(&p.ap_local, &status, &other);
    assert_eq!(ap_radio.stats.tx_frames.load(Relaxed), after_ours,
               "the network answered a probe for a network it does not serve");
}
