// The receive and transmit chains end to end on one interface pair, so the
// ciphers, the duplicate check and the replay check are exercised where they
// are actually wired rather than only where they are defined.

use alloc::vec;
use alloc::vec::Vec;

use wireless::ieee80211::{fctl, hdr::MacHeader};
use wireless::uapi::ciphers::cipher;
use wireless::uapi::enums::IfType;

use crate::key::Key;
use crate::netdev::convert::EthFrame;
use crate::ops::{RxStatus, StaState};
use crate::tests_fixture as f;

const ETH_P_IP: u16 = 0x0800;

/// A station interface that believes it is associated to `f::AP`.
fn station(name: &str, keyed: bool)
    -> (alloc::sync::Arc<crate::Local>, alloc::sync::Arc<crate::Sdata>,
        alloc::sync::Arc<f::Recorder>)
{
    let (local, rec) = f::radio(f::STA);
    let sdata = f::iface(&local, IfType::Station, name);
    if keyed {
        sdata.with(|s| s.keys.install(
            Key::new(cipher::CCMP, vec![0x5a; 16], 0, true, Some(f::AP), None)));
    }
    crate::iface::update_bss(&local, &sdata, |bss| {
        bss.assoc = true;
        bss.bssid = Some(f::AP);
        bss.port_authorized = true;
    });
    sdata.stas.insert(crate::sta_info::Sta::new(f::AP, 0));
    sdata.stas.set_state(f::AP, StaState::Authorized, |_, _| true);
    rec.taken();
    (local, sdata, rec)
}

#[test]
fn a_transmitted_frame_is_encrypted_and_the_same_key_decrypts_it_back() {
    let (local, sdata, rec) = station("wlan-crypt", true);
    let sink = f::Collector::new();
    *sdata.deliver.lock() = Some(sink.clone());

    let payload: Vec<u8> = (0u8..32).collect();
    let eth = EthFrame { dst: f::PEER, src: f::STA, proto: ETH_P_IP,
                         payload: payload.clone() };
    assert!(crate::tx::xmit_eth(&local, &sdata, &eth));
    let sent = rec.taken();
    assert_eq!(sent.len(), 1);
    let frame = &sent[0];
    let hdr = MacHeader::parse(frame).unwrap();
    assert!(fctl::is_protected(hdr.frame_control), "the frame went out in the clear");
    assert!(!frame.windows(payload.len()).any(|w| w == &payload[..]),
            "the payload is recognisable in the transmitted frame");

    // Turn it round: the same frame arriving from the access point, under the
    // same key, must come back out as the Ethernet frame that went in.
    let mut back = frame.clone();
    let fc = (u16::from_le_bytes([back[0], back[1]]) & !fctl::FCTL_TODS)
        | fctl::FCTL_FROMDS;
    back[0..2].copy_from_slice(&fc.to_le_bytes());
    // Swap the address fields so the frame is addressed to us from the
    // network, which is the direction the receive chain accepts.
    back[4..10].copy_from_slice(&f::STA.0);
    back[10..16].copy_from_slice(&f::AP.0);
    back[16..22].copy_from_slice(&f::PEER.0);

    // The header changed, so the frame must be re-sealed under it — the
    // header is authenticated, which is exactly what the test above proves.
    let hdr = MacHeader::parse(&back).unwrap();
    let sealed = crate::crypto::ccmp::encrypt(&[0x5a; 16], &hdr,
        crate::crypto::pn::Pn(1), 0, &{
            let mut b = Vec::new();
            wireless::ieee80211::build::snap_header(&mut b, ETH_P_IP);
            b.extend_from_slice(&payload);
            b
        }).unwrap();
    let mut rx_frame = back[..hdr.len].to_vec();
    rx_frame.extend_from_slice(&sealed);

    let status = RxStatus { freq: 2412, now_ns: 10, ..Default::default() };
    crate::rx::rx(&local, &status, &rx_frame);
    let got = sink.taken();
    assert_eq!(got.len(), 1, "the protected frame did not reach the stack");
    assert_eq!(got[0].payload, payload);
    assert_eq!(got[0].proto, ETH_P_IP);
    f::drop_radio(&local);
}

#[test]
fn a_replayed_frame_is_dropped_by_the_receive_chain() {
    let (local, sdata, _rec) = station("wlan-replay", true);
    let sink = f::Collector::new();
    *sdata.deliver.lock() = Some(sink.clone());

    let payload: Vec<u8> = (0u8..16).collect();
    let mut body = Vec::new();
    wireless::ieee80211::build::snap_header(&mut body, ETH_P_IP);
    body.extend_from_slice(&payload);

    let hdr_bytes = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, true);
    let hdr = f::parse(&hdr_bytes);
    let sealed = crate::crypto::ccmp::encrypt(&[0x5a; 16], &hdr,
                                              crate::crypto::pn::Pn(5), 0, &body).unwrap();
    let mut frame = hdr_bytes.clone();
    frame.extend_from_slice(&sealed);

    let status = RxStatus { freq: 2412, now_ns: 10, ..Default::default() };
    crate::rx::rx(&local, &status, &frame);
    assert_eq!(sink.taken().len(), 1, "the first copy must be delivered");

    let before = sdata.stats().rx_crypto_failed;
    crate::rx::rx(&local, &status, &frame);
    assert_eq!(sink.taken().len(), 0, "the replayed copy must not be delivered");
    assert_eq!(sdata.stats().rx_crypto_failed, before + 1);
    f::drop_radio(&local);
}

#[test]
fn an_unprotected_frame_is_dropped_on_an_interface_that_has_keys() {
    // An attacker can always clear the protected bit; the only thing that
    // makes doing so useless is refusing the frame.
    let (local, sdata, _rec) = station("wlan-clear", true);
    let sink = f::Collector::new();
    *sdata.deliver.lock() = Some(sink.clone());

    let mut body = Vec::new();
    wireless::ieee80211::build::snap_header(&mut body, ETH_P_IP);
    body.extend_from_slice(&[0u8; 16]);
    let mut frame = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, false);
    frame.extend_from_slice(&body);

    let status = RxStatus { freq: 2412, now_ns: 10, ..Default::default() };
    crate::rx::rx(&local, &status, &frame);
    assert_eq!(sink.taken().len(), 0);
    assert_eq!(sdata.stats().rx_crypto_failed, 1);
    f::drop_radio(&local);
}

#[test]
fn the_same_frame_retried_is_delivered_once() {
    let (local, sdata, _rec) = station("wlan-dup", false);
    let sink = f::Collector::new();
    *sdata.deliver.lock() = Some(sink.clone());

    let mut body = Vec::new();
    wireless::ieee80211::build::snap_header(&mut body, ETH_P_IP);
    body.extend_from_slice(&[1u8; 8]);
    let base = f::with_seq(f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, false), 42, 0);
    let mut frame = base.clone();
    frame.extend_from_slice(&body);

    let status = RxStatus { freq: 2412, now_ns: 10, ..Default::default() };
    crate::rx::rx(&local, &status, &frame);
    assert_eq!(sink.taken().len(), 1);

    // The same frame with the retry bit set is the access point resending
    // because our acknowledgement was lost.
    let mut retry = frame.clone();
    let fc = u16::from_le_bytes([retry[0], retry[1]]) | fctl::FCTL_RETRY;
    retry[0..2].copy_from_slice(&fc.to_le_bytes());
    crate::rx::rx(&local, &status, &retry);
    assert_eq!(sink.taken().len(), 0, "a retransmission must not be delivered twice");
    assert_eq!(sdata.stats().rx_duplicate, 1);
    f::drop_radio(&local);
}

#[test]
fn a_frame_from_another_network_is_not_delivered() {
    let (local, sdata, _rec) = station("wlan-other", false);
    let sink = f::Collector::new();
    *sdata.deliver.lock() = Some(sink.clone());

    let mut body = Vec::new();
    wireless::ieee80211::build::snap_header(&mut body, ETH_P_IP);
    body.extend_from_slice(&[2u8; 8]);
    // Broadcast, from a network this interface did not join.
    let mut frame = f::data_hdr_from_ds(wireless::ieee80211::MacAddr::BROADCAST,
                                        f::OTHER, f::PEER, None, false);
    frame.extend_from_slice(&body);

    let status = RxStatus { freq: 2412, now_ns: 10, ..Default::default() };
    crate::rx::rx(&local, &status, &frame);
    assert_eq!(sink.taken().len(), 0);
    f::drop_radio(&local);
}

#[test]
fn a_frame_with_an_unknown_protocol_version_is_dropped_before_anything_is_read() {
    let (local, sdata, _rec) = station("wlan-vers", false);
    let sink = f::Collector::new();
    *sdata.deliver.lock() = Some(sink.clone());

    let mut frame = f::data_hdr_from_ds(f::STA, f::AP, f::PEER, None, false);
    frame[0] |= 0x01;
    frame.extend_from_slice(&[0u8; 16]);
    let status = RxStatus { freq: 2412, now_ns: 10, ..Default::default() };
    crate::rx::rx(&local, &status, &frame);
    assert_eq!(sink.taken().len(), 0);
    f::drop_radio(&local);
}
