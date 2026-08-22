// Capability advertisements and the command gates they open.

extern crate alloc;

use crate::ieee80211::{fctl, MacAddr};
use crate::nl80211::{connect_cmd, iface_cmd, key_cmd, mgmt_cmd, scan_cmd, wiphy_cmd};
use crate::nl80211::tests_support::{caps, find, has, lock, radio_from_caps,
                                    radio_with_caps, Call, Req};
use crate::sme::ConnectParams;
use crate::uapi::attr as a;
use crate::uapi::ciphers::cipher;
use crate::uapi::cmd;
use crate::uapi::enums::{auth_type, ext_feature, feature_flags, key_type, scan_flags,
                         IfType};
use crate::uapi::nested::key as k;
use crate::wiphy::flags as wf;

const PEER: MacAddr = MacAddr([0x02, 0x99, 0, 0, 0, 1]);

#[test]
fn extended_feature_indexes_match_the_wire_bitmap() {
    assert_eq!([wf::FOUR_ADDR_AP, wf::FOUR_ADDR_STATION, wf::IBSS_RSN, wf::OFFCHAN_TX],
               [1 << 5, 1 << 6, 1 << 8, 1 << 20]);
    assert_eq!([
        ext_feature::FILS_STA, ext_feature::FILS_SK_OFFLOAD,
        ext_feature::LOW_SPAN_SCAN, ext_feature::LOW_POWER_SCAN,
        ext_feature::HIGH_ACCURACY_SCAN, ext_feature::SCAN_RANDOM_SN,
        ext_feature::EXT_KEY_ID, ext_feature::SAE_OFFLOAD,
        ext_feature::BEACON_PROTECTION, ext_feature::CONTROL_PORT_NO_PREAUTH,
        ext_feature::BEACON_PROTECTION_CLIENT, ext_feature::SCAN_FREQ_KHZ,
        ext_feature::CONTROL_PORT_OVER_NL80211_TX_STATUS,
        ext_feature::SAE_OFFLOAD_AP, ext_feature::EPPKE,
        ext_feature::IEEE8021X_AUTH,
    ], [9, 14, 22, 23, 24, 29, 36, 38, 41, 42, 46, 47, 48, 51, 70, 72]);
}

#[test]
fn get_wiphy_publishes_the_flag_backed_capabilities() {
    let _g = lock();
    let mut c = caps();
    c.flags |= wf::IBSS_RSN | wf::OFFCHAN_TX;
    let (w, _ops) = radio_from_caps(c);
    let reply = Req::wiphy(&w).call(wiphy_cmd::get);
    assert!(has(reply.body(), a::SUPPORT_IBSS_RSN));
    assert!(has(reply.body(), a::OFFCHANNEL_TX_OK));
    assert_eq!(find(reply.body(), a::SUPPORT_IBSS_RSN), Some(&[][..]));
}

#[test]
fn each_four_address_mode_needs_its_own_radio_flag() {
    let _g = lock();
    let mut c = caps();
    c.flags &= !(wf::FOUR_ADDR_AP | wf::FOUR_ADDR_STATION);
    let (w, _ops) = radio_from_caps(c.clone());
    let mut no = Req::wiphy(&w);
    no.text(a::IFNAME, "wlan4");
    no.u32(a::IFTYPE, IfType::Station.as_u32());
    no.u8(a::_4ADDR, 1);
    assert!(no.call(iface_cmd::new).is_err(syscall::errno::Errno::Eopnotsupp));

    c.flags |= wf::FOUR_ADDR_STATION;
    let (w, _ops) = radio_from_caps(c.clone());
    let mut station = Req::wiphy(&w);
    station.text(a::IFNAME, "wlan4");
    station.u32(a::IFTYPE, IfType::Station.as_u32());
    station.u8(a::_4ADDR, 1);
    assert_eq!(station.call(iface_cmd::new).cmd(), Some(cmd::NEW_INTERFACE));
    assert!(w.wdevs()[0].with(|d| d.use_4addr));

    c.add_iftype(IfType::ApVlan);
    c.flags |= wf::FOUR_ADDR_AP;
    let (w, _ops) = radio_from_caps(c);
    let mut ap = Req::wiphy(&w);
    ap.text(a::IFNAME, "vlan4");
    ap.u32(a::IFTYPE, IfType::ApVlan.as_u32());
    ap.u8(a::_4ADDR, 1);
    assert_eq!(ap.call(iface_cmd::new).cmd(), Some(cmd::NEW_INTERFACE));
}

#[test]
fn an_ibss_rsn_radio_accepts_a_peer_addressed_group_key() {
    let _g = lock();
    let mut c = caps();
    c.add_iftype(IfType::Adhoc);
    c.flags |= wf::IBSS_RSN;
    let (_w, ops, d) = radio_with_caps(c, IfType::Adhoc);
    d.with(|v| v.conn.associated(PEER, 1, alloc::vec::Vec::new(),
                                 alloc::vec::Vec::new(), true));
    let _ = ConnectParams::default();
    let material = [0x5au8; 16];
    let mut req = Req::wdev(&d);
    req.mac(a::MAC, PEER);
    req.nest(a::KEY, |out| {
        netlink::genetlink::attr::put(out, k::DATA, &material);
        netlink::genetlink::attr::put(out, k::IDX, &[1]);
        netlink::genetlink::attr::put_u32(out, k::CIPHER, cipher::CCMP);
        netlink::genetlink::attr::put_u32(out, k::TYPE, key_type::GROUP);
    });
    let reply = req.call(key_cmd::new);
    assert!(reply.is_ack(), "errno {:?}", reply.errno());
    assert!(ops.calls.lock().unwrap().contains(&Call::AddKey { idx: 1, pairwise: false }));
}

#[test]
fn authentication_features_open_only_the_matching_command_modes() {
    let mut c = caps();
    c.features &= !feature_flags::SAE;
    for bit in [ext_feature::FILS_STA, ext_feature::FILS_SK_OFFLOAD,
                ext_feature::SAE_OFFLOAD, ext_feature::SAE_OFFLOAD_AP,
                ext_feature::EPPKE, ext_feature::IEEE8021X_AUTH] {
        c.add_ext_feature(bit);
    }
    let w = alloc::sync::Arc::new(crate::wiphy::Wiphy::new(
        MacAddr([2, 0, 0, 0, 0, 1]), c,
        alloc::sync::Arc::new(crate::nl80211::tests_support::FakeOps::default())));
    assert!(connect_cmd::parse::valid_auth_type(&w, auth_type::FILS_SK,
                                                cmd::AUTHENTICATE));
    assert!(connect_cmd::parse::valid_auth_type(&w, auth_type::FILS_SK, cmd::CONNECT));
    assert!(!connect_cmd::parse::valid_auth_type(&w, auth_type::FILS_PK, cmd::CONNECT));
    assert!(connect_cmd::parse::valid_auth_type(&w, auth_type::SAE, cmd::CONNECT));
    assert!(connect_cmd::parse::valid_auth_type(&w, auth_type::SAE, cmd::START_AP));
    assert!(connect_cmd::parse::valid_auth_type(&w, auth_type::EPPKE,
                                                cmd::AUTHENTICATE));
    assert!(connect_cmd::parse::valid_auth_type(&w, auth_type::IEEE8021X,
                                                cmd::AUTHENTICATE));
}

#[test]
fn scan_features_open_the_matching_flags_and_khz_frequency_list() {
    let _g = lock();
    for (flag, feature) in [
        (scan_flags::LOW_SPAN, ext_feature::LOW_SPAN_SCAN),
        (scan_flags::LOW_POWER, ext_feature::LOW_POWER_SCAN),
        (scan_flags::HIGH_ACCURACY, ext_feature::HIGH_ACCURACY_SCAN),
        (scan_flags::RANDOM_SN, ext_feature::SCAN_RANDOM_SN),
    ] {
        let mut c = caps();
        c.add_ext_feature(feature);
        let (_w, ops, d) = radio_with_caps(c, IfType::Station);
        let mut req = Req::wdev(&d);
        req.u32(a::SCAN_FLAGS, flag);
        assert!(req.call(scan_cmd::trigger).is_ack());
        assert!(matches!(ops.calls.lock().unwrap()[0],
                         Call::Scan { flags, .. } if flags == flag));
    }

    // These two flags are request/reporting selections, not capability
    // gates. They remain valid without an extended-feature bit.
    let (_w, ops, d) = radio_with_caps(caps(), IfType::Station);
    let mut req = Req::wdev(&d);
    req.u32(a::SCAN_FLAGS, scan_flags::FREQ_KHZ | scan_flags::COLOCATED_6GHZ);
    assert!(req.call(scan_cmd::trigger).is_ack());
    assert!(matches!(ops.calls.lock().unwrap()[0], Call::Scan { flags, .. }
        if flags == (scan_flags::FREQ_KHZ | scan_flags::COLOCATED_6GHZ)));

    let mut c = caps();
    c.ext_features.retain(|&bit| bit != ext_feature::SCAN_FREQ_KHZ);
    let (_w, _ops, d) = radio_with_caps(c.clone(), IfType::Station);
    let mut req = Req::wdev(&d);
    req.nest(a::SCAN_FREQ_KHZ, |out| {
        netlink::genetlink::attr::put_u32(out, 0, 2_412_000);
    });
    assert!(req.call(scan_cmd::trigger).is_err(syscall::errno::Errno::Eopnotsupp));

    c.add_ext_feature(ext_feature::SCAN_FREQ_KHZ);
    let (_w, ops, d) = radio_with_caps(c, IfType::Station);
    let mut req = Req::wdev(&d);
    req.nest(a::SCAN_FREQ_KHZ, |out| {
        netlink::genetlink::attr::put_u32(out, 0, 2_412_000);
    });
    assert!(req.call(scan_cmd::trigger).is_ack());
    assert!(matches!(&ops.calls.lock().unwrap()[0],
                     Call::Scan { freqs, .. } if freqs == &alloc::vec![2412]));
}

#[test]
fn off_channel_transmission_is_rejected_without_and_accepted_with_the_flag() {
    let _g = lock();
    let mut c = caps();
    c.flags &= !wf::OFFCHAN_TX;
    let (_w, _ops, d) = radio_with_caps(c.clone(), IfType::Station);
    let frame = crate::nl80211::tests_support::mgmt_frame(
        fctl::mgmt_stype::ACTION, d.addr(), PEER, &[4, 10]);
    let mut req = Req::wdev(&d);
    req.bytes(a::FRAME, &frame);
    req.flag(a::OFFCHANNEL_TX_OK);
    req.u32(a::WIPHY_FREQ, 2437);
    assert!(req.call(mgmt_cmd::tx).is_err(syscall::errno::Errno::Einval));

    c.flags |= wf::OFFCHAN_TX;
    let (_w, ops, d) = radio_with_caps(c, IfType::Station);
    let frame = crate::nl80211::tests_support::mgmt_frame(
        fctl::mgmt_stype::ACTION, d.addr(), PEER, &[4, 10]);
    let mut req = Req::wdev(&d);
    req.bytes(a::FRAME, &frame);
    req.flag(a::OFFCHANNEL_TX_OK);
    req.u32(a::WIPHY_FREQ, 2437);
    assert!(req.call(mgmt_cmd::tx).cmd().is_some());
    assert!(matches!(ops.calls.lock().unwrap()[0], Call::MgmtTx { offchan: true, .. }));
}
