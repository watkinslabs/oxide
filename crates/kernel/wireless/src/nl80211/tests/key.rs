// Key installation: which requests are refused and with what.

extern crate alloc;

use syscall::errno::Errno;

use crate::ieee80211::MacAddr;
use crate::nl80211::key_cmd;
use crate::nl80211::tests_support::{find, lock, radio_with, u8_of, Call, Req};
use crate::sme::ConnectParams;
use crate::uapi::attr as a;
use crate::uapi::ciphers::cipher;
use crate::uapi::enums::{key_type, IfType};
use crate::uapi::nested::key as k;
use crate::wdev::Wdev;

/// A connected client interface, since a client with no association has
/// nothing to install a key against. # C: O(1)
fn connect(d: &alloc::sync::Arc<Wdev>) {
    let peer = MacAddr([0x02, 0x99, 0, 0, 0, 1]);
    d.with(|w| w.conn.associated(peer, 1, alloc::vec::Vec::new(),
                                 alloc::vec::Vec::new(), true));
    let _ = ConnectParams::default();
}

/// A group key request in the modern nest encoding. # C: O(1)
fn group_key(d: &alloc::sync::Arc<Wdev>, idx: u8, suite: u32, len: usize) -> Req {
    let mut req = Req::wdev(d);
    let material = alloc::vec![0x5au8; len];
    req.nest(a::KEY, |out| {
        netlink::genetlink::attr::put(out, k::DATA, &material);
        netlink::genetlink::attr::put(out, k::IDX, &[idx]);
        netlink::genetlink::attr::put_u32(out, k::CIPHER, suite);
    });
    req
}

#[test]
fn a_group_key_the_radio_advertises_installs() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    connect(&d);
    assert!(group_key(&d, 1, cipher::CCMP, 16).call(key_cmd::new).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::AddKey { idx: 1, pairwise: false });
    assert!(d.with(|w| w.keys.get(1, false, None).is_some()));
}

#[test]
fn the_flat_legacy_encoding_installs_the_same_key() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    connect(&d);
    let mut req = Req::wdev(&d);
    req.bytes(a::KEY_DATA, &[0x11u8; 13]);
    req.u8(a::KEY_IDX, 2);
    req.u32(a::KEY_CIPHER, cipher::WEP104);
    assert!(req.call(key_cmd::new).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0], Call::AddKey { idx: 2, pairwise: false });
}

#[test]
fn a_cipher_the_radio_never_advertised_is_refused() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    connect(&d);
    assert!(group_key(&d, 1, cipher::GCMP_256, 32).call(key_cmd::new)
        .is_err(Errno::Einval));
    assert!(ops.calls.lock().unwrap().is_empty(),
            "a refused key must not reach the driver");
}

#[test]
fn a_key_of_the_wrong_length_for_its_cipher_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    assert!(group_key(&d, 1, cipher::CCMP, 32).call(key_cmd::new).is_err(Errno::Einval));
}

#[test]
fn a_pairwise_key_at_index_one_without_extended_key_id_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    let peer = MacAddr([0x02, 0x99, 0, 0, 0, 1]);
    let mut req = group_key(&d, 1, cipher::CCMP, 16);
    req.mac(a::MAC, peer);
    assert!(req.call(key_cmd::new).is_err(Errno::Einval));
    // The same key at index zero is accepted, so it is the index and not the
    // pairing that was refused.
    let mut ok = group_key(&d, 0, cipher::CCMP, 16);
    ok.mac(a::MAC, peer);
    assert!(ok.call(key_cmd::new).is_ack());
}

#[test]
fn a_management_cipher_offered_as_a_pairwise_key_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    let mut req = group_key(&d, 4, cipher::AES_CMAC, 16);
    req.mac(a::MAC, MacAddr([0x02, 0x99, 0, 0, 0, 1]));
    req.nest(a::KEY, |out| {
        netlink::genetlink::attr::put_u32(out, k::TYPE, key_type::PAIRWISE);
    });
    assert!(req.call(key_cmd::new).is_err(Errno::Einval));
}

#[test]
fn a_management_cipher_below_its_own_index_range_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    assert!(group_key(&d, 1, cipher::AES_CMAC, 16).call(key_cmd::new)
        .is_err(Errno::Einval));
}

#[test]
fn an_index_above_what_the_radio_admits_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    // The fixture radio advertises an integrity cipher but no beacon
    // protection, so index 6 does not exist on it.
    assert!(group_key(&d, 6, cipher::AES_CMAC, 16).call(key_cmd::new)
        .is_err(Errno::Einval));
}

#[test]
fn a_key_on_an_unassociated_client_reports_no_link() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    assert!(group_key(&d, 1, cipher::CCMP, 16).call(key_cmd::new).is_err(Errno::Enolink));
}

#[test]
fn a_bad_cipher_on_an_unassociated_client_is_still_a_bad_argument() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    // Both refusals apply. The arguments are checked before the interface's
    // state, so the caller is told what is wrong with the request.
    assert!(group_key(&d, 1, cipher::GCMP_256, 32).call(key_cmd::new)
        .is_err(Errno::Einval));
}

#[test]
fn a_request_with_no_key_material_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    let mut req = Req::wdev(&d);
    req.nest(a::KEY, |out| {
        netlink::genetlink::attr::put(out, k::IDX, &[1]);
        netlink::genetlink::attr::put_u32(out, k::CIPHER, cipher::CCMP);
    });
    assert!(req.call(key_cmd::new).is_err(Errno::Einval));
}

#[test]
fn two_default_flags_on_one_key_are_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    let mut req = Req::wdev(&d);
    req.nest(a::KEY, |out| {
        netlink::genetlink::attr::put(out, k::IDX, &[1]);
        netlink::genetlink::attr::put(out, k::DEFAULT, &[]);
        netlink::genetlink::attr::put(out, k::DEFAULT_MGMT, &[]);
    });
    assert!(req.call(key_cmd::set).is_err(Errno::Einval));
}

#[test]
fn a_management_default_outside_its_index_range_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    let mut req = Req::wdev(&d);
    req.nest(a::KEY, |out| {
        netlink::genetlink::attr::put(out, k::IDX, &[1]);
        netlink::genetlink::attr::put(out, k::DEFAULT_MGMT, &[]);
    });
    assert!(req.call(key_cmd::set).is_err(Errno::Einval));
}

#[test]
fn a_data_default_above_index_three_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    let mut req = Req::wdev(&d);
    req.nest(a::KEY, |out| {
        netlink::genetlink::attr::put(out, k::IDX, &[4]);
        netlink::genetlink::attr::put(out, k::DEFAULT, &[]);
    });
    assert!(req.call(key_cmd::set).is_err(Errno::Einval));
}

#[test]
fn selecting_a_default_reaches_the_driver_and_the_ring() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    connect(&d);
    assert!(group_key(&d, 2, cipher::CCMP, 16).call(key_cmd::new).is_ack());
    let mut req = Req::wdev(&d);
    req.nest(a::KEY, |out| {
        netlink::genetlink::attr::put(out, k::IDX, &[2]);
        netlink::genetlink::attr::put(out, k::DEFAULT, &[]);
    });
    assert!(req.call(key_cmd::set).is_ack());
    assert!(ops.calls.lock().unwrap()
        .contains(&Call::DefaultKey { idx: 2, uni: true, multi: true }));
    assert_eq!(d.with(|w| w.keys.default_key), Some(2));
}

#[test]
fn a_default_pointing_at_an_empty_slot_reports_no_entry() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    let mut req = Req::wdev(&d);
    req.nest(a::KEY, |out| {
        netlink::genetlink::attr::put(out, k::IDX, &[3]);
        netlink::genetlink::attr::put(out, k::DEFAULT, &[]);
    });
    assert!(req.call(key_cmd::set).is_err(Errno::Enoent));
}

#[test]
fn a_query_reports_the_cipher_and_index_and_never_the_material() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    assert!(group_key(&d, 1, cipher::CCMP, 16).call(key_cmd::new).is_ack());
    let mut req = Req::wdev(&d);
    req.u8(a::KEY_IDX, 1);
    let reply = req.call(key_cmd::get);
    let b = reply.body();
    assert_eq!(u8_of(b, a::KEY_IDX), Some(1));
    assert!(find(b, a::KEY_CIPHER).is_some());
    assert!(find(b, a::KEY_DATA).is_none(), "a query must never return key material");
    let nest = find(b, a::KEY).expect("key nest");
    assert_eq!(u8_of(nest, k::IDX), Some(1));
    assert!(find(nest, k::DATA).is_none());
}

#[test]
fn a_query_for_a_slot_with_no_key_reports_no_entry() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    let mut req = Req::wdev(&d);
    req.u8(a::KEY_IDX, 3);
    assert!(req.call(key_cmd::get).is_err(Errno::Enoent));
}

#[test]
fn removing_a_key_reaches_the_driver_and_clears_the_ring() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    connect(&d);
    assert!(group_key(&d, 1, cipher::CCMP, 16).call(key_cmd::new).is_ack());
    let mut req = Req::wdev(&d);
    req.u8(a::KEY_IDX, 1);
    assert!(req.call(key_cmd::del).is_ack());
    assert!(ops.calls.lock().unwrap().contains(&Call::DelKey { idx: 1, pairwise: false }));
    assert!(d.with(|w| w.keys.get(1, false, None).is_none()));
}

#[test]
fn removing_a_key_with_no_index_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    assert!(Req::wdev(&d).call(key_cmd::del).is_err(Errno::Einval));
}

#[test]
fn a_group_key_addressed_to_a_peer_has_no_such_entry() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    connect(&d);
    let mut req = Req::wdev(&d);
    req.u8(a::KEY_IDX, 1);
    req.mac(a::MAC, MacAddr([0x02, 0x99, 0, 0, 0, 1]));
    req.u32(a::KEY_TYPE, key_type::GROUP);
    assert!(req.call(key_cmd::del).is_err(Errno::Enoent));
}
