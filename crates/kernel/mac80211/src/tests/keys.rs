// Key installation and selection.
//
// The selection rule decides which key protects a frame, and getting it wrong
// does not fail: the frame goes out encrypted under the wrong key and the
// peer either cannot read it or — worse, with the group key — every station
// on the network can.

use alloc::vec;
use alloc::vec::Vec;

use wireless::uapi::ciphers::cipher;

use crate::crypto::pn::Pn;
use crate::flags;
use crate::key::{Key, KeySet};
use crate::tests_fixture as f;

fn ccmp_key(idx: u8, pairwise: bool, peer: Option<wireless::ieee80211::MacAddr>) -> Key {
    Key::new(cipher::CCMP, vec![idx; 16], idx, pairwise, peer, None)
}

#[test]
fn a_pairwise_key_beats_the_group_key_for_a_unicast_frame() {
    let mut ks = KeySet::default();
    ks.install(ccmp_key(0, false, None));
    ks.install(Key::new(cipher::CCMP, vec![0xee; 16], 0, true, Some(f::PEER), None));
    let (key, _) = ks.tx_key(f::PEER).expect("a key applies");
    assert!(key.pairwise, "a peer with a pairwise key must not use the group key");
    assert_eq!(key.material, vec![0xee; 16]);
}

#[test]
fn a_group_frame_uses_the_group_key_even_when_a_pairwise_key_exists() {
    let mut ks = KeySet::default();
    ks.install(ccmp_key(1, false, None));
    ks.set_default(1);
    ks.install(Key::new(cipher::CCMP, vec![0xee; 16], 0, true, Some(f::PEER), None));
    let (key, idx) = ks.tx_key(wireless::ieee80211::MacAddr::BROADCAST).unwrap();
    assert!(!key.pairwise);
    assert_eq!(idx, 1);
}

#[test]
fn a_peer_with_no_pairwise_key_falls_back_to_the_group_key() {
    let mut ks = KeySet::default();
    ks.install(ccmp_key(2, false, None));
    ks.set_default(2);
    ks.install(Key::new(cipher::CCMP, vec![0xee; 16], 0, true, Some(f::PEER), None));
    let (key, idx) = ks.tx_key(f::OTHER).unwrap();
    assert!(!key.pairwise);
    assert_eq!(idx, 2);
}

#[test]
fn the_key_index_selects_the_key() {
    let mut ks = KeySet::default();
    for i in 0..4u8 { ks.install(ccmp_key(i, false, None)); }
    for i in 0..4u8 {
        assert_eq!(ks.get(i, false, None).unwrap().material, vec![i; 16], "index {i}");
    }
    for i in 0..4u8 {
        assert!(ks.set_default(i));
        assert_eq!(ks.tx_key(wireless::ieee80211::MacAddr::BROADCAST).unwrap().1, i);
    }
}

#[test]
fn a_key_installed_for_one_cipher_is_not_used_for_another() {
    let mut ks = KeySet::default();
    ks.install(Key::new(cipher::TKIP, vec![0x11; 32], 0, false, None, None));
    let (key, _) = ks.tx_key(wireless::ieee80211::MacAddr::BROADCAST).unwrap();
    assert_eq!(key.cipher, cipher::TKIP);
    // The overheads differ, so a caller that reserved room for the wrong
    // cipher would truncate the frame.
    assert_eq!(key.overhead(), crate::crypto::tkip::overhead());
    assert_ne!(key.overhead(), crate::crypto::gcmp::overhead());
    // And only the encryption half of the blob is the cipher's key.
    assert_eq!(key.encr_len(), crate::uapi::tkip_key::ENCR_LEN);
    assert_eq!(key.material.len(), crate::uapi::tkip_key::TOTAL_LEN);
}

#[test]
fn the_first_group_key_becomes_the_transmit_default() {
    // A network with a group key and no default sends its broadcast traffic
    // in the clear, which is not a degraded state anybody notices.
    let mut ks = KeySet::default();
    assert_eq!(ks.default_key, None);
    ks.install(ccmp_key(1, false, None));
    assert_eq!(ks.default_key, Some(1));
    // A later install does not steal the default.
    ks.install(ccmp_key(2, false, None));
    assert_eq!(ks.default_key, Some(1));
}

#[test]
fn a_default_pointing_at_nothing_is_refused() {
    let mut ks = KeySet::default();
    assert!(!ks.set_default(3), "a default index with no key sends frames in the clear");
    ks.install(ccmp_key(3, false, None));
    assert!(ks.set_default(3));
}

#[test]
fn removing_a_key_clears_a_default_that_pointed_at_it() {
    let mut ks = KeySet::default();
    ks.install(ccmp_key(0, false, None));
    assert_eq!(ks.default_key, Some(0));
    assert!(ks.remove(0, false, None));
    assert_eq!(ks.default_key, None);
    assert!(ks.tx_key(wireless::ieee80211::MacAddr::BROADCAST).is_none());
    assert!(!ks.remove(0, false, None), "removing twice reports nothing was there");
}

#[test]
fn a_receive_only_key_is_not_used_to_transmit() {
    // A key staged for a rekey encrypts frames the peer cannot yet read.
    let mut ks = KeySet::default();
    let mut key = ccmp_key(0, true, Some(f::PEER));
    key.flags |= flags::key::RX_ONLY;
    ks.install(key);
    assert!(ks.tx_key(f::PEER).is_none());
    assert!(ks.rx_key(f::PEER, true, 0).is_some(), "but it still decrypts");
}

#[test]
fn a_received_unicast_frame_uses_the_senders_pairwise_key() {
    let mut ks = KeySet::default();
    ks.install(ccmp_key(0, false, None));
    ks.install(Key::new(cipher::CCMP, vec![0x77; 16], 0, true, Some(f::PEER), None));
    let key = ks.rx_key(f::PEER, true, 0).unwrap();
    assert_eq!(key.material, vec![0x77; 16]);
    // A group frame from the same sender uses the group key at the index the
    // cipher header named.
    let key = ks.rx_key(f::PEER, false, 0).unwrap();
    assert!(!key.pairwise);
}

#[test]
fn forgetting_a_peer_drops_only_that_peers_keys() {
    let mut ks = KeySet::default();
    ks.install(ccmp_key(0, false, None));
    ks.install(Key::new(cipher::CCMP, vec![1; 16], 0, true, Some(f::PEER), None));
    ks.install(Key::new(cipher::CCMP, vec![2; 16], 0, true, Some(f::OTHER), None));
    ks.forget_peer(f::PEER);
    assert!(!ks.has_pairwise(f::PEER));
    assert!(ks.has_pairwise(f::OTHER));
    assert!(ks.get(0, false, None).is_some(), "the group key survives");
}

#[test]
fn a_flush_leaves_nothing_behind() {
    let mut ks = KeySet::default();
    ks.install(ccmp_key(0, false, None));
    ks.install(Key::new(cipher::CCMP, vec![1; 16], 0, true, Some(f::PEER), None));
    ks.flush();
    assert!(!ks.any());
    assert_eq!(ks.default_key, None);
}

#[test]
fn an_installed_sequence_counter_seeds_both_directions() {
    // The wire carries the counter least significant byte first.
    let seq = vec![0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
    let key = Key::new(cipher::CCMP, vec![0; 16], 0, false, None, Some(&seq));
    assert_eq!(key.tx_pn.peek(), Pn(5));
    assert!(!key.rx_pn.would_accept(Some(0), Pn(5)));
    assert!(key.rx_pn.would_accept(Some(0), Pn(6)));
}

#[test]
fn a_key_with_no_installed_counter_starts_from_nothing() {
    let key = Key::new(cipher::CCMP, vec![0; 16], 0, false, None, None);
    assert_eq!(key.tx_pn.peek(), Pn(0));
    assert!(key.rx_pn.would_accept(Some(0), Pn(0)));
}

#[test]
fn a_pairwise_install_with_no_peer_is_ignored() {
    let mut ks = KeySet::default();
    ks.install(Key::new(cipher::CCMP, vec![0; 16], 0, true, None, None));
    assert!(!ks.any());
}

#[test]
fn an_index_beyond_the_key_slots_is_ignored() {
    let mut ks = KeySet::default();
    ks.install(Key::new(cipher::CCMP, vec![0; 16], 99, false, None, None));
    assert!(!ks.any());
    assert!(ks.get(99, false, None).is_none());
}

#[test]
fn the_management_default_is_separate_from_the_data_default() {
    let mut ks = KeySet::default();
    ks.install(ccmp_key(0, false, None));
    ks.install(Key::new(cipher::AES_CMAC, vec![0; 16], 4, false, None, None));
    ks.default_mgmt_key = Some(4);
    assert_eq!(ks.default_key, Some(0));
    let (mgmt, idx) = ks.tx_mgmt_key().unwrap();
    assert_eq!(idx, 4);
    assert_eq!(mgmt.cipher, cipher::AES_CMAC);
    assert_eq!(ks.tx_key(f::PEER).unwrap().1, 0);
}

#[test]
fn peers_holding_keys_are_reported() {
    let mut ks = KeySet::default();
    assert!(!ks.has_pairwise(f::PEER));
    ks.install(Key::new(cipher::CCMP, vec![0; 16], 0, true, Some(f::PEER), None));
    assert!(ks.has_pairwise(f::PEER));
    let _: Vec<u8> = Vec::new();
}
