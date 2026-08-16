// Key installation: the validation ladder and the key ring.
//
// Every refusal here is a security property, and each has its OWN errno that
// userspace branches on. A wrong answer in this file installs a key for the
// wrong cipher or the wrong index, and traffic goes out protected by
// something other than what userspace believes.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::ieee80211::MacAddr;
use crate::keys::{self, key_mode, InstalledKey, KeyCaps, KeyParams, KeyRing,
                  FIRST_BIGTK_IDX, FIRST_IGTK_IDX, LAST_BIGTK_IDX, LAST_IGTK_IDX,
                  MAX_DATA_KEY_IDX};
use crate::uapi::ciphers::{self, cipher};
use crate::uapi::enums::IfType;

const PEER: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0xaa]);
const PEER2: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0xbb]);

/// Every suite this build knows, so a validation failure is never "the radio
/// does not advertise it" unless the test means that.
fn supported() -> Vec<u32> {
    alloc::vec![cipher::WEP40, cipher::WEP104, cipher::TKIP, cipher::CCMP,
                cipher::CCMP_256, cipher::GCMP, cipher::GCMP_256, cipher::AES_CMAC,
                cipher::BIP_CMAC_256, cipher::BIP_GMAC_128, cipher::BIP_GMAC_256]
}

fn params(suite: u32) -> KeyParams {
    KeyParams { cipher: suite, key: alloc::vec![0x11; ciphers::key_len(suite).unwrap_or(16)],
                seq: None, mode: key_mode::RX_TX, vlan_id: 0 }
}

fn caps() -> KeyCaps {
    KeyCaps { igtk: true, beacon_protection: true, ext_key_id: false, ibss_rsn: false }
}

fn check(caps: KeyCaps, p: &KeyParams, idx: u8, pairwise: bool, peer: Option<MacAddr>)
    -> Result<(), Errno>
{
    keys::validate(caps, &supported(), IfType::Station, p, idx, pairwise, peer)
}

#[test]
fn the_highest_usable_index_depends_on_what_the_radio_advertised() {
    let none = KeyCaps::default();
    assert_eq!(keys::max_key_idx(none, false), MAX_DATA_KEY_IDX);
    let igtk = KeyCaps { igtk: true, ..none };
    assert_eq!(keys::max_key_idx(igtk, false), LAST_IGTK_IDX);
    let bp = KeyCaps { igtk: true, beacon_protection: true, ..none };
    assert_eq!(keys::max_key_idx(bp, false), LAST_BIGTK_IDX);
    // A pairwise key never goes above the data indexes whatever the radio says.
    assert_eq!(keys::max_key_idx(bp, true), MAX_DATA_KEY_IDX);
    assert!(!keys::valid_key_idx(none, FIRST_IGTK_IDX, false));
    assert!(keys::valid_key_idx(igtk, FIRST_IGTK_IDX, false));
    assert!(!keys::valid_key_idx(igtk, FIRST_BIGTK_IDX, false));
    assert!(keys::valid_key_idx(bp, LAST_BIGTK_IDX, false));
    assert!(!keys::valid_key_idx(bp, 8, false));
}

#[test]
fn a_pairwise_key_needs_a_peer_and_a_group_key_normally_does_not_take_one() {
    assert_eq!(check(caps(), &params(cipher::CCMP), 0, true, None), Err(Errno::Einval));
    assert_eq!(check(caps(), &params(cipher::CCMP), 0, true, Some(PEER)), Ok(()));
    assert_eq!(check(caps(), &params(cipher::CCMP), 1, false, None), Ok(()));
    // A group key addressed to one peer only makes sense in a secured ad-hoc
    // network, where each peer has its own.
    assert_eq!(check(caps(), &params(cipher::CCMP), 1, false, Some(PEER)),
               Err(Errno::Einval));
    let ibss = KeyCaps { ibss_rsn: true, ..caps() };
    assert_eq!(check(ibss, &params(cipher::CCMP), 1, false, Some(PEER)), Ok(()));
}

#[test]
fn a_counter_mode_pairwise_key_is_index_zero_without_extended_key_id() {
    assert_eq!(check(caps(), &params(cipher::CCMP), 0, true, Some(PEER)), Ok(()));
    assert_eq!(check(caps(), &params(cipher::CCMP), 1, true, Some(PEER)), Err(Errno::Einval));
    let ext = KeyCaps { ext_key_id: true, ..caps() };
    assert_eq!(check(ext, &params(cipher::CCMP), 1, true, Some(PEER)), Ok(()));
    assert_eq!(check(ext, &params(cipher::CCMP), 2, true, Some(PEER)), Err(Errno::Einval));
    for suite in [cipher::CCMP_256, cipher::GCMP, cipher::GCMP_256] {
        assert_eq!(check(ext, &params(suite), 1, true, Some(PEER)), Ok(()), "{suite:#x}");
        assert_eq!(check(caps(), &params(suite), 1, true, Some(PEER)), Err(Errno::Einval));
    }
}

#[test]
fn the_temporal_key_cipher_has_no_extended_key_id_and_no_staged_install() {
    // Extended key id exists only for the counter-mode ciphers.
    let ext = KeyCaps { ext_key_id: true, ..caps() };
    assert_eq!(check(ext, &params(cipher::TKIP), 1, true, Some(PEER)), Err(Errno::Einval));
    assert_eq!(check(ext, &params(cipher::TKIP), 0, true, Some(PEER)), Ok(()));
    let staged = KeyParams { mode: key_mode::NO_TX, ..params(cipher::TKIP) };
    assert_eq!(check(caps(), &staged, 0, true, Some(PEER)), Err(Errno::Einval));
}

#[test]
fn a_receive_only_install_is_a_pairwise_idea_and_set_transmit_is_never_an_install() {
    let no_tx = KeyParams { mode: key_mode::NO_TX, ..params(cipher::CCMP) };
    assert_eq!(check(caps(), &no_tx, 0, true, Some(PEER)), Ok(()));
    assert_eq!(check(caps(), &no_tx, 1, false, None), Err(Errno::Einval));
    let set_tx = KeyParams { mode: key_mode::SET_TX, ..params(cipher::CCMP) };
    assert_eq!(check(caps(), &set_tx, 0, true, Some(PEER)), Err(Errno::Einval));
    assert_eq!(check(caps(), &set_tx, 1, false, None), Err(Errno::Einval));
    let bogus = KeyParams { mode: 99, ..params(cipher::CCMP) };
    assert_eq!(check(caps(), &bogus, 1, false, None), Err(Errno::Einval));
}

#[test]
fn an_integrity_group_cipher_can_never_be_a_pairwise_key() {
    // Offering one as a pairwise key would install a management-frame
    // integrity key where a data key belongs.
    for suite in [cipher::AES_CMAC, cipher::BIP_CMAC_256, cipher::BIP_GMAC_128,
                  cipher::BIP_GMAC_256] {
        assert!(ciphers::is_mgmt_cipher(suite));
        assert!(!ciphers::is_pairwise_capable(suite));
        assert_eq!(check(caps(), &params(suite), 0, true, Some(PEER)), Err(Errno::Einval),
                   "{suite:#x}");
        // And it may only occupy a management or beacon index.
        for idx in 0..FIRST_IGTK_IDX {
            assert_eq!(check(caps(), &params(suite), idx, false, None), Err(Errno::Einval),
                       "{suite:#x} at {idx}");
        }
        for idx in FIRST_IGTK_IDX..=LAST_BIGTK_IDX {
            assert_eq!(check(caps(), &params(suite), idx, false, None), Ok(()),
                       "{suite:#x} at {idx}");
        }
    }
}

#[test]
fn a_wired_equivalent_key_stays_in_the_data_indexes() {
    for suite in [cipher::WEP40, cipher::WEP104] {
        assert_eq!(check(caps(), &params(suite), MAX_DATA_KEY_IDX, false, None), Ok(()));
        assert_eq!(check(caps(), &params(suite), FIRST_IGTK_IDX, false, None),
                   Err(Errno::Einval));
    }
}

#[test]
fn every_cipher_takes_exactly_its_own_key_length() {
    let expected = [
        (cipher::WEP40, 5usize), (cipher::WEP104, 13), (cipher::TKIP, 32),
        (cipher::CCMP, 16), (cipher::CCMP_256, 32), (cipher::GCMP, 16),
        (cipher::GCMP_256, 32), (cipher::AES_CMAC, 16), (cipher::BIP_CMAC_256, 32),
        (cipher::BIP_GMAC_128, 16), (cipher::BIP_GMAC_256, 32),
    ];
    for (suite, len) in expected {
        assert_eq!(ciphers::key_len(suite), Some(len), "{suite:#x}");
        let idx = if ciphers::is_mgmt_cipher(suite) { FIRST_IGTK_IDX } else { 1 };
        let mut p = params(suite);
        assert_eq!(p.key.len(), len);
        assert_eq!(check(caps(), &p, idx, false, None), Ok(()), "{suite:#x}");
        p.key.push(0);
        assert_eq!(check(caps(), &p, idx, false, None), Err(Errno::Einval),
                   "{suite:#x} one byte long");
        p.key.truncate(len - 1);
        assert_eq!(check(caps(), &p, idx, false, None), Err(Errno::Einval),
                   "{suite:#x} one byte short");
    }
    assert_eq!(ciphers::key_len(0xdead_beef), None);
}

#[test]
fn a_replay_counter_is_six_bytes_and_the_wired_ciphers_have_none() {
    for suite in [cipher::TKIP, cipher::CCMP, cipher::CCMP_256, cipher::GCMP,
                  cipher::GCMP_256, cipher::AES_CMAC, cipher::BIP_CMAC_256,
                  cipher::BIP_GMAC_128, cipher::BIP_GMAC_256] {
        assert_eq!(ciphers::seq_len(suite), 6, "{suite:#x}");
        let idx = if ciphers::is_mgmt_cipher(suite) { FIRST_IGTK_IDX } else { 1 };
        let good = KeyParams { seq: Some(alloc::vec![0; 6]), ..params(suite) };
        assert_eq!(check(caps(), &good, idx, false, None), Ok(()), "{suite:#x}");
        let short = KeyParams { seq: Some(alloc::vec![0; 5]), ..params(suite) };
        assert_eq!(check(caps(), &short, idx, false, None), Err(Errno::Einval));
    }
    for suite in [cipher::WEP40, cipher::WEP104] {
        assert_eq!(ciphers::seq_len(suite), 0);
        let p = KeyParams { seq: Some(alloc::vec![0; 6]), ..params(suite) };
        assert_eq!(check(caps(), &p, 0, false, None), Err(Errno::Einval),
                   "{suite:#x} has no replay counter to install");
    }
}

#[test]
fn a_cipher_the_radio_never_advertised_is_refused() {
    // A driver that silently installed a cipher it does not implement would
    // leave traffic in the clear while userspace believed it protected.
    let advertised = alloc::vec![cipher::CCMP];
    let p = params(cipher::GCMP);
    assert_eq!(keys::validate(caps(), &advertised, IfType::Station, &p, 1, false, None),
               Err(Errno::Einval));
    let p = params(cipher::CCMP);
    assert_eq!(keys::validate(caps(), &advertised, IfType::Station, &p, 1, false, None),
               Ok(()));
}

#[test]
fn the_index_check_runs_before_the_cipher_check() {
    // Two refusals both apply; the order decides which errno userspace sees
    // and therefore whether it retries with a different index or a different
    // cipher.
    let none = KeyCaps::default();
    let p = params(cipher::AES_CMAC);
    // Index 4 is out of range for a radio with no integrity cipher, AND the
    // cipher is a management one. The index answer comes first.
    assert_eq!(keys::validate(none, &supported(), IfType::Station, &p, FIRST_IGTK_IDX,
                              false, None), Err(Errno::Einval));
}

#[test]
fn a_neighbour_awareness_data_interface_takes_only_two_ciphers() {
    for suite in [cipher::CCMP, cipher::GCMP_256] {
        let idx = 1;
        assert_eq!(keys::validate(caps(), &supported(), IfType::NanData, &params(suite),
                                  idx, false, None), Ok(()), "{suite:#x}");
    }
    for suite in [cipher::TKIP, cipher::GCMP, cipher::CCMP_256] {
        assert_eq!(keys::validate(caps(), &supported(), IfType::NanData, &params(suite),
                                  1, false, None), Err(Errno::Einval), "{suite:#x}");
    }
}

#[test]
fn an_interface_with_no_link_reports_that_rather_than_a_bad_argument() {
    // A client with no association has nothing to install a key against, and
    // the distinction tells a supplicant to associate rather than to fix its
    // arguments.
    assert_eq!(keys::key_allowed(IfType::Station, false, false), Err(Errno::Enolink));
    assert_eq!(keys::key_allowed(IfType::Station, true, false), Ok(()));
    assert_eq!(keys::key_allowed(IfType::P2pClient, false, false), Err(Errno::Enolink));
    assert_eq!(keys::key_allowed(IfType::Adhoc, false, false), Err(Errno::Enolink));
    // A beaconing interface always has somewhere to put a key.
    for ty in [IfType::Ap, IfType::ApVlan, IfType::P2pGo, IfType::MeshPoint] {
        assert_eq!(keys::key_allowed(ty, false, false), Ok(()), "{ty:?}");
    }
    // The neighbour-awareness types need the secure variant of the protocol.
    assert_eq!(keys::key_allowed(IfType::Nan, false, false), Err(Errno::Einval));
    assert_eq!(keys::key_allowed(IfType::Nan, false, true), Ok(()));
    // Types that carry no keys at all are a bad argument, not a missing link.
    for ty in [IfType::Monitor, IfType::P2pDevice, IfType::Wds, IfType::Ocb,
               IfType::Unspecified] {
        assert_eq!(keys::key_allowed(ty, true, true), Err(Errno::Einval), "{ty:?}");
    }
}

fn installed(suite: u32, idx: u8, pairwise: bool, peer: Option<MacAddr>) -> InstalledKey {
    InstalledKey { params: params(suite), idx, pairwise, peer }
}

#[test]
fn a_group_key_and_a_pairwise_key_at_the_same_index_are_different_keys() {
    let mut r = KeyRing::default();
    r.install(installed(cipher::CCMP, 0, false, None));
    r.install(installed(cipher::TKIP, 0, true, Some(PEER)));
    assert_eq!(r.get(0, false, None).unwrap().params.cipher, cipher::CCMP);
    assert_eq!(r.get(0, true, Some(PEER)).unwrap().params.cipher, cipher::TKIP);
    // And another peer's slot is empty.
    assert!(r.get(0, true, Some(PEER2)).is_none());
}

#[test]
fn removing_reports_whether_anything_was_there() {
    let mut r = KeyRing::default();
    assert!(!r.remove(0, false, None));
    r.install(installed(cipher::CCMP, 0, false, None));
    assert!(r.remove(0, false, None));
    assert!(!r.remove(0, false, None));
    assert!(r.get(0, false, None).is_none());

    r.install(installed(cipher::CCMP, 0, true, Some(PEER)));
    assert!(!r.remove(0, true, Some(PEER2)), "another peer's key is not this one");
    assert!(r.remove(0, true, Some(PEER)));
    assert!(!r.remove(0, true, None), "a pairwise removal with no peer names nothing");
}

#[test]
fn a_default_must_point_at_a_key_that_exists() {
    // A default pointing at nothing sends frames in the clear.
    let mut r = KeyRing::default();
    assert_eq!(r.set_default(1), Err(Errno::Enoent));
    r.install(installed(cipher::CCMP, 1, false, None));
    assert_eq!(r.set_default(1), Ok(()));
    assert_eq!(r.default_key, Some(1));
    assert_eq!(r.set_default(MAX_DATA_KEY_IDX + 1), Err(Errno::Einval));

    assert_eq!(r.set_default_mgmt(FIRST_IGTK_IDX), Err(Errno::Enoent));
    r.install(installed(cipher::AES_CMAC, FIRST_IGTK_IDX, false, None));
    assert_eq!(r.set_default_mgmt(FIRST_IGTK_IDX), Ok(()));
    assert_eq!(r.set_default_mgmt(0), Err(Errno::Einval));
    assert_eq!(r.set_default_mgmt(FIRST_BIGTK_IDX), Err(Errno::Einval));

    assert_eq!(r.set_default_beacon(FIRST_BIGTK_IDX), Err(Errno::Enoent));
    r.install(installed(cipher::BIP_GMAC_128, FIRST_BIGTK_IDX, false, None));
    assert_eq!(r.set_default_beacon(FIRST_BIGTK_IDX), Ok(()));
    assert_eq!(r.set_default_beacon(LAST_IGTK_IDX), Err(Errno::Einval));
}

#[test]
fn removing_a_key_clears_a_default_that_pointed_at_it() {
    let mut r = KeyRing::default();
    r.install(installed(cipher::CCMP, 2, false, None));
    r.set_default(2).unwrap();
    r.install(installed(cipher::AES_CMAC, FIRST_IGTK_IDX, false, None));
    r.set_default_mgmt(FIRST_IGTK_IDX).unwrap();
    r.remove(2, false, None);
    assert_eq!(r.default_key, None, "a default must never outlive its key");
    assert_eq!(r.default_mgmt_key, Some(FIRST_IGTK_IDX));
    r.remove(FIRST_IGTK_IDX, false, None);
    assert_eq!(r.default_mgmt_key, None);
}

#[test]
fn forgetting_a_peer_drops_only_that_peers_keys() {
    let mut r = KeyRing::default();
    r.install(installed(cipher::CCMP, 0, true, Some(PEER)));
    r.install(installed(cipher::CCMP, 0, true, Some(PEER2)));
    r.install(installed(cipher::CCMP, 1, false, None));
    assert_eq!(r.peers().len(), 2);
    r.forget_peer(PEER);
    assert_eq!(r.peers(), alloc::vec![PEER2]);
    assert!(r.get(0, true, Some(PEER)).is_none());
    assert!(r.get(0, true, Some(PEER2)).is_some());
    assert!(r.get(1, false, None).is_some());
}

#[test]
fn flushing_leaves_nothing_behind() {
    let mut r = KeyRing::default();
    r.install(installed(cipher::CCMP, 0, true, Some(PEER)));
    r.install(installed(cipher::CCMP, 1, false, None));
    r.set_default(1).unwrap();
    r.flush();
    assert!(r.peers().is_empty());
    assert!(r.get(1, false, None).is_none());
    assert_eq!(r.default_key, None);
    assert_eq!(r.default_mgmt_key, None);
    assert_eq!(r.default_beacon_key, None);
}

#[test]
fn an_index_past_the_ring_is_stored_nowhere_and_read_as_nothing() {
    let mut r = KeyRing::default();
    r.install(installed(cipher::CCMP, 99, false, None));
    assert!(r.get(99, false, None).is_none());
    assert!(!r.remove(99, false, None));
}
