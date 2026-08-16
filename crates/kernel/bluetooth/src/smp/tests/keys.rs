//! The key store, key roles, and resolvable address handling.

use super::hex;
use crate::hci::conn::PeerId;
use crate::uapi::bt::{BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM, BdAddr};
use crate::uapi::smp::*;
use crate::smp::keys::*;

fn peer(n: u8, addr_type: u8) -> PeerId {
    PeerId::new(BdAddr([n, n, n, n, n, n]), addr_type)
}

fn ltk(p: PeerId, key_type: u8, seed: u8) -> Ltk {
    Ltk { peer: p, key_type, authenticated: true, val: [seed; SMP_KEY_LEN],
          enc_size: SMP_MAX_ENC_KEY_SIZE, ediv: 0, rand: 0 }
}

#[test]
fn a_key_type_names_the_role_it_serves() {
    assert_eq!(ltk_role(SMP_LTK), SMP_ROLE_INITIATOR);
    assert_eq!(ltk_role(SMP_STK), SMP_ROLE_RESPONDER);
    assert_eq!(ltk_role(SMP_LTK_RESPONDER), SMP_ROLE_RESPONDER);
    assert_eq!(role_of(true), SMP_ROLE_INITIATOR);
    assert_eq!(role_of(false), SMP_ROLE_RESPONDER);
}

#[test]
fn a_role_bound_key_is_not_usable_in_the_other_role() {
    let p = peer(1, BDADDR_LE_PUBLIC);
    assert!(ltk(p, SMP_LTK, 1).usable_in_role(SMP_ROLE_INITIATOR));
    assert!(!ltk(p, SMP_LTK, 1).usable_in_role(SMP_ROLE_RESPONDER));
    assert!(ltk(p, SMP_LTK_RESPONDER, 1).usable_in_role(SMP_ROLE_RESPONDER));
    assert!(!ltk(p, SMP_LTK_RESPONDER, 1).usable_in_role(SMP_ROLE_INITIATOR));
}

#[test]
fn a_secure_connections_key_serves_both_roles() {
    let p = peer(1, BDADDR_LE_PUBLIC);
    for t in [SMP_LTK_P256, SMP_LTK_P256_DEBUG] {
        assert!(ltk(p, t, 1).usable_in_role(SMP_ROLE_INITIATOR), "type {}", t);
        assert!(ltk(p, t, 1).usable_in_role(SMP_ROLE_RESPONDER), "type {}", t);
    }
}

#[test]
fn the_same_address_on_two_address_types_is_two_peers() {
    let mut s = KeyStore::new();
    let public = peer(9, BDADDR_LE_PUBLIC);
    let random = peer(9, BDADDR_LE_RANDOM);
    s.add_ltk(ltk(public, SMP_LTK, 0xaa));
    assert!(s.find_ltk(&public, SMP_ROLE_INITIATOR).is_some());
    assert!(s.find_ltk(&random, SMP_ROLE_INITIATOR).is_none());
    s.add_ltk(ltk(random, SMP_LTK, 0xbb));
    assert_eq!(s.ltks().len(), 2);
    assert_eq!(s.find_ltk(&random, SMP_ROLE_INITIATOR).unwrap().val, [0xbb; SMP_KEY_LEN]);
}

#[test]
fn re_pairing_replaces_rather_than_accumulates() {
    let mut s = KeyStore::new();
    let p = peer(3, BDADDR_LE_PUBLIC);
    s.add_ltk(ltk(p, SMP_LTK, 1));
    s.add_ltk(ltk(p, SMP_LTK, 2));
    assert_eq!(s.ltks().len(), 1);
    assert_eq!(s.find_ltk(&p, SMP_ROLE_INITIATOR).unwrap().val, [2; SMP_KEY_LEN]);
    // The other role is a separate slot.
    s.add_ltk(ltk(p, SMP_LTK_RESPONDER, 3));
    assert_eq!(s.ltks().len(), 2);
}

#[test]
fn both_roles_can_be_held_and_found_independently() {
    let mut s = KeyStore::new();
    let p = peer(4, BDADDR_LE_PUBLIC);
    s.add_ltk(ltk(p, SMP_LTK, 1));
    s.add_ltk(ltk(p, SMP_LTK_RESPONDER, 2));
    assert_eq!(s.find_ltk(&p, SMP_ROLE_INITIATOR).unwrap().key_type, SMP_LTK);
    assert_eq!(s.find_ltk(&p, SMP_ROLE_RESPONDER).unwrap().key_type, SMP_LTK_RESPONDER);
    assert!(s.have_ltk(&p));
}

#[test]
fn forgetting_a_peer_removes_every_kind_of_key() {
    let mut s = KeyStore::new();
    let p = peer(5, BDADDR_LE_PUBLIC);
    s.add_ltk(ltk(p, SMP_LTK, 1));
    s.add_irk(Irk { peer: p, val: [7; SMP_KEY_LEN] });
    s.add_csrk(Csrk { peer: p, val: [8; SMP_KEY_LEN], authenticated: true, counter: 3 });
    s.add_link_key(LinkKey { addr: p.addr, val: [9; SMP_KEY_LEN], key_type: SMP_LTK_P256 });
    assert!(s.find_irk(&p).is_some());
    assert!(s.find_csrk(&p).is_some());
    assert!(s.find_link_key(&p.addr).is_some());
    s.forget(&p);
    assert!(!s.have_ltk(&p));
    assert!(s.find_irk(&p).is_none());
    assert!(s.find_csrk(&p).is_none());
    assert!(s.find_link_key(&p.addr).is_none());
    assert_eq!(s.ltks().len() + s.irks().len() + s.csrks().len() + s.link_keys().len(), 0);
}

// The address the published hash vector produces: its low three bytes are the
// hash of its high three under the vector's resolving key.
const VECTOR_IRK: [u8; 16] = hex("9b7d390aa610103405adc857a33402ec");
const VECTOR_PRAND: [u8; 3] = hex("948170");
const VECTOR_HASH: [u8; 3] = hex("aafb0d");

#[test]
fn a_generated_address_resolves_under_its_own_key() {
    let rpa = generate_rpa(&VECTOR_IRK, &VECTOR_PRAND);
    assert_eq!(&rpa.as_bytes()[..3], &VECTOR_HASH);
    assert_eq!(&rpa.as_bytes()[3..], &VECTOR_PRAND);
    assert!(is_rpa(&rpa));
    assert!(irk_matches(&VECTOR_IRK, &rpa));
}

#[test]
fn generation_forces_the_resolvable_address_type_bits() {
    // Whatever the caller's randomness looks like, the top two bits are set to
    // the pattern that marks the address resolvable.
    for top in [0x00u8, 0x3f, 0x80, 0xc0, 0xff] {
        let rpa = generate_rpa(&VECTOR_IRK, &[0x11, 0x22, top]);
        assert!(is_rpa(&rpa), "top {:#x}", top);
        assert!(irk_matches(&VECTOR_IRK, &rpa), "top {:#x}", top);
    }
}

#[test]
fn a_different_key_does_not_match() {
    let rpa = generate_rpa(&VECTOR_IRK, &VECTOR_PRAND);
    let mut other = VECTOR_IRK;
    other[0] ^= 1;
    assert!(!irk_matches(&other, &rpa));
}

#[test]
fn resolution_finds_the_identity_behind_the_address() {
    let mut s = KeyStore::new();
    let p = peer(6, BDADDR_LE_PUBLIC);
    let q = peer(7, BDADDR_LE_PUBLIC);
    s.add_irk(Irk { peer: p, val: VECTOR_IRK });
    let mut other = VECTOR_IRK;
    other[15] ^= 0xff;
    s.add_irk(Irk { peer: q, val: other });

    let rpa = generate_rpa(&VECTOR_IRK, &VECTOR_PRAND);
    assert_eq!(s.resolve(&rpa), Some(p));
    let rpa_q = generate_rpa(&other, &VECTOR_PRAND);
    assert_eq!(s.resolve(&rpa_q), Some(q));
}

#[test]
fn a_non_resolvable_address_is_not_attempted() {
    let mut s = KeyStore::new();
    s.add_irk(Irk { peer: peer(6, BDADDR_LE_PUBLIC), val: VECTOR_IRK });
    // A public identity address has the marker bits clear.
    let plain = BdAddr([0xaa, 0xfb, 0x0d, 0x94, 0x81, 0x00]);
    assert!(!is_rpa(&plain));
    assert_eq!(s.resolve(&plain), None);
}

#[test]
fn an_unknown_address_resolves_to_nothing() {
    let s = KeyStore::new();
    assert_eq!(s.resolve(&generate_rpa(&VECTOR_IRK, &VECTOR_PRAND)), None);
}
