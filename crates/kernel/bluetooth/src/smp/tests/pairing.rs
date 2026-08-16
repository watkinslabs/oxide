//! Two sessions driven against each other, which is the only check that the
//! two halves of every ordering decision agree.
//!
//! A pairing that derives different keys on the two sides still looks like a
//! success from inside either one; only running both catches it.

extern crate alloc;
use alloc::vec::Vec;

use super::hex;
use crate::hci::conn::PeerId;
use crate::uapi::bt::{BDADDR_LE_PUBLIC, BT_SECURITY_FIPS, BT_SECURITY_HIGH, BT_SECURITY_LOW,
                      BT_SECURITY_MEDIUM, BdAddr};
use crate::uapi::smp::*;
use crate::smp::chan::{self, Step, start_pairing};
use crate::smp::keys::{KeyStore, Ltk};
use crate::smp::pdu::{Pdu, SMP_PDU_MAX};
use crate::smp::sc::DEBUG_PRIVATE_KEY;
use crate::smp::session::{Entropy, LinkAddrs, Smp, SmpConfig, SmpEvent};

const INIT_ADDR: BdAddr = BdAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
const RESP_ADDR: BdAddr = BdAddr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);

/// Two usable private keys distinct from the published debug one, so neither
/// the reflection check nor the debug-key marking fires in a normal pairing.
const A_PRIVATE_KEY: [u8; 32] =
    hex("82b8eac0e103535092da1920c386e08ba33a84436e1b62f6832dcfe5eb21d124");
const B_PRIVATE_KEY: [u8; 32] =
    hex("53ee6b4746ab83b2e09bbf068f5d6888e20cb3ac6411012a01ae785d9c9cef17");

fn addrs() -> LinkAddrs {
    LinkAddrs {
        init_addr: INIT_ADDR, init_addr_type: BDADDR_LE_PUBLIC,
        resp_addr: RESP_ADDR, resp_addr_type: BDADDR_LE_PUBLIC,
    }
}

struct Node {
    smp: Smp,
    keys: KeyStore,
    level: u8,
    tag: u8,
    ctr: u8,
    /// Passkey a display method showed the user.
    displayed: Option<u32>,
    encrypted_with: Option<[u8; SMP_KEY_LEN]>,
    stored: Vec<Ltk>,
    failure: Option<u8>,
}

impl Node {
    fn new(cfg: SmpConfig, tag: u8, peer_addr: BdAddr) -> Node {
        let peer = PeerId::new(peer_addr, BDADDR_LE_PUBLIC);
        Node {
            smp: Smp::new(cfg, peer, addrs(), 0),
            keys: KeyStore::new(), level: BT_SECURITY_LOW, tag, ctr: 0,
            displayed: None, encrypted_with: None, stored: Vec::new(),
            failure: None,
        }
    }

    fn entropy(&mut self, passkey: u32) -> Entropy {
        self.ctr = self.ctr.wrapping_add(1);
        let mut nonce = [0u8; SMP_RAND_LEN];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = self.tag.wrapping_mul(0x11).wrapping_add(self.ctr).wrapping_add(i as u8);
        }
        let mut ltk = [0u8; SMP_KEY_LEN];
        for (i, b) in ltk.iter_mut().enumerate() { *b = self.tag ^ (i as u8) ^ self.ctr; }
        Entropy { nonce, passkey, ltk, ediv: self.tag as u16, rand: self.tag as u64 }
    }
}

/// Drive both sides until neither has anything to send. `passkey` is the value
/// a display method shows and an entry method types.
fn run(a: &mut Node, b: &mut Node, first: Vec<SmpEvent>, passkey: u32) {
    let mut pending: Vec<(bool, Vec<SmpEvent>)> = alloc::vec![(true, first)];
    let mut guard = 0;
    while let Some((from_a, events)) = pending.pop() {
        guard += 1;
        assert!(guard < 400, "pairing did not settle");
        let mut more: Vec<(bool, Vec<SmpEvent>)> = Vec::new();
        for ev in events {
            let (me, peer) = if from_a { (&mut *a, &mut *b) } else { (&mut *b, &mut *a) };
            match ev {
                SmpEvent::Send(pdu) => {
                    let mut buf = [0u8; SMP_PDU_MAX + 1];
                    let n = pdu.encode(&mut buf).expect("encodes");
                    let ent = peer.entropy(passkey);
                    let step = Step {
                        now_ms: 1, current_level: peer.level, stk_encrypted: false,
                        have_ltk: false, ent: &ent,
                    };
                    let mut out = Vec::new();
                    match chan::receive(&mut peer.smp, &buf[..n], &step, &mut out) {
                        Ok(_) => {}
                        Err(reason) => { peer.failure = Some(reason); out.clear(); }
                    }
                    more.push((!from_a, out));
                }
                SmpEvent::UserConfirm { .. } => {
                    let mut out = Vec::new();
                    chan::user_confirm(&mut me.smp, true, &mut out).unwrap();
                    more.push((from_a, out));
                }
                SmpEvent::UserPasskeyRequest => {
                    let ent = me.entropy(passkey);
                    let mut out = Vec::new();
                    chan::user_passkey(&mut me.smp, passkey, &ent, &mut out).unwrap();
                    more.push((from_a, out));
                }
                SmpEvent::UserPasskeyNotify(p) => { me.displayed = Some(p); }
                SmpEvent::StartEncryption { ltk, .. } => {
                    me.encrypted_with = Some(ltk);
                    me.level = me.smp.pending_sec_level;
                }
                SmpEvent::StoreLtk(k) => { me.stored.push(k); me.keys.add_ltk(k); }
                SmpEvent::StoreIrk(k) => me.keys.add_irk(k),
                SmpEvent::StoreCsrk(k) => me.keys.add_csrk(k),
                SmpEvent::StoreLinkKey(k) => me.keys.add_link_key(k),
                SmpEvent::SendIdentAddr => {}
                SmpEvent::Complete => {}
                SmpEvent::Fail(r) => { me.failure = Some(r); }
            }
        }
        while let Some(x) = more.pop() { pending.push(x); }
    }
}

fn legacy_cfg(io: u8) -> SmpConfig {
    SmpConfig { io_capability: io, sc_enabled: false, cross_transport: false,
                ..SmpConfig::default() }
}

fn sc_cfg(io: u8) -> SmpConfig {
    SmpConfig { io_capability: io, sc_enabled: true, cross_transport: false,
                ..SmpConfig::default() }
}

fn pair_legacy(io_a: u8, io_b: u8, level: u8) -> (Node, Node) {
    let mut a = Node::new(legacy_cfg(io_a), 1, RESP_ADDR);
    let mut b = Node::new(legacy_cfg(io_b), 2, INIT_ADDR);
    let ent = a.entropy(123456);
    let mut out = Vec::new();
    start_pairing(&mut a.smp, level, &ent, &mut out);
    run(&mut a, &mut b, out, 123456);
    (a, b)
}

fn pair_sc(io_a: u8, io_b: u8, level: u8, passkey: u32) -> (Node, Node) {
    let mut a = Node::new(sc_cfg(io_a), 1, RESP_ADDR);
    let mut b = Node::new(sc_cfg(io_b), 2, INIT_ADDR);
    assert!(a.smp.set_keypair(&A_PRIVATE_KEY));
    assert!(b.smp.set_keypair(&B_PRIVATE_KEY));
    let ent = a.entropy(passkey);
    let mut out = Vec::new();
    start_pairing(&mut a.smp, level, &ent, &mut out);
    run(&mut a, &mut b, out, passkey);
    (a, b)
}

#[test]
fn the_test_private_keys_are_usable_and_distinct() {
    let mut s = Smp::new(sc_cfg(SMP_IO_NO_INPUT_OUTPUT), PeerId::new(RESP_ADDR, BDADDR_LE_PUBLIC),
                         addrs(), 0);
    assert!(s.set_keypair(&A_PRIVATE_KEY));
    let a = s.local_pk;
    assert!(s.set_keypair(&B_PRIVATE_KEY));
    let b = s.local_pk;
    assert!(s.set_keypair(&DEBUG_PRIVATE_KEY));
    assert_ne!(a, b);
    assert_ne!(a, s.local_pk);
    assert_ne!(b, s.local_pk);
    assert_eq!(s.local_pk, crate::smp::sc::DEBUG_PUBLIC_KEY);
}

#[test]
fn a_pairing_against_the_published_debug_key_is_marked_as_such() {
    let mut a = Node::new(sc_cfg(SMP_IO_NO_INPUT_OUTPUT), 1, RESP_ADDR);
    let mut b = Node::new(sc_cfg(SMP_IO_NO_INPUT_OUTPUT), 2, INIT_ADDR);
    assert!(a.smp.set_keypair(&DEBUG_PRIVATE_KEY));
    assert!(b.smp.set_keypair(&B_PRIVATE_KEY));
    let ent = a.entropy(0);
    let mut out = Vec::new();
    start_pairing(&mut a.smp, BT_SECURITY_MEDIUM, &ent, &mut out);
    run(&mut a, &mut b, out, 0);
    assert!(b.smp.debug_key);
    let stored = b.stored.iter().find(|k| k.key_type == SMP_LTK_P256_DEBUG)
        .expect("responder stored a debug key");
    assert_eq!(stored.val, a.smp.tk);
}

#[test]
fn legacy_without_interaction_agrees_on_a_key() {
    let (a, b) = pair_legacy(SMP_IO_NO_INPUT_OUTPUT, SMP_IO_NO_INPUT_OUTPUT, BT_SECURITY_MEDIUM);
    assert_eq!(a.failure, None);
    assert_eq!(b.failure, None);
    let stk = a.encrypted_with.expect("initiator started encryption");
    let stored = b.stored.iter().find(|k| k.key_type == SMP_STK).expect("responder stored");
    assert_eq!(stored.val, stk);
    assert!(!stored.authenticated);
}

#[test]
fn legacy_with_a_passkey_agrees_on_a_key_and_authenticates_it() {
    let (a, b) = pair_legacy(SMP_IO_KEYBOARD_ONLY, SMP_IO_DISPLAY_ONLY, BT_SECURITY_HIGH);
    assert_eq!(a.failure, None);
    assert_eq!(b.failure, None);
    let stk = a.encrypted_with.expect("initiator started encryption");
    let stored = b.stored.iter().find(|k| k.key_type == SMP_STK).expect("responder stored");
    assert_eq!(stored.val, stk);
    assert!(stored.authenticated);
    assert_eq!(a.smp.pending_sec_level, BT_SECURITY_HIGH);
}

#[test]
fn legacy_key_depends_on_the_passkey() {
    // The same exchange with a different passkey must not produce the same key,
    // which is what makes the passkey worth typing.
    let (a1, _) = pair_legacy(SMP_IO_KEYBOARD_ONLY, SMP_IO_DISPLAY_ONLY, BT_SECURITY_HIGH);
    let mut a = Node::new(legacy_cfg(SMP_IO_KEYBOARD_ONLY), 1, RESP_ADDR);
    let mut b = Node::new(legacy_cfg(SMP_IO_DISPLAY_ONLY), 2, INIT_ADDR);
    let ent = a.entropy(654321);
    let mut out = Vec::new();
    start_pairing(&mut a.smp, BT_SECURITY_HIGH, &ent, &mut out);
    run(&mut a, &mut b, out, 654321);
    assert_ne!(a1.encrypted_with, a.encrypted_with);
}

#[test]
fn secure_connections_without_interaction_agrees_on_a_key() {
    let (a, b) = pair_sc(SMP_IO_NO_INPUT_OUTPUT, SMP_IO_NO_INPUT_OUTPUT, BT_SECURITY_MEDIUM, 0);
    assert_eq!(a.failure, None);
    assert_eq!(b.failure, None);
    assert_eq!(a.smp.dhkey, b.smp.dhkey);
    assert_eq!(a.smp.mackey, b.smp.mackey);
    assert_eq!(a.smp.tk, b.smp.tk);
    let key = a.encrypted_with.expect("initiator started encryption");
    assert_eq!(key, b.smp.tk);
    let stored = b.stored.iter().find(|k| k.key_type == SMP_LTK_P256).expect("responder stored");
    assert!(!stored.authenticated);
}

#[test]
fn secure_connections_numeric_comparison_shows_the_same_number_on_both_sides() {
    let (a, b) = pair_sc(SMP_IO_DISPLAY_YESNO, SMP_IO_DISPLAY_YESNO, BT_SECURITY_FIPS, 0);
    assert_eq!(a.failure, None);
    assert_eq!(b.failure, None);
    assert_eq!(a.smp.tk, b.smp.tk);
    assert_eq!(crate::smp::sc::numeric_value(&a.smp), crate::smp::sc::numeric_value(&b.smp));
    assert_eq!(a.smp.pending_sec_level, BT_SECURITY_FIPS);
    let stored = b.stored.iter().find(|k| k.key_type == SMP_LTK_P256).expect("responder stored");
    assert!(stored.authenticated);
}

#[test]
fn secure_connections_passkey_runs_every_round_and_agrees() {
    let (a, b) = pair_sc(SMP_IO_KEYBOARD_ONLY, SMP_IO_DISPLAY_ONLY, BT_SECURITY_FIPS, 246813);
    assert_eq!(a.failure, None);
    assert_eq!(b.failure, None);
    assert_eq!(b.displayed, Some(246813));
    assert_eq!(a.smp.passkey_round, SMP_PASSKEY_ROUNDS);
    assert_eq!(b.smp.passkey_round, SMP_PASSKEY_ROUNDS);
    assert_eq!(a.smp.tk, b.smp.tk);
    assert_eq!(a.smp.pending_sec_level, BT_SECURITY_FIPS);
    assert_eq!(a.encrypted_with, Some(a.smp.tk));
}

#[test]
fn a_tampered_confirm_is_refused() {
    let mut a = Node::new(legacy_cfg(SMP_IO_NO_INPUT_OUTPUT), 1, RESP_ADDR);
    let mut b = Node::new(legacy_cfg(SMP_IO_NO_INPUT_OUTPUT), 2, INIT_ADDR);
    let ent = a.entropy(0);
    let mut out = Vec::new();
    start_pairing(&mut a.smp, BT_SECURITY_MEDIUM, &ent, &mut out);
    run(&mut a, &mut b, out, 0);
    // Replay the responder's nonce against a corrupted stored confirm.
    a.smp.pcnf[0] ^= 0xff;
    let mut out2 = Vec::new();
    let rrnd = a.smp.rrnd;
    assert_eq!(crate::smp::legacy::on_random(&mut a.smp, rrnd, &mut out2),
               Err(SMP_CONFIRM_FAILED));
}

#[test]
fn a_peer_key_off_the_curve_is_refused_before_the_secret_is_computed() {
    let mut a = Node::new(sc_cfg(SMP_IO_NO_INPUT_OUTPUT), 1, RESP_ADDR);
    assert!(a.smp.set_keypair(&DEBUG_PRIVATE_KEY));
    a.smp.initiator = true;
    a.smp.sc = true;
    let sk = a.smp.local_sk.unwrap();
    let ent = a.entropy(0);
    let mut out = Vec::new();
    // A key whose y is copied from its x is not a curve point.
    let mut bad = [0u8; SMP_PUBLIC_KEY_LEN];
    bad[..SMP_PUBKEY_COORD_LEN].copy_from_slice(&a.smp.local_pk[..SMP_PUBKEY_COORD_LEN]);
    bad[SMP_PUBKEY_COORD_LEN..].copy_from_slice(&a.smp.local_pk[..SMP_PUBKEY_COORD_LEN]);
    assert_eq!(crate::smp::sc::on_public_key(&mut a.smp, &bad, &sk, &ent, &mut out),
               Err(SMP_DHKEY_CHECK_FAILED));
    assert_eq!(a.smp.dhkey, [0u8; SMP_DHKEY_LEN]);
}

#[test]
fn a_peer_echoing_our_own_key_is_refused() {
    let mut a = Node::new(sc_cfg(SMP_IO_NO_INPUT_OUTPUT), 1, RESP_ADDR);
    assert!(a.smp.set_keypair(&DEBUG_PRIVATE_KEY));
    a.smp.initiator = true;
    let sk = a.smp.local_sk.unwrap();
    let ent = a.entropy(0);
    let mut out = Vec::new();
    let own = a.smp.local_pk;
    assert_eq!(crate::smp::sc::on_public_key(&mut a.smp, &own, &sk, &ent, &mut out),
               Err(SMP_DHKEY_CHECK_FAILED));
}

#[test]
fn a_frame_arriving_out_of_order_is_dropped() {
    let mut a = Node::new(legacy_cfg(SMP_IO_NO_INPUT_OUTPUT), 1, RESP_ADDR);
    let ent = a.entropy(0);
    let mut out = Vec::new();
    start_pairing(&mut a.smp, BT_SECURITY_MEDIUM, &ent, &mut out);
    // A confirm is not expected until the response has arrived.
    let mut buf = [0u8; SMP_PDU_MAX + 1];
    let n = Pdu::Confirm([0; SMP_KEY_LEN]).encode(&mut buf).unwrap();
    let step = Step { now_ms: 1, current_level: BT_SECURITY_LOW, stk_encrypted: false,
                      have_ltk: false, ent: &ent };
    let mut out2 = Vec::new();
    assert_eq!(chan::receive(&mut a.smp, &buf[..n], &step, &mut out2), Ok(false));
    assert!(out2.is_empty());
}

#[test]
fn a_distributed_key_arriving_out_of_order_is_refused_explicitly() {
    let mut a = Node::new(legacy_cfg(SMP_IO_NO_INPUT_OUTPUT), 1, RESP_ADDR);
    let ent = a.entropy(0);
    let mut buf = [0u8; SMP_PDU_MAX + 1];
    let n = Pdu::IdentInfo([0; SMP_KEY_LEN]).encode(&mut buf).unwrap();
    let step = Step { now_ms: 1, current_level: BT_SECURITY_LOW, stk_encrypted: false,
                      have_ltk: false, ent: &ent };
    let mut out = Vec::new();
    assert_eq!(chan::receive(&mut a.smp, &buf[..n], &step, &mut out), Err(SMP_KEY_REJECTED));
}

#[test]
fn a_stalled_pairing_expires() {
    let a = Node::new(legacy_cfg(SMP_IO_NO_INPUT_OUTPUT), 1, RESP_ADDR);
    assert!(!a.smp.expired(0));
    assert!(!a.smp.expired(SMP_TIMEOUT_MS - 1));
    assert!(a.smp.expired(SMP_TIMEOUT_MS));
}

#[test]
fn a_received_frame_restarts_the_deadline() {
    let mut a = Node::new(legacy_cfg(SMP_IO_NO_INPUT_OUTPUT), 1, RESP_ADDR);
    a.smp.touch(1_000);
    assert!(!a.smp.expired(SMP_TIMEOUT_MS));
    assert!(a.smp.expired(1_000 + SMP_TIMEOUT_MS));
}

#[test]
fn a_security_request_that_is_already_satisfied_starts_nothing() {
    let mut a = Node::new(legacy_cfg(SMP_IO_NO_INPUT_OUTPUT), 1, RESP_ADDR);
    a.smp.initiator = true;
    let ent = a.entropy(0);
    let step = Step { now_ms: 1, current_level: BT_SECURITY_MEDIUM, stk_encrypted: false,
                      have_ltk: true, ent: &ent };
    let mut buf = [0u8; SMP_PDU_MAX + 1];
    let n = Pdu::SecurityReq(SMP_AUTH_BONDING).encode(&mut buf).unwrap();
    let mut out = Vec::new();
    assert_eq!(chan::receive(&mut a.smp, &buf[..n], &step, &mut out), Ok(true));
    assert!(out.is_empty());
}

#[test]
fn a_security_request_asking_for_more_starts_a_pairing() {
    let mut a = Node::new(legacy_cfg(SMP_IO_KEYBOARD_DISPLAY), 1, RESP_ADDR);
    a.smp.initiator = true;
    let ent = a.entropy(0);
    let step = Step { now_ms: 1, current_level: BT_SECURITY_MEDIUM, stk_encrypted: false,
                      have_ltk: true, ent: &ent };
    let mut buf = [0u8; SMP_PDU_MAX + 1];
    let n = Pdu::SecurityReq(SMP_AUTH_MITM | SMP_AUTH_BONDING).encode(&mut buf).unwrap();
    let mut out = Vec::new();
    assert_eq!(chan::receive(&mut a.smp, &buf[..n], &step, &mut out), Ok(true));
    assert_eq!(a.smp.pending_sec_level, BT_SECURITY_HIGH);
    assert!(matches!(out.first(), Some(SmpEvent::Send(Pdu::PairingReq(_)))));
}

#[test]
fn asking_for_a_level_no_method_can_reach_is_refused() {
    // Neither side can interact, so a request for an authenticated level
    // cannot be met and must be refused rather than met with a weaker key.
    let mut a = Node::new(legacy_cfg(SMP_IO_NO_INPUT_OUTPUT), 1, RESP_ADDR);
    let mut b = Node::new(legacy_cfg(SMP_IO_NO_INPUT_OUTPUT), 2, INIT_ADDR);
    b.smp.pending_sec_level = BT_SECURITY_HIGH;
    let ent = a.entropy(0);
    let mut out = Vec::new();
    start_pairing(&mut a.smp, BT_SECURITY_HIGH, &ent, &mut out);
    let SmpEvent::Send(pdu) = out.remove(0) else { panic!("expected a frame") };
    let mut buf = [0u8; SMP_PDU_MAX + 1];
    let n = pdu.encode(&mut buf).unwrap();
    let bent = b.entropy(0);
    let step = Step { now_ms: 1, current_level: BT_SECURITY_LOW, stk_encrypted: false,
                      have_ltk: false, ent: &bent };
    let mut bout = Vec::new();
    assert_eq!(chan::receive(&mut b.smp, &buf[..n], &step, &mut bout),
               Err(SMP_AUTH_REQUIREMENTS));
}

#[test]
fn a_key_size_below_the_minimum_is_refused() {
    let mut b = Node::new(legacy_cfg(SMP_IO_NO_INPUT_OUTPUT), 2, INIT_ADDR);
    let cmd = crate::smp::pdu::PairingCmd {
        io_capability: SMP_IO_NO_INPUT_OUTPUT,
        oob_flag: SMP_OOB_NOT_PRESENT,
        auth_req: SMP_AUTH_BONDING,
        max_key_size: SMP_MIN_ENC_KEY_SIZE - 1,
        init_key_dist: SMP_DIST_ENC_KEY,
        resp_key_dist: SMP_DIST_ENC_KEY,
    };
    let mut buf = [0u8; SMP_PDU_MAX + 1];
    let n = Pdu::PairingReq(cmd).encode(&mut buf).unwrap();
    let ent = b.entropy(0);
    let step = Step { now_ms: 1, current_level: BT_SECURITY_LOW, stk_encrypted: false,
                      have_ltk: false, ent: &ent };
    let mut out = Vec::new();
    assert_eq!(chan::receive(&mut b.smp, &buf[..n], &step, &mut out), Err(SMP_ENC_KEY_SIZE));
}
