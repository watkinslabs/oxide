//! Distributed key records and the store that holds them.
//!
//! Every record is keyed by peer identity — the address together with its
//! type — because the same six bytes seen as a public identity and as a
//! random one are different peers. Long-term keys are additionally keyed by
//! role, since a key generated for one role cannot encrypt a link established
//! in the other; a key from a secure-connections exchange is the exception,
//! being usable in both.

extern crate alloc;
use alloc::vec::Vec;

use crate::hci::conn::PeerId;
use crate::uapi::bt::{BDADDR_LEN, BdAddr};
use crate::uapi::smp::{
    SMP_KEY_LEN, SMP_LTK, SMP_RPA_HASH_LEN, SMP_RPA_PRAND_LEN, SMP_RPA_TYPE_BITS,
    SMP_RPA_TYPE_MASK, SMP_ROLE_INITIATOR, SMP_ROLE_RESPONDER,
};
use super::crypto::ah;
use super::level::{ltk_is_sc, ltk_sec_level};

/// A long-term encryption key.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ltk {
    pub peer: PeerId,
    /// Which exchange produced it, which decides the level it supports.
    pub key_type: u8,
    pub authenticated: bool,
    pub val: [u8; SMP_KEY_LEN],
    /// Bytes of the key that are significant; the rest are zero.
    pub enc_size: u8,
    pub ediv: u16,
    pub rand: u64,
}

/// An identity resolving key, which turns a peer's changing random addresses
/// back into one identity.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Irk {
    pub peer: PeerId,
    pub val: [u8; SMP_KEY_LEN],
}

/// A signing key for unencrypted authenticated data.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Csrk {
    pub peer: PeerId,
    pub val: [u8; SMP_KEY_LEN],
    pub authenticated: bool,
    /// Last accepted signature counter; a repeat or a rewind is a replay.
    pub counter: u32,
}

/// A basic-rate link key, which cross-transport derivation converts to and
/// from. Basic-rate links have no address type, so the address alone keys it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LinkKey {
    pub addr: BdAddr,
    pub val: [u8; SMP_KEY_LEN],
    pub key_type: u8,
}

/// The role a key type was generated for. A secure-connections key is not
/// role-bound and this value is not consulted for one. # C: O(1)
pub fn ltk_role(key_type: u8) -> u8 {
    if key_type == SMP_LTK { SMP_ROLE_INITIATOR } else { SMP_ROLE_RESPONDER }
}

impl Ltk {
    /// The security level this key can support. # C: O(1)
    pub fn sec_level(&self) -> u8 { ltk_sec_level(self.key_type, self.authenticated) }

    /// Whether the key came from a secure-connections exchange. # C: O(1)
    pub fn is_sc(&self) -> bool { ltk_is_sc(self.key_type) }

    /// Whether the key is usable for a link in `role`. # C: O(1)
    pub fn usable_in_role(&self, role: u8) -> bool {
        self.is_sc() || ltk_role(self.key_type) == role
    }

    /// Whether re-encrypting with this key would reach `want`. # C: O(1)
    pub fn satisfies(&self, want: u8) -> bool { self.sec_level() >= want }
}

/// Whether an address is a resolvable private one, which is the only kind
/// worth attempting to resolve. # C: O(1)
pub fn is_rpa(addr: &BdAddr) -> bool {
    addr.as_bytes()[BDADDR_LEN - 1] & !SMP_RPA_TYPE_MASK == SMP_RPA_TYPE_BITS
}

/// Whether an identity resolving key generated an address. The address's low
/// three bytes are the hash of its high three. # C: O(1)
pub fn irk_matches(irk: &[u8; SMP_KEY_LEN], addr: &BdAddr) -> bool {
    let b = addr.as_bytes();
    let mut prand = [0u8; SMP_RPA_PRAND_LEN];
    prand.copy_from_slice(&b[SMP_RPA_HASH_LEN..]);
    ah(irk, &prand) == b[..SMP_RPA_HASH_LEN]
}

/// Build a resolvable private address from a key and three random bytes. The
/// caller supplies the randomness so the pool it comes from is its choice.
/// # C: O(1)
pub fn generate_rpa(irk: &[u8; SMP_KEY_LEN], prand: &[u8; SMP_RPA_PRAND_LEN]) -> BdAddr {
    let mut p = *prand;
    p[SMP_RPA_PRAND_LEN - 1] = (p[SMP_RPA_PRAND_LEN - 1] & SMP_RPA_TYPE_MASK) | SMP_RPA_TYPE_BITS;
    let hash = ah(irk, &p);
    let mut a = [0u8; BDADDR_LEN];
    a[..SMP_RPA_HASH_LEN].copy_from_slice(&hash);
    a[SMP_RPA_HASH_LEN..].copy_from_slice(&p);
    BdAddr(a)
}

/// Every key this host holds.
#[derive(Default)]
pub struct KeyStore {
    ltks: Vec<Ltk>,
    irks: Vec<Irk>,
    csrks: Vec<Csrk>,
    link_keys: Vec<LinkKey>,
}

impl KeyStore {
    /// An empty store. # C: O(1)
    pub fn new() -> KeyStore { KeyStore::default() }

    /// Store a long-term key, replacing one already held for the same peer and
    /// role. Replacing rather than appending is what keeps a re-pairing from
    /// leaving the superseded key usable. # C: O(n)
    pub fn add_ltk(&mut self, key: Ltk) {
        let role = ltk_role(key.key_type);
        if let Some(slot) = self.ltks.iter_mut()
            .find(|k| k.peer == key.peer && k.usable_in_role(role))
        {
            *slot = key;
            return;
        }
        self.ltks.push(key);
    }

    /// The long-term key for a peer on a link in `role`. # C: O(n)
    pub fn find_ltk(&self, peer: &PeerId, role: u8) -> Option<&Ltk> {
        self.ltks.iter().find(|k| k.peer == *peer && k.usable_in_role(role))
    }

    /// Whether any long-term key is held for a peer, in either role. # C: O(n)
    pub fn have_ltk(&self, peer: &PeerId) -> bool {
        self.ltks.iter().any(|k| k.peer == *peer)
    }

    /// Store an identity resolving key, replacing one held for the same peer.
    /// # C: O(n)
    pub fn add_irk(&mut self, key: Irk) {
        if let Some(slot) = self.irks.iter_mut().find(|k| k.peer == key.peer) {
            *slot = key;
            return;
        }
        self.irks.push(key);
    }

    /// The identity resolving key held for a peer. # C: O(n)
    pub fn find_irk(&self, peer: &PeerId) -> Option<&Irk> {
        self.irks.iter().find(|k| k.peer == *peer)
    }

    /// The identity behind a resolvable private address. # C: O(n)
    pub fn resolve(&self, addr: &BdAddr) -> Option<PeerId> {
        if !is_rpa(addr) { return None; }
        self.irks.iter().find(|k| irk_matches(&k.val, addr)).map(|k| k.peer)
    }

    /// Store a signing key, replacing one held for the same peer. # C: O(n)
    pub fn add_csrk(&mut self, key: Csrk) {
        if let Some(slot) = self.csrks.iter_mut().find(|k| k.peer == key.peer) {
            *slot = key;
            return;
        }
        self.csrks.push(key);
    }

    /// The signing key held for a peer. # C: O(n)
    pub fn find_csrk(&self, peer: &PeerId) -> Option<&Csrk> {
        self.csrks.iter().find(|k| k.peer == *peer)
    }

    /// Store a basic-rate link key, replacing one held for the same address.
    /// # C: O(n)
    pub fn add_link_key(&mut self, key: LinkKey) {
        if let Some(slot) = self.link_keys.iter_mut().find(|k| k.addr == key.addr) {
            *slot = key;
            return;
        }
        self.link_keys.push(key);
    }

    /// The basic-rate link key held for an address. # C: O(n)
    pub fn find_link_key(&self, addr: &BdAddr) -> Option<&LinkKey> {
        self.link_keys.iter().find(|k| k.addr == *addr)
    }

    /// Forget every key held for a peer, including a basic-rate link key to
    /// the same address. Forgetting one kind and not the others would leave a
    /// peer that appears unpaired still able to encrypt. # C: O(n)
    pub fn forget(&mut self, peer: &PeerId) {
        self.ltks.retain(|k| k.peer != *peer);
        self.irks.retain(|k| k.peer != *peer);
        self.csrks.retain(|k| k.peer != *peer);
        self.link_keys.retain(|k| k.addr != peer.addr);
    }

    /// Long-term keys held, for a caller enumerating them. # C: O(1)
    pub fn ltks(&self) -> &[Ltk] { &self.ltks }

    /// Identity resolving keys held. # C: O(1)
    pub fn irks(&self) -> &[Irk] { &self.irks }

    /// Signing keys held. # C: O(1)
    pub fn csrks(&self) -> &[Csrk] { &self.csrks }

    /// Basic-rate link keys held. # C: O(1)
    pub fn link_keys(&self) -> &[LinkKey] { &self.link_keys }
}

/// The role a link is in, from whether this host initiated it. # C: O(1)
pub fn role_of(outbound: bool) -> u8 {
    if outbound { SMP_ROLE_INITIATOR } else { SMP_ROLE_RESPONDER }
}
