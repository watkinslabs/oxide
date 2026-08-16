// Installed keys and the choice of which one a frame uses.
//
// The selection rule is the part worth reading twice: a unicast frame to a
// peer that has a pairwise key uses THAT key, whatever the default transmit
// index says, and only a frame with no pairwise key falls back to the group
// key. Getting the precedence backwards encrypts unicast traffic under the
// group key — which every station on the network holds, so the traffic is
// readable by all of them while looking perfectly protected.
//
// The live cipher counters live here and only here. What userspace asked for
// is recorded by the configuration layer; what the cipher is currently doing
// is this.

extern crate alloc;

use alloc::vec::Vec;

use wireless::ieee80211::MacAddr;
use wireless::keys::NUM_KEY_IDX;
use wireless::uapi::ciphers::{self, cipher};

use crate::crypto::pn::{Pn, RxPn, TxPn};
use crate::flags;

/// One key with its live state.
#[derive(Debug)]
pub struct Key {
    pub cipher: u32,
    /// Key material as installed. For the temporal-key cipher this is the
    /// whole three-part blob, not just the encryption half.
    pub material: Vec<u8>,
    pub idx: u8,
    pub pairwise: bool,
    /// Peer a pairwise key belongs to.
    pub peer: Option<MacAddr>,
    /// Bits from `flags::key`.
    pub flags: u32,
    /// Counter the next transmitted frame takes its packet number from.
    pub tx_pn: TxPn,
    /// Counters the replay check consults, one per traffic identifier.
    pub rx_pn: RxPn,
    /// Frames this key has protected and verified, for diagnosis.
    pub tx_count: u64,
    pub rx_count: u64,
}

impl Key {
    /// Build a key from what was installed. A supplied sequence counter seeds
    /// both directions: it is the value the peer will start from, so
    /// accepting anything below it would accept frames sent before the rekey.
    /// # C: O(1)
    pub fn new(cipher: u32, material: Vec<u8>, idx: u8, pairwise: bool,
               peer: Option<MacAddr>, seq: Option<&[u8]>) -> Self {
        let start = match seq {
            Some(s) if s.len() >= 6 => Pn::from_bytes(&[s[5], s[4], s[3], s[2], s[1], s[0]]),
            _ => Pn(0),
        };
        let mut key_flags = 0;
        if pairwise { key_flags |= flags::key::PAIRWISE; }
        if ciphers::is_mgmt_cipher(cipher) { key_flags |= flags::key::MGMT; }
        Self {
            cipher, material, idx, pairwise, peer, flags: key_flags,
            tx_pn: TxPn::new(start.0),
            rx_pn: if start.0 == 0 { RxPn::default() } else { RxPn::seeded(start) },
            tx_count: 0, rx_count: 0,
        }
    }

    /// Whether the hardware took this key, so software must not encrypt with
    /// it as well. # C: O(1)
    pub fn in_hardware(&self) -> bool { self.flags & flags::key::UPLOADED != 0 }

    /// Whether the key may be used to transmit. A key staged for a rekey is
    /// installed for receive only, and using it to send produces frames the
    /// peer cannot yet decrypt. # C: O(1)
    pub fn may_transmit(&self) -> bool { self.flags & flags::key::RX_ONLY == 0 }

    /// Bytes this key's cipher adds to a frame. # C: O(1)
    pub fn overhead(&self) -> usize {
        match self.cipher {
            cipher::CCMP | cipher::CCMP_256 =>
                crate::crypto::ccmp::overhead(self.encr_len()),
            cipher::GCMP | cipher::GCMP_256 => crate::crypto::gcmp::overhead(),
            cipher::TKIP => crate::crypto::tkip::overhead(),
            cipher::WEP40 | cipher::WEP104 => crate::crypto::wep::overhead(),
            _ => 0,
        }
    }

    /// Length of the ENCRYPTION half of the material, which for the
    /// temporal-key cipher is not the whole blob. # C: O(1)
    pub fn encr_len(&self) -> usize {
        if self.cipher == cipher::TKIP { crate::uapi::tkip_key::ENCR_LEN }
        else { self.material.len() }
    }
}

/// A per-peer slot set.
type Slots = [Option<Key>; NUM_KEY_IDX];

/// Every key one interface holds.
#[derive(Debug, Default)]
pub struct KeySet {
    group: Slots,
    pairwise: Vec<(MacAddr, Slots)>,
    /// Default index for transmitted data frames.
    pub default_key: Option<u8>,
    /// Default index for protected management frames.
    pub default_mgmt_key: Option<u8>,
    /// Default index for protected beacons.
    pub default_beacon_key: Option<u8>,
}

impl KeySet {
    /// Install a key, replacing whatever held that slot. # C: O(N peers)
    pub fn install(&mut self, key: Key) {
        let i = key.idx as usize;
        if i >= NUM_KEY_IDX { return; }
        if key.pairwise {
            let Some(peer) = key.peer else { return; };
            if let Some(slot) = self.pairwise.iter_mut().find(|(p, _)| *p == peer) {
                slot.1[i] = Some(key);
                return;
            }
            let mut set: Slots = Default::default();
            set[i] = Some(key);
            self.pairwise.push((peer, set));
        } else {
            self.group[i] = Some(key);
            // The first group key installed becomes the transmit default,
            // because a network with a group key and no default sends its
            // broadcast traffic in the clear.
            if self.default_key.is_none() && i <= wireless::keys::MAX_DATA_KEY_IDX as usize {
                self.default_key = Some(key_idx(i));
            }
        }
    }

    /// Remove a key. Reports whether one was there. # C: O(N peers)
    pub fn remove(&mut self, idx: u8, pairwise: bool, peer: Option<MacAddr>) -> bool {
        let i = idx as usize;
        if i >= NUM_KEY_IDX { return false; }
        if pairwise {
            let Some(peer) = peer else { return false; };
            let Some(slot) = self.pairwise.iter_mut().find(|(p, _)| *p == peer)
                else { return false; };
            let had = slot.1[i].take().is_some();
            if slot.1.iter().all(Option::is_none) { self.pairwise.retain(|(p, _)| *p != peer); }
            had
        } else {
            let had = self.group[i].take().is_some();
            if had {
                if self.default_key == Some(idx) { self.default_key = None; }
                if self.default_mgmt_key == Some(idx) { self.default_mgmt_key = None; }
                if self.default_beacon_key == Some(idx) { self.default_beacon_key = None; }
            }
            had
        }
    }

    /// The key at an index. # C: O(N peers)
    pub fn get(&self, idx: u8, pairwise: bool, peer: Option<MacAddr>) -> Option<&Key> {
        let i = idx as usize;
        if i >= NUM_KEY_IDX { return None; }
        if pairwise {
            let peer = peer?;
            self.pairwise.iter().find(|(p, _)| *p == peer)?.1[i].as_ref()
        } else { self.group[i].as_ref() }
    }

    /// Mutable access to the key at an index, for advancing its counters.
    /// # C: O(N peers)
    pub fn get_mut(&mut self, idx: u8, pairwise: bool, peer: Option<MacAddr>)
        -> Option<&mut Key>
    {
        let i = idx as usize;
        if i >= NUM_KEY_IDX { return None; }
        if pairwise {
            let peer = peer?;
            self.pairwise.iter_mut().find(|(p, _)| *p == peer)?.1[i].as_mut()
        } else { self.group[i].as_mut() }
    }

    /// The key a frame to `dst` should be protected with, and the index it
    /// sits at. A unicast destination with a pairwise key uses it; everything
    /// else uses the default group key. # C: O(N peers)
    pub fn tx_key(&self, dst: MacAddr) -> Option<(&Key, u8)> {
        if dst.is_unicast() {
            if let Some((_, slots)) = self.pairwise.iter().find(|(p, _)| *p == dst) {
                if let Some((i, k)) = slots.iter().enumerate()
                    .find_map(|(i, s)| s.as_ref().filter(|k| k.may_transmit()).map(|k| (i, k)))
                { return Some((k, key_idx(i))); }
            }
        }
        let idx = self.default_key?;
        let k = self.group[idx as usize].as_ref()?;
        if !k.may_transmit() { return None; }
        Some((k, idx))
    }

    /// The key a protected management frame should use. # C: O(1)
    pub fn tx_mgmt_key(&self) -> Option<(&Key, u8)> {
        let idx = self.default_mgmt_key?;
        Some((self.group[idx as usize].as_ref()?, idx))
    }

    /// The key a received frame names: the pairwise key of the sender when
    /// the frame is unicast to us and one exists, the group key at the index
    /// the cipher header carried otherwise. # C: O(N peers)
    pub fn rx_key(&self, sender: MacAddr, dst_is_unicast: bool, idx: u8) -> Option<&Key> {
        if dst_is_unicast {
            if let Some((_, slots)) = self.pairwise.iter().find(|(p, _)| *p == sender) {
                if let Some(k) = slots.iter().flatten().next() { return Some(k); }
            }
        }
        self.group.get(idx as usize)?.as_ref()
    }

    /// Mutable form of `rx_key`, for advancing the replay counter after a
    /// frame is accepted. # C: O(N peers)
    pub fn rx_key_mut(&mut self, sender: MacAddr, dst_is_unicast: bool, idx: u8)
        -> Option<&mut Key>
    {
        if dst_is_unicast && self.pairwise.iter().any(|(p, s)|
            *p == sender && s.iter().any(Option::is_some))
        {
            let slots = &mut self.pairwise.iter_mut().find(|(p, _)| *p == sender)?.1;
            return slots.iter_mut().flatten().next();
        }
        self.group.get_mut(idx as usize)?.as_mut()
    }

    /// Whether this interface has any key at all, which decides whether an
    /// unprotected frame may be delivered. # C: O(N peers)
    pub fn any(&self) -> bool {
        self.group.iter().any(Option::is_some) || !self.pairwise.is_empty()
    }

    /// Whether a peer holds a pairwise key. # C: O(N peers)
    pub fn has_pairwise(&self, peer: MacAddr) -> bool {
        self.pairwise.iter().any(|(p, s)| *p == peer && s.iter().any(Option::is_some))
    }

    /// Drop every key belonging to a peer, as a disassociation does.
    /// # C: O(N peers)
    pub fn forget_peer(&mut self, peer: MacAddr) {
        self.pairwise.retain(|(p, _)| *p != peer);
    }

    /// Drop everything. # C: O(N peers)
    pub fn flush(&mut self) {
        self.group = Default::default();
        self.pairwise.clear();
        self.default_key = None;
        self.default_mgmt_key = None;
        self.default_beacon_key = None;
    }

    /// Make an installed index the transmit default. # C: O(1)
    pub fn set_default(&mut self, idx: u8) -> bool {
        if idx as usize >= NUM_KEY_IDX || self.group[idx as usize].is_none() { return false; }
        self.default_key = Some(idx);
        true
    }
}

fn key_idx(i: usize) -> u8 { i as u8 }
