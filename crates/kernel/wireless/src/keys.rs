// Key management: what a `NEW_KEY` must satisfy before a cipher is installed,
// and where an installed key lives.
//
// The validation order here is load-bearing and is the reason this module is
// separate from the netlink shim: several checks would each reject the same
// bad request, but with DIFFERENT errnos, and userspace branches on which one
// it gets. An unsupported cipher must not be reported as a bad key length,
// and a key the interface is not in a state to accept must report that it has
// no link rather than that its arguments are wrong.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::ieee80211::MacAddr;
use crate::uapi::ciphers::{self, cipher};
use crate::uapi::enums::IfType;

/// Data keys occupy indexes 0 to 3.
pub const MAX_DATA_KEY_IDX: u8 = 3;
/// Integrity group keys occupy indexes 4 and 5.
pub const FIRST_IGTK_IDX: u8 = 4;
pub const LAST_IGTK_IDX: u8 = 5;
/// Beacon integrity group keys occupy indexes 6 and 7.
pub const FIRST_BIGTK_IDX: u8 = 6;
pub const LAST_BIGTK_IDX: u8 = 7;
/// Key indexes in total.
pub const NUM_KEY_IDX: usize = 8;

/// `NL80211_KEY_*` install modes.
pub mod key_mode {
    /// The key is used for both directions.
    pub const RX_TX: u32 = 0;
    /// The key is installed for receive only, so a rekey can be staged before
    /// the sender switches over.
    pub const NO_TX: u32 = 1;
    /// The key already installed becomes the transmit key. Not valid while
    /// installing, only afterwards.
    pub const SET_TX: u32 = 2;
    pub const MAX: u32 = SET_TX;
}

/// One key as userspace asked for it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KeyParams {
    pub cipher: u32,
    pub key: Vec<u8>,
    /// Replay counter the key starts at, when one was supplied.
    pub seq: Option<Vec<u8>>,
    pub mode: u32,
    /// VLAN a group key belongs to on an AP.
    pub vlan_id: u16,
}

/// One installed key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledKey {
    pub params: KeyParams,
    pub idx: u8,
    pub pairwise: bool,
    /// Peer the key is for; a group key has none.
    pub peer: Option<MacAddr>,
}

/// The keys one interface holds.
#[derive(Clone, Debug, Default)]
pub struct KeyRing {
    /// Group keys, indexed by key index.
    group: [Option<InstalledKey>; NUM_KEY_IDX],
    /// Pairwise keys, one set per peer.
    pairwise: Vec<(MacAddr, [Option<InstalledKey>; NUM_KEY_IDX])>,
    /// Default transmit key index for data frames.
    pub default_key: Option<u8>,
    /// Default key index for protected management frames.
    pub default_mgmt_key: Option<u8>,
    /// Default key index for protected beacons.
    pub default_beacon_key: Option<u8>,
}

/// What the radio supports, as key validation needs to see it. Passing this
/// in rather than reaching for the radio keeps the whole decision testable
/// without a registered device.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KeyCaps {
    /// Radio advertises an integrity group cipher, so indexes 4 and 5 exist.
    pub igtk: bool,
    /// Radio advertises beacon protection, so indexes 6 and 7 exist.
    pub beacon_protection: bool,
    /// Radio supports extended key id, so a pairwise key may sit at index 1.
    pub ext_key_id: bool,
    /// Radio allows a group key addressed to a peer, for a secured ad-hoc
    /// network.
    pub ibss_rsn: bool,
}

/// Highest key index that may be used, which depends on what the radio
/// advertised: a radio with no integrity group cipher has no index above 3,
/// and only a radio advertising beacon protection reaches 7. # C: O(1)
pub fn max_key_idx(caps: KeyCaps, pairwise: bool) -> u8 {
    if pairwise { return MAX_DATA_KEY_IDX; }
    if caps.beacon_protection { return LAST_BIGTK_IDX; }
    if caps.igtk { return LAST_IGTK_IDX; }
    MAX_DATA_KEY_IDX
}

/// Whether a key index is usable at all on this radio. # C: O(1)
pub fn valid_key_idx(caps: KeyCaps, idx: u8, pairwise: bool) -> bool {
    idx <= max_key_idx(caps, pairwise)
}

/// Validate an install request against the standard and against the radio's
/// advertisement. Nothing is installed; the caller applies only on success.
///
/// The checks run in the order the wire contract requires: index range,
/// pairwise/group addressing, per-cipher index rules, key length, sequence
/// length, and finally whether the radio advertises the cipher at all.
/// # C: O(N suites)
pub fn validate(caps: KeyCaps, supported: &[u32], iftype: IfType, params: &KeyParams,
                idx: u8, pairwise: bool, peer: Option<MacAddr>) -> Result<(), Errno> {
    if !valid_key_idx(caps, idx, pairwise) { return Err(Errno::Einval); }
    // A group key addressed to one peer only makes sense in a secured ad-hoc
    // network, where each peer has its own group key.
    if !pairwise && peer.is_some() && !caps.ibss_rsn { return Err(Errno::Einval); }
    if pairwise && peer.is_none() { return Err(Errno::Einval); }
    if params.mode > key_mode::MAX { return Err(Errno::Einval); }

    match params.cipher {
        cipher::TKIP => {
            // Extended key id exists only for the counter-mode ciphers, so a
            // pairwise TKIP key can only be index 0 and can only be RX+TX.
            if (pairwise && idx != 0) || params.mode != key_mode::RX_TX {
                return Err(Errno::Einval);
            }
        }
        cipher::CCMP | cipher::CCMP_256 | cipher::GCMP | cipher::GCMP_256 => {
            // Receive-only staging is a pairwise-key idea; and a request may
            // not both install a key and make it the transmit key.
            if (params.mode == key_mode::NO_TX && !pairwise)
                || params.mode == key_mode::SET_TX { return Err(Errno::Einval); }
            if caps.ext_key_id {
                if pairwise && idx > 1 { return Err(Errno::Einval); }
            } else if pairwise && idx != 0 { return Err(Errno::Einval); }
        }
        c if ciphers::is_mgmt_cipher(c) => {
            // An integrity group cipher protects management frames and can
            // never be a pairwise key.
            if pairwise { return Err(Errno::Einval); }
            if idx < FIRST_IGTK_IDX { return Err(Errno::Einval); }
        }
        cipher::WEP40 | cipher::WEP104 => {
            if idx > MAX_DATA_KEY_IDX { return Err(Errno::Einval); }
        }
        _ => {}
    }

    // A data interface for the neighbour-awareness protocol is restricted to
    // two counter-mode ciphers by that protocol's own specification.
    if iftype == IfType::NanData
        && params.cipher != cipher::CCMP && params.cipher != cipher::GCMP_256 {
        return Err(Errno::Einval);
    }

    if let Some(want) = ciphers::key_len(params.cipher) {
        if params.key.len() != want { return Err(Errno::Einval); }
    }

    if let Some(seq) = &params.seq {
        let want = ciphers::seq_len(params.cipher);
        // The wired-equivalent ciphers have no replay counter to install.
        if want == 0 { return Err(Errno::Einval); }
        if seq.len() != want { return Err(Errno::Einval); }
    }

    if !supported.contains(&params.cipher) { return Err(Errno::Einval); }
    Ok(())
}

/// Whether an interface is in a state where a key may be installed at all.
/// A client with no association has nothing to install a key against, which
/// is reported as a missing link and not as a bad argument. # C: O(1)
pub fn key_allowed(iftype: IfType, connected: bool, secure_nan: bool) -> Result<(), Errno> {
    match iftype {
        IfType::Ap | IfType::ApVlan | IfType::P2pGo | IfType::MeshPoint => Ok(()),
        IfType::Adhoc | IfType::Station | IfType::P2pClient =>
            if connected { Ok(()) } else { Err(Errno::Enolink) },
        IfType::Nan | IfType::NanData | IfType::Pd =>
            if secure_nan { Ok(()) } else { Err(Errno::Einval) },
        _ => Err(Errno::Einval),
    }
}

impl KeyRing {
    /// Install a key, replacing whatever occupied that slot. # C: O(N peers)
    pub fn install(&mut self, key: InstalledKey) {
        let idx = key.idx as usize;
        if idx >= NUM_KEY_IDX { return; }
        if key.pairwise {
            let Some(peer) = key.peer else { return; };
            if let Some(slot) = self.pairwise.iter_mut().find(|(p, _)| *p == peer) {
                slot.1[idx] = Some(key);
                return;
            }
            let mut set: [Option<InstalledKey>; NUM_KEY_IDX] = Default::default();
            set[idx] = Some(key);
            self.pairwise.push((peer, set));
        } else {
            self.group[idx] = Some(key);
        }
    }

    /// Remove a key. Reports whether one was there — a delete of an empty
    /// slot is the caller's `ENOENT`. # C: O(N peers)
    pub fn remove(&mut self, idx: u8, pairwise: bool, peer: Option<MacAddr>) -> bool {
        let i = idx as usize;
        if i >= NUM_KEY_IDX { return false; }
        if pairwise {
            let Some(peer) = peer else { return false; };
            let Some(slot) = self.pairwise.iter_mut().find(|(p, _)| *p == peer)
                else { return false; };
            let had = slot.1[i].take().is_some();
            if slot.1.iter().all(Option::is_none) {
                self.pairwise.retain(|(p, _)| *p != peer);
            }
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

    /// The key at an index, group or pairwise. # C: O(N peers)
    pub fn get(&self, idx: u8, pairwise: bool, peer: Option<MacAddr>)
        -> Option<&InstalledKey>
    {
        let i = idx as usize;
        if i >= NUM_KEY_IDX { return None; }
        if pairwise {
            let peer = peer?;
            self.pairwise.iter().find(|(p, _)| *p == peer)?.1[i].as_ref()
        } else {
            self.group[i].as_ref()
        }
    }

    /// Drop every key. # C: O(N peers)
    pub fn flush(&mut self) {
        self.group = Default::default();
        self.pairwise.clear();
        self.default_key = None;
        self.default_mgmt_key = None;
        self.default_beacon_key = None;
    }

    /// Drop every key for one peer, as a disassociation does. # C: O(N peers)
    pub fn forget_peer(&mut self, peer: MacAddr) {
        self.pairwise.retain(|(p, _)| *p != peer);
    }

    /// Make an installed index the default. An index with no key is refused:
    /// a default pointing at nothing sends frames in the clear. # C: O(1)
    pub fn set_default(&mut self, idx: u8) -> Result<(), Errno> {
        if idx > MAX_DATA_KEY_IDX { return Err(Errno::Einval); }
        if self.group[idx as usize].is_none() { return Err(Errno::Enoent); }
        self.default_key = Some(idx);
        Ok(())
    }

    /// Make an installed integrity index the management default. # C: O(1)
    pub fn set_default_mgmt(&mut self, idx: u8) -> Result<(), Errno> {
        if !(FIRST_IGTK_IDX..=LAST_IGTK_IDX).contains(&idx) { return Err(Errno::Einval); }
        if self.group[idx as usize].is_none() { return Err(Errno::Enoent); }
        self.default_mgmt_key = Some(idx);
        Ok(())
    }

    /// Make an installed integrity index the beacon default. # C: O(1)
    pub fn set_default_beacon(&mut self, idx: u8) -> Result<(), Errno> {
        if !(FIRST_BIGTK_IDX..=LAST_BIGTK_IDX).contains(&idx) { return Err(Errno::Einval); }
        if self.group[idx as usize].is_none() { return Err(Errno::Enoent); }
        self.default_beacon_key = Some(idx);
        Ok(())
    }

    /// Every peer holding a pairwise key. # C: O(N peers)
    pub fn peers(&self) -> Vec<MacAddr> { self.pairwise.iter().map(|(p, _)| *p).collect() }
}
