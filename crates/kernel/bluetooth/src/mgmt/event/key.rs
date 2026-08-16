//! Key delivery. Each event leads with a store hint: whether the key is worth
//! writing to persistent storage, or is a session key that must not outlive the
//! connection. A client that ignores the hint and stores everything is how a
//! debug key survives a reboot.

use alloc::vec::Vec;

use crate::mgmt::codec::{Reader, Writer};
use crate::mgmt::types::{CsrkInfo, IrkInfo, LinkKeyInfo, LtkInfo};
use crate::uapi::bt::{BdAddr, BDADDR_LEN};
use crate::uapi::mgmt::limits::{
    MGMT_CSRK_INFO_SIZE, MGMT_IRK_INFO_SIZE, MGMT_LINK_KEY_INFO_SIZE, MGMT_LTK_INFO_SIZE,
};

/// `NEW_LINK_KEY`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NewLinkKey {
    pub store_hint: u8,
    pub key: LinkKeyInfo,
}

impl NewLinkKey {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(1 + MGMT_LINK_KEY_INFO_SIZE);
        w.u8(self.store_hint);
        self.key.write(&mut w);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<NewLinkKey> {
        let mut r = Reader::new(buf);
        let v = NewLinkKey { store_hint: r.u8()?, key: LinkKeyInfo::read(&mut r)? };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `NEW_LONG_TERM_KEY`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NewLongTermKey {
    pub store_hint: u8,
    pub key: LtkInfo,
}

impl NewLongTermKey {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(1 + MGMT_LTK_INFO_SIZE);
        w.u8(self.store_hint);
        self.key.write(&mut w);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<NewLongTermKey> {
        let mut r = Reader::new(buf);
        let v = NewLongTermKey { store_hint: r.u8()?, key: LtkInfo::read(&mut r)? };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `NEW_IRK`: the key, plus the resolvable address it was first seen under.
/// Both are needed — the resolvable address is what a client already has on
/// screen when the identity behind it becomes known.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NewIrk {
    pub store_hint: u8,
    pub rpa: BdAddr,
    pub irk: IrkInfo,
}

impl NewIrk {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(1 + BDADDR_LEN + MGMT_IRK_INFO_SIZE);
        w.u8(self.store_hint);
        w.addr(&self.rpa);
        self.irk.write(&mut w);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<NewIrk> {
        let mut r = Reader::new(buf);
        let v = NewIrk {
            store_hint: r.u8()?, rpa: r.addr()?, irk: IrkInfo::read(&mut r)?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `NEW_CSRK`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NewCsrk {
    pub store_hint: u8,
    pub key: CsrkInfo,
}

impl NewCsrk {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(1 + MGMT_CSRK_INFO_SIZE);
        w.u8(self.store_hint);
        self.key.write(&mut w);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<NewCsrk> {
        let mut r = Reader::new(buf);
        let v = NewCsrk { store_hint: r.u8()?, key: CsrkInfo::read(&mut r)? };
        if !r.done() { return None; }
        Some(v)
    }
}

#[cfg(test)]
#[path = "../tests/event_key.rs"]
mod tests;
