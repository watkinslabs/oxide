//! Baseband connection tracking.
//!
//! One entry per link the controller holds, keyed by the handle the controller
//! assigned. A peer is identified by its address AND its address type: a BR/EDR
//! link and an LE link to the same six bytes are different peers with different
//! keys, and collapsing them is how a stack hands an LE key to a BR/EDR link.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::bt::{BdAddr, BT_CLOSED, BT_CONNECT, BT_CONNECTED, BT_SECURITY_LOW, BDADDR_BREDR, BDADDR_LE_PUBLIC};
use crate::uapi::hci::{ACL_LINK, ESCO_LINK, LE_LINK, SCO_LINK};

/// A peer identity: the address together with the address type it was seen on.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PeerId {
    pub addr: BdAddr,
    pub addr_type: u8,
}

impl PeerId {
    /// Name a peer by address and address type. # C: O(1)
    pub fn new(addr: BdAddr, addr_type: u8) -> PeerId { PeerId { addr, addr_type } }
}

/// One live or forming baseband link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Conn {
    pub handle: u16,
    pub peer: PeerId,
    /// `ACL_LINK`, `SCO_LINK`, `ESCO_LINK` or `LE_LINK`.
    pub link_type: u8,
    pub state: u8,
    /// Whether this host initiated the link.
    pub out: bool,
    /// Security level the link currently satisfies.
    pub sec_level: u8,
    /// Highest level any user of the link has asked for, which is what an
    /// elevation compares against.
    pub pending_sec_level: u8,
    pub encrypted: bool,
    pub authenticated: bool,
    /// Encryption key size in bytes, zero while the link is unencrypted. A
    /// level's sufficiency depends on it, not only on the level number.
    pub enc_key_size: u8,
    /// Data credits the controller has granted for this link's payload queue.
    pub tx_credits: u16,
}

impl Conn {
    /// A link in the connecting state, before the controller has confirmed it.
    /// # C: O(1)
    pub fn new(handle: u16, peer: PeerId, link_type: u8, out: bool) -> Conn {
        Conn {
            handle, peer, link_type, state: BT_CONNECT, out,
            sec_level: BT_SECURITY_LOW, pending_sec_level: BT_SECURITY_LOW,
            encrypted: false, authenticated: false, enc_key_size: 0, tx_credits: 0,
        }
    }

    /// Whether the link is an LE one, which decides which signalling channel,
    /// which pairing protocol and which key store apply. # C: O(1)
    pub fn is_le(&self) -> bool { self.link_type == LE_LINK }

    /// Whether the link carries voice rather than data. # C: O(1)
    pub fn is_sco(&self) -> bool { self.link_type == SCO_LINK || self.link_type == ESCO_LINK }

    /// Whether the link is established. # C: O(1)
    pub fn is_connected(&self) -> bool { self.state == BT_CONNECTED }
}

/// Every link one controller holds.
#[derive(Default)]
pub struct ConnList {
    conns: Vec<Conn>,
}

impl ConnList {
    /// An empty list. # C: O(1)
    pub fn new() -> ConnList { ConnList { conns: Vec::new() } }

    /// Number of tracked links. # C: O(1)
    pub fn len(&self) -> usize { self.conns.len() }

    /// Whether no link is tracked. # C: O(1)
    pub fn is_empty(&self) -> bool { self.conns.is_empty() }

    /// Add a link. A handle already present is replaced, because a controller
    /// reusing a handle has torn the old link down whether or not the host saw
    /// the disconnection. # C: O(n)
    pub fn insert(&mut self, conn: Conn) {
        match self.conns.iter_mut().find(|c| c.handle == conn.handle) {
            Some(slot) => *slot = conn,
            None => self.conns.push(conn),
        }
    }

    /// The link with this handle. # C: O(n)
    pub fn by_handle(&self, handle: u16) -> Option<&Conn> {
        self.conns.iter().find(|c| c.handle == handle)
    }

    /// Mutable access to the link with this handle. # C: O(n)
    pub fn by_handle_mut(&mut self, handle: u16) -> Option<&mut Conn> {
        self.conns.iter_mut().find(|c| c.handle == handle)
    }

    /// The link of this type to this peer. The type is part of the key because a
    /// peer can hold an ACL link and a SCO link at once. # C: O(n)
    pub fn by_peer(&self, peer: PeerId, link_type: u8) -> Option<&Conn> {
        self.conns.iter().find(|c| c.peer == peer && c.link_type == link_type)
    }

    /// Remove and return the link with this handle. # C: O(n)
    pub fn remove(&mut self, handle: u16) -> Option<Conn> {
        let idx = self.conns.iter().position(|c| c.handle == handle)?;
        Some(self.conns.remove(idx))
    }

    /// Every tracked link. # C: O(1)
    pub fn iter(&self) -> core::slice::Iter<'_, Conn> { self.conns.iter() }

    /// Drop every link, as a controller going down requires. # C: O(n)
    pub fn clear(&mut self) { self.conns.clear(); }

    /// Mark a link established at the handle the controller assigned. # C: O(n)
    pub fn set_connected(&mut self, handle: u16) -> bool {
        match self.by_handle_mut(handle) {
            Some(c) => { c.state = BT_CONNECTED; true }
            None => false,
        }
    }

    /// Mark a link closed without removing it, which is the state a disconnect
    /// completion leaves before the users of the link have been told. # C: O(n)
    pub fn set_closed(&mut self, handle: u16) -> bool {
        match self.by_handle_mut(handle) {
            Some(c) => { c.state = BT_CLOSED; c.encrypted = false; c.enc_key_size = 0; true }
            None => false,
        }
    }
}

/// The address type a link of this baseband type reports when the controller
/// gave no type of its own: a BR/EDR link is always a BR/EDR address, and an LE
/// link defaults to a public one. # C: O(1)
pub fn default_addr_type(link_type: u8) -> u8 {
    if link_type == LE_LINK { BDADDR_LE_PUBLIC } else { BDADDR_BREDR }
}

/// Whether a link type names a data link that L2CAP runs over. # C: O(1)
pub fn carries_l2cap(link_type: u8) -> bool { link_type == ACL_LINK || link_type == LE_LINK }

#[cfg(test)]
#[path = "tests/conn.rs"]
mod tests;
