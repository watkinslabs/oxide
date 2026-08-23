//! The owner of one L2CAP connection, corresponding to Linux `struct l2cap_conn`.
//!
//! HCI delivers ACL fragments, not L2CAP packets.  This object owns the
//! fragment buffer, the channel identifiers, and the signalling dispatch
//! boundary so a packet cannot be decoded without a link context.

extern crate alloc;
use alloc::vec::Vec;

use crate::hci::conn::PeerId;
use crate::uapi::hci::{ACL_CONT, ACL_START};
use crate::uapi::l2cap as u;
use super::chan::Channel;
use super::codec::{decode_frame, split_cmd};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct L2capConn {
    pub handle: u16,
    pub peer: PeerId,
    pub link_type: u8,
    channels: Vec<Channel>,
    rx: Vec<u8>,
    rx_expected: Option<usize>,
    next_ident: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Inbound {
    Signalling(Vec<SignallingCommand>),
    Data { cid: u16, body: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignallingCommand {
    pub code: u8,
    pub ident: u8,
    pub body: Vec<u8>,
}

impl L2capConn {
    pub fn new(handle: u16, peer: PeerId, link_type: u8) -> Self {
        Self { handle, peer, link_type, channels: Vec::new(), rx: Vec::new(),
            rx_expected: None, next_ident: 0 }
    }

    pub fn channels(&self) -> core::slice::Iter<'_, Channel> { self.channels.iter() }
    pub fn channel(&self, cid: u16) -> Option<&Channel> {
        self.channels.iter().find(|c| c.scid == cid || c.dcid == cid)
    }
    pub fn channel_mut(&mut self, cid: u16) -> Option<&mut Channel> {
        self.channels.iter_mut().find(|c| c.scid == cid || c.dcid == cid)
    }
    pub fn add_channel(&mut self, chan: Channel) -> bool {
        if chan.scid < u::CID_DYN_START || self.channel(chan.scid).is_some() ||
            (chan.dcid != 0 && self.channel(chan.dcid).is_some()) { return false; }
        self.channels.push(chan); true
    }
    pub fn remove_channel(&mut self, cid: u16) -> Option<Channel> {
        let at = self.channels.iter().position(|c| c.scid == cid || c.dcid == cid)?;
        Some(self.channels.remove(at))
    }

    /// Allocate a nonzero signalling identifier, wrapping while refusing an
    /// identifier still awaited by a channel.
    pub fn alloc_ident(&mut self) -> Option<u8> {
        for _ in 0..u8::MAX {
            self.next_ident = self.next_ident.wrapping_add(1);
            if self.next_ident != 0 && !self.channels.iter().any(|c| c.ident == self.next_ident) {
                return Some(self.next_ident);
            }
        }
        None
    }

    /// Allocate a dynamic CID from the Linux range, keeping the LE range
    /// separate from BR/EDR's full dynamic range.
    pub fn alloc_cid(&self) -> Option<u16> {
        let end = if self.link_type == crate::uapi::hci::LE_LINK { u::CID_LE_DYN_END } else { u::CID_DYN_END };
        (u::CID_DYN_START..=end).find(|cid| !self.channels.iter().any(|c| c.scid == *cid || c.dcid == *cid))
    }

    /// Consume one HCI ACL fragment.  A continuation without a start, a
    /// length overflow, or a second packet glued to the first is dropped.
    pub fn receive_acl(&mut self, flags: u16, body: &[u8]) -> Option<Inbound> {
        match flags {
            ACL_START => {
                if body.len() < u::HDR_SIZE { return None; }
                let len = u16::from_le_bytes([body[0], body[1]]) as usize;
                if len > u::DEFAULT_MAX_SDU_SIZE as usize || body.len() > u::HDR_SIZE + len { return None; }
                self.rx.clear(); self.rx.extend_from_slice(body);
                self.rx_expected = Some(u::HDR_SIZE + len);
            }
            ACL_CONT => {
                if self.rx_expected.is_none() { return None; }
                self.rx.extend_from_slice(body);
            }
            _ => return None,
        }
        let expected = self.rx_expected?;
        if self.rx.len() < expected { return None; }
        if self.rx.len() != expected { self.rx.clear(); self.rx_expected = None; return None; }
        let packet = core::mem::take(&mut self.rx); self.rx_expected = None;
        let (cid, payload) = decode_frame(&packet)?;
        if cid == u::CID_SIGNALING || (self.link_type == crate::uapi::hci::LE_LINK && cid == u::CID_LE_SIGNALING) {
            let mut out = Vec::new(); let mut at = 0;
            while at < payload.len() {
                let cmd = split_cmd(&payload[at..])?;
                out.push(SignallingCommand { code: cmd.hdr.code, ident: cmd.hdr.ident, body: cmd.body.to_vec() });
                at += cmd.next;
            }
            Some(Inbound::Signalling(out))
        } else {
            Some(Inbound::Data { cid, body: payload.to_vec() })
        }
    }
}

#[derive(Default)]
pub struct L2capRegistry { conns: Vec<L2capConn> }

impl L2capRegistry {
    pub fn by_handle(&self, handle: u16) -> Option<&L2capConn> { self.conns.iter().find(|c| c.handle == handle) }
    pub fn by_handle_mut(&mut self, handle: u16) -> Option<&mut L2capConn> { self.conns.iter_mut().find(|c| c.handle == handle) }
    pub fn insert(&mut self, conn: L2capConn) {
        if let Some(old) = self.by_handle_mut(conn.handle) { *old = conn; } else { self.conns.push(conn); }
    }
    pub fn remove(&mut self, handle: u16) -> Option<L2capConn> {
        let at = self.conns.iter().position(|c| c.handle == handle)?; Some(self.conns.remove(at))
    }
    pub fn clear(&mut self) { self.conns.clear(); }
    pub fn len(&self) -> usize { self.conns.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use crate::uapi::bt::{BdAddr, BDADDR_BREDR};
    use crate::uapi::hci::ACL_START;

    fn conn() -> L2capConn {
        L2capConn::new(7, PeerId::new(BdAddr([1, 2, 3, 4, 5, 6]), BDADDR_BREDR),
            crate::uapi::hci::ACL_LINK)
    }

    fn acl(cid: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        v.extend_from_slice(&cid.to_le_bytes());
        v.extend_from_slice(payload); v
    }

    #[test]
    fn an_acl_packet_is_reassembled_before_signalling_dispatch() {
        let mut c = conn();
        let packet = acl(u::CID_SIGNALING, &[u::ECHO_REQ, 1, 1, 0, 0xaa]);
        assert!(c.receive_acl(ACL_START, &packet[..6]).is_none());
        assert_eq!(c.receive_acl(crate::uapi::hci::ACL_CONT, &packet[6..]),
            Some(Inbound::Signalling(vec![SignallingCommand { code: u::ECHO_REQ,
                ident: 1, body: vec![0xaa] }])));
    }

    #[test]
    fn an_acl_continuation_without_a_start_is_dropped() {
        assert!(conn().receive_acl(crate::uapi::hci::ACL_CONT, &[1, 2]).is_none());
    }

    #[test]
    fn identifiers_and_cids_are_allocated_in_the_connection_namespace() {
        let mut c = conn();
        assert_eq!(c.alloc_ident(), Some(1));
        assert_eq!(c.alloc_cid(), Some(u::CID_DYN_START));
        let mut chan = Channel::new(); chan.scid = u::CID_DYN_START; chan.ident = 1;
        assert!(c.add_channel(chan));
        assert_eq!(c.alloc_ident(), Some(2));
        assert_eq!(c.alloc_cid(), Some(u::CID_DYN_START + 1));
    }
}
