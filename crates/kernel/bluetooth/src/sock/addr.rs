//! The four address forms, one per protocol.
//!
//! Each is decoded from and encoded to its exact ABI width. A buffer shorter
//! than the form is refused rather than read short: a partially decoded address
//! carries a peer identity the caller never supplied, and binding or connecting
//! to it reaches the wrong device.

use crate::uapi::bt::{BdAddr, AF_BLUETOOTH, BDADDR_BREDR, BDADDR_LE_RANDOM, BDADDR_LEN};

/// `struct sockaddr_hci`: family, controller index, channel.
pub const SOCKADDR_HCI_LEN: usize = 6;
/// `struct sockaddr_l2`: family, protocol/service selector, address, channel
/// identifier, address type.
pub const SOCKADDR_L2_LEN: usize = 13;
/// `struct sockaddr_sco`: family and address.
pub const SOCKADDR_SCO_LEN: usize = 8;
/// `struct sockaddr_rc`: family, address, server channel.
pub const SOCKADDR_RC_LEN: usize = 9;

/// A raw controller-socket address.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SockAddrHci { pub dev: u16, pub channel: u16 }

/// A channel address.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SockAddrL2 {
    pub psm: u16,
    pub bdaddr: BdAddr,
    pub cid: u16,
    pub bdaddr_type: u8,
}

/// A voice-link address.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SockAddrSco { pub bdaddr: BdAddr }

/// A serial-emulation address.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SockAddrRc { pub bdaddr: BdAddr, pub channel: u8 }

fn family_ok(buf: &[u8]) -> bool {
    buf.len() >= 2 && u16::from_ne_bytes([buf[0], buf[1]]) as u32 == AF_BLUETOOTH
}

fn le16(b: &[u8], off: usize) -> u16 { u16::from_le_bytes([b[off], b[off + 1]]) }

/// Decode a raw controller-socket address. # C: O(1)
pub fn hci_from_wire(buf: &[u8]) -> Option<SockAddrHci> {
    if buf.len() < SOCKADDR_HCI_LEN || !family_ok(buf) { return None; }
    Some(SockAddrHci { dev: le16(buf, 2), channel: le16(buf, 4) })
}

/// Encode a raw controller-socket address. # C: O(1)
pub fn hci_to_wire(a: SockAddrHci) -> [u8; SOCKADDR_HCI_LEN] {
    let mut out = [0u8; SOCKADDR_HCI_LEN];
    out[0..2].copy_from_slice(&(AF_BLUETOOTH as u16).to_ne_bytes());
    out[2..4].copy_from_slice(&a.dev.to_le_bytes());
    out[4..6].copy_from_slice(&a.channel.to_le_bytes());
    out
}

/// Decode a channel address. # C: O(1)
pub fn l2_from_wire(buf: &[u8]) -> Option<SockAddrL2> {
    if buf.len() < SOCKADDR_L2_LEN || !family_ok(buf) { return None; }
    Some(SockAddrL2 {
        psm: le16(buf, 2),
        bdaddr: BdAddr::from_wire(buf, 4)?,
        cid: le16(buf, 4 + BDADDR_LEN),
        bdaddr_type: buf[SOCKADDR_L2_LEN - 1],
    })
}

/// Encode a channel address. # C: O(1)
pub fn l2_to_wire(a: SockAddrL2) -> [u8; SOCKADDR_L2_LEN] {
    let mut out = [0u8; SOCKADDR_L2_LEN];
    out[0..2].copy_from_slice(&(AF_BLUETOOTH as u16).to_ne_bytes());
    out[2..4].copy_from_slice(&a.psm.to_le_bytes());
    a.bdaddr.to_wire(&mut out, 4);
    out[4 + BDADDR_LEN..6 + BDADDR_LEN].copy_from_slice(&a.cid.to_le_bytes());
    out[SOCKADDR_L2_LEN - 1] = a.bdaddr_type;
    out
}

/// Decode a voice-link address. # C: O(1)
pub fn sco_from_wire(buf: &[u8]) -> Option<SockAddrSco> {
    if buf.len() < SOCKADDR_SCO_LEN || !family_ok(buf) { return None; }
    Some(SockAddrSco { bdaddr: BdAddr::from_wire(buf, 2)? })
}

/// Encode a voice-link address. # C: O(1)
pub fn sco_to_wire(a: SockAddrSco) -> [u8; SOCKADDR_SCO_LEN] {
    let mut out = [0u8; SOCKADDR_SCO_LEN];
    out[0..2].copy_from_slice(&(AF_BLUETOOTH as u16).to_ne_bytes());
    a.bdaddr.to_wire(&mut out, 2);
    out
}

/// Decode a serial-emulation address. # C: O(1)
pub fn rc_from_wire(buf: &[u8]) -> Option<SockAddrRc> {
    if buf.len() < SOCKADDR_RC_LEN || !family_ok(buf) { return None; }
    Some(SockAddrRc { bdaddr: BdAddr::from_wire(buf, 2)?, channel: buf[SOCKADDR_RC_LEN - 1] })
}

/// Encode a serial-emulation address. # C: O(1)
pub fn rc_to_wire(a: SockAddrRc) -> [u8; SOCKADDR_RC_LEN] {
    let mut out = [0u8; SOCKADDR_RC_LEN];
    out[0..2].copy_from_slice(&(AF_BLUETOOTH as u16).to_ne_bytes());
    a.bdaddr.to_wire(&mut out, 2);
    out[SOCKADDR_RC_LEN - 1] = a.channel;
    out
}

/// Whether an address type names one of the three real ones. A type outside
/// them is not a peer this host can reach, and admitting it would key a
/// connection under an identity no key store can ever match. # C: O(1)
pub fn addr_type_valid(addr_type: u8) -> bool {
    (BDADDR_BREDR..=BDADDR_LE_RANDOM).contains(&addr_type)
}

#[cfg(test)]
#[path = "tests/addr.rs"]
mod tests;
