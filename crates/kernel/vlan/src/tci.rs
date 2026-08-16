// Tag control information: the 16 bits that ride beside the tag protocol
// identifier, and the byte surgery that moves a tag into or out of a frame.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::{
    ETH_ALEN, ETH_P_8021AD, ETH_P_8021Q, VLAN_CFI_MASK, VLAN_ETH_HLEN, VLAN_HLEN,
    VLAN_PRIO_MASK, VLAN_PRIO_SHIFT, VLAN_VID_MASK,
};

/// Offset of the ethertype/TPID field in an Ethernet header.
const ETHERTYPE_OFF: usize = ETH_ALEN * 2;
/// Offset of the TCI in a tagged frame.
const TCI_OFF: usize = ETHERTYPE_OFF + 2;
/// Offset of the encapsulated ethertype in a tagged frame.
const INNER_TYPE_OFF: usize = TCI_OFF + 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TagError {
    /// Frame is too short to hold the header the operation needs.
    Short,
    /// Outer ethertype is not a tag protocol identifier.
    NotTagged,
}

/// Whether an ethertype introduces a VLAN tag. # C: O(1)
pub const fn is_tpid(ethertype: u16) -> bool {
    ethertype == ETH_P_8021Q || ethertype == ETH_P_8021AD
}

/// Pack an identifier and a priority code point into tag control information.
/// Bits outside each field are dropped, and the drop-eligible bit stays clear —
/// the transmit path never sets it.
/// # C: O(1)
pub const fn encode(vlan_id: u16, pcp: u8) -> u16 {
    (vlan_id & VLAN_VID_MASK) | qos_mask(pcp)
}

/// Priority code point already shifted into its field, ready to be OR-ed into
/// tag control information. # C: O(1)
pub const fn qos_mask(pcp: u8) -> u16 {
    ((pcp as u16) << VLAN_PRIO_SHIFT) & VLAN_PRIO_MASK
}

/// Identifier carried in tag control information. # C: O(1)
pub const fn vlan_id(tci: u16) -> u16 { tci & VLAN_VID_MASK }

/// Priority code point carried in tag control information. # C: O(1)
pub const fn pcp(tci: u16) -> u8 { ((tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT) as u8 }

/// Drop-eligible / canonical-format bit. # C: O(1)
pub const fn cfi(tci: u16) -> bool { tci & VLAN_CFI_MASK != 0 }

/// The 4 tag bytes as they appear on the wire: tag protocol identifier then
/// tag control information, both big-endian. # C: O(1)
pub const fn tag_bytes(proto: u16, tci: u16) -> [u8; VLAN_HLEN] {
    let p = proto.to_be_bytes();
    let t = tci.to_be_bytes();
    [p[0], p[1], t[0], t[1]]
}

/// Build a tagged copy of an untagged frame.
///
/// The addresses stay put and the frame's own ethertype becomes the
/// encapsulated one, so the tag is inserted after the source address rather
/// than prepended. An already-tagged frame is stacked, which is what an outer
/// service tag over a customer tag is.
/// # C: O(len)
pub fn insert(frame: &[u8], proto: u16, tci: u16) -> Result<Vec<u8>, TagError> {
    if frame.len() < ETHERTYPE_OFF { return Err(TagError::Short); }
    let mut out = Vec::with_capacity(frame.len() + VLAN_HLEN);
    out.extend_from_slice(&frame[..ETHERTYPE_OFF]);
    out.extend_from_slice(&tag_bytes(proto, tci));
    out.extend_from_slice(&frame[ETHERTYPE_OFF..]);
    Ok(out)
}

/// The tag a frame carries, without modifying it. # C: O(1)
pub fn peek(frame: &[u8]) -> Result<(u16, u16), TagError> {
    if frame.len() < VLAN_ETH_HLEN { return Err(TagError::Short); }
    let proto = u16::from_be_bytes([frame[ETHERTYPE_OFF], frame[ETHERTYPE_OFF + 1]]);
    if !is_tpid(proto) { return Err(TagError::NotTagged); }
    let tci = u16::from_be_bytes([frame[TCI_OFF], frame[TCI_OFF + 1]]);
    Ok((proto, tci))
}

/// Remove the outermost tag, returning it alongside the untagged frame.
///
/// The result is byte-for-byte the frame `insert` was given: the encapsulated
/// ethertype slides back down to where the tag protocol identifier was.
/// # C: O(len)
pub fn strip(frame: &[u8]) -> Result<(u16, u16, Vec<u8>), TagError> {
    let (proto, tci) = peek(frame)?;
    let mut out = Vec::with_capacity(frame.len() - VLAN_HLEN);
    out.extend_from_slice(&frame[..ETHERTYPE_OFF]);
    out.extend_from_slice(&frame[INNER_TYPE_OFF..]);
    Ok((proto, tci, out))
}

/// Ethertype a tagged frame encapsulates. # C: O(1)
pub fn inner_ethertype(frame: &[u8]) -> Result<u16, TagError> {
    peek(frame)?;
    Ok(u16::from_be_bytes([frame[INNER_TYPE_OFF], frame[INNER_TYPE_OFF + 1]]))
}
