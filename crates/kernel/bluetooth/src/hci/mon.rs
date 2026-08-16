//! Monitor record framing.
//!
//! Every frame the core sends or receives, and every controller appearing or
//! disappearing, becomes one monitor record: a six-byte header naming the
//! record kind and the controller, then the frame's own bytes WITHOUT the H:4
//! prefix — the prefix is redundant once the opcode has named the kind, and a
//! trace that carried both would decode one byte off.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::bt::BdAddr;
use crate::uapi::hci::{HCI_ACLDATA_PKT, HCI_COMMAND_PKT, HCI_EVENT_PKT, HCI_ISODATA_PKT, HCI_SCODATA_PKT};
use crate::uapi::hci_mon::{
    HCI_MON_ACL_RX_PKT, HCI_MON_ACL_TX_PKT, HCI_MON_COMMAND_PKT, HCI_MON_EVENT_PKT,
    HCI_MON_HDR_SIZE, HCI_MON_INDEX_INFO_SIZE, HCI_MON_ISO_RX_PKT, HCI_MON_ISO_TX_PKT,
    HCI_MON_NEW_INDEX_SIZE, HCI_MON_SCO_RX_PKT, HCI_MON_SCO_TX_PKT, MON_HDR_INDEX_OFF,
    MON_HDR_LEN_OFF, MON_HDR_OPCODE_OFF, MON_INDEX_INFO_BDADDR_OFF,
    MON_INDEX_INFO_MANUFACTURER_OFF, MON_NEW_INDEX_BDADDR_OFF, MON_NEW_INDEX_BUS_OFF,
    MON_NEW_INDEX_NAME_LEN, MON_NEW_INDEX_NAME_OFF, MON_NEW_INDEX_TYPE_OFF,
};

/// Direction a frame travelled, which selects between the transmit and receive
/// opcode of the same packet type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Dir { Tx, Rx }

/// Monitor opcode for a packet type and direction. Commands are always host to
/// controller and events always the other way, so their opcodes carry no
/// direction of their own and a direction that contradicts the type is what a
/// caller passing the wrong one would produce — the type decides. # C: O(1)
pub fn opcode_for(pkt_type: u8, dir: Dir) -> Option<u16> {
    Some(match (pkt_type, dir) {
        (HCI_COMMAND_PKT, _) => HCI_MON_COMMAND_PKT,
        (HCI_EVENT_PKT, _)   => HCI_MON_EVENT_PKT,
        (HCI_ACLDATA_PKT, Dir::Tx) => HCI_MON_ACL_TX_PKT,
        (HCI_ACLDATA_PKT, Dir::Rx) => HCI_MON_ACL_RX_PKT,
        (HCI_SCODATA_PKT, Dir::Tx) => HCI_MON_SCO_TX_PKT,
        (HCI_SCODATA_PKT, Dir::Rx) => HCI_MON_SCO_RX_PKT,
        (HCI_ISODATA_PKT, Dir::Tx) => HCI_MON_ISO_TX_PKT,
        (HCI_ISODATA_PKT, Dir::Rx) => HCI_MON_ISO_RX_PKT,
        _ => return None,
    })
}

/// Build one monitor record from an opcode, a controller index and a payload.
/// # C: O(len)
pub fn record(opcode: u16, index: u16, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > u16::MAX as usize { return None; }
    let mut out = Vec::with_capacity(HCI_MON_HDR_SIZE + payload.len());
    out.extend_from_slice(&opcode.to_le_bytes());
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    Some(out)
}

/// Wrap a whole H:4 frame as a monitor record, dropping the prefix byte the
/// record's opcode already names. # C: O(len)
pub fn frame_record(index: u16, frame: &[u8], dir: Dir) -> Option<Vec<u8>> {
    let (&pkt_type, rest) = frame.split_first()?;
    record(opcode_for(pkt_type, dir)?, index, rest)
}

/// Payload of a new-index record: controller type, bus, address, short name.
/// The name field is fixed width and NOT necessarily terminated — a name that
/// exactly fills it has no terminator, so a reader must bound by the width.
/// # C: O(1)
pub fn new_index_payload(dev_type: u8, bus: u8, addr: BdAddr, name: &str) -> [u8; HCI_MON_NEW_INDEX_SIZE] {
    let mut out = [0u8; HCI_MON_NEW_INDEX_SIZE];
    out[MON_NEW_INDEX_TYPE_OFF] = dev_type;
    out[MON_NEW_INDEX_BUS_OFF] = bus;
    addr.to_wire(&mut out, MON_NEW_INDEX_BDADDR_OFF);
    let bytes = name.as_bytes();
    let n = bytes.len().min(MON_NEW_INDEX_NAME_LEN);
    out[MON_NEW_INDEX_NAME_OFF..MON_NEW_INDEX_NAME_OFF + n].copy_from_slice(&bytes[..n]);
    out
}

/// Payload of an index-info record: address and manufacturer. # C: O(1)
pub fn index_info_payload(addr: BdAddr, manufacturer: u16) -> [u8; HCI_MON_INDEX_INFO_SIZE] {
    let mut out = [0u8; HCI_MON_INDEX_INFO_SIZE];
    addr.to_wire(&mut out, MON_INDEX_INFO_BDADDR_OFF);
    out[MON_INDEX_INFO_MANUFACTURER_OFF..MON_INDEX_INFO_MANUFACTURER_OFF + 2]
        .copy_from_slice(&manufacturer.to_le_bytes());
    out
}

/// Read the three header fields of a monitor record. # C: O(1)
pub fn parse_header(buf: &[u8]) -> Option<(u16, u16, u16)> {
    if buf.len() < HCI_MON_HDR_SIZE { return None; }
    let w = |off: usize| u16::from_le_bytes([buf[off], buf[off + 1]]);
    Some((w(MON_HDR_OPCODE_OFF), w(MON_HDR_INDEX_OFF), w(MON_HDR_LEN_OFF)))
}

#[cfg(test)]
#[path = "tests/mon.rs"]
mod tests;
