//! Controller enumeration. Three lists exist because a client asking "what is
//! there" means three different things: the controllers it can use, the ones
//! present but not yet configured, and — in the extended form — every one of
//! them tagged with which of the two it is and what bus it sits on.

use alloc::vec::Vec;

use super::codec::{Reader, Writer};
use crate::uapi::mgmt::ev::{MGMT_EXT_INDEX_TYPE_CONFIGURED, MGMT_EXT_INDEX_TYPE_UNCONFIGURED};

/// One row of the extended list.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExtIndexEntry {
    pub index: u16,
    /// Configured or unconfigured, per the extended-index type byte.
    pub kind: u8,
    /// Transport the controller is attached by.
    pub bus: u8,
}

impl ExtIndexEntry {
    /// # C: O(1)
    pub fn new(index: u16, configured: bool, bus: u8) -> ExtIndexEntry {
        let kind = if configured { MGMT_EXT_INDEX_TYPE_CONFIGURED }
                   else { MGMT_EXT_INDEX_TYPE_UNCONFIGURED };
        ExtIndexEntry { index, kind, bus }
    }

    /// # C: O(1)
    pub fn is_configured(&self) -> bool { self.kind == MGMT_EXT_INDEX_TYPE_CONFIGURED }
}

/// Count then that many indices. Serves both the plain and the unconfigured
/// list, which differ only in which controllers the caller put in. # C: O(n)
pub fn encode_index_list(indices: &[u16]) -> Vec<u8> {
    let mut w = Writer::with_capacity(2 + 2 * indices.len());
    w.u16(indices.len() as u16);
    for i in indices { w.u16(*i); }
    w.finish()
}

/// Read an index list back. Refuses a count that disagrees with the bytes
/// present, in either direction. # C: O(n)
pub fn decode_index_list(buf: &[u8]) -> Option<Vec<u16>> {
    let mut r = Reader::new(buf);
    let n = r.u16()? as usize;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n { v.push(r.u16()?); }
    if !r.done() { return None; }
    Some(v)
}

/// Count then that many `{index, type, bus}` rows. # C: O(n)
pub fn encode_ext_index_list(entries: &[ExtIndexEntry]) -> Vec<u8> {
    let mut w = Writer::with_capacity(2 + 4 * entries.len());
    w.u16(entries.len() as u16);
    for e in entries {
        w.u16(e.index);
        w.u8(e.kind);
        w.u8(e.bus);
    }
    w.finish()
}

/// # C: O(n)
pub fn decode_ext_index_list(buf: &[u8]) -> Option<Vec<ExtIndexEntry>> {
    let mut r = Reader::new(buf);
    let n = r.u16()? as usize;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(ExtIndexEntry { index: r.u16()?, kind: r.u8()?, bus: r.u8()? });
    }
    if !r.done() { return None; }
    Some(v)
}

/// The `EXT_INDEX_ADDED`/`EXT_INDEX_REMOVED` payload: the type and bus of the
/// controller the header's index already names. # C: O(1)
pub fn encode_ext_index_event(configured: bool, bus: u8) -> Vec<u8> {
    let mut w = Writer::with_capacity(2);
    w.u8(if configured { MGMT_EXT_INDEX_TYPE_CONFIGURED } else { MGMT_EXT_INDEX_TYPE_UNCONFIGURED });
    w.u8(bus);
    w.finish()
}

#[cfg(test)]
#[path = "tests/index.rs"]
mod tests;
