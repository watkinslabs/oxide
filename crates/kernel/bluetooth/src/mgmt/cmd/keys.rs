//! Key and out-of-band data commands. Each load command is a count followed by
//! exactly that many fixed-width records, and the count is checked against the
//! bytes present — a count that overstates would otherwise read whatever
//! followed the buffer, and one that understates would leave a silent tail.

use alloc::vec::Vec;

use crate::mgmt::codec::{Reader, Writer};
use crate::mgmt::types::{AddrInfo, BlockedKeyInfo, ConnParam, IrkInfo, LinkKeyInfo, LtkInfo};
use crate::uapi::mgmt::limits::{
    MGMT_ADDR_INFO_SIZE, MGMT_BLOCKED_KEY_INFO_SIZE, MGMT_CONN_PARAM_SIZE, MGMT_IRK_INFO_SIZE,
    MGMT_KEY_LEN, MGMT_LINK_KEY_INFO_SIZE, MGMT_LTK_INFO_SIZE,
};
use crate::uapi::mgmt::op::{
    MGMT_ADD_REMOTE_OOB_DATA_SIZE, MGMT_ADD_REMOTE_OOB_EXT_DATA_SIZE,
};

/// `LOAD_LINK_KEYS`: whether debug keys are acceptable, then the key set. An
/// empty set is meaningful — it clears the stored keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadLinkKeys {
    pub debug_keys: u8,
    pub keys: Vec<LinkKeyInfo>,
}

impl LoadLinkKeys {
    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<LoadLinkKeys> {
        let mut r = Reader::new(buf);
        let debug_keys = r.u8()?;
        let n = r.u16()? as usize;
        if r.remaining() != n * MGMT_LINK_KEY_INFO_SIZE { return None; }
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n { keys.push(LinkKeyInfo::read(&mut r)?); }
        Some(LoadLinkKeys { debug_keys, keys })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(3 + MGMT_LINK_KEY_INFO_SIZE * self.keys.len());
        w.u8(self.debug_keys);
        w.u16(self.keys.len() as u16);
        for k in &self.keys { k.write(&mut w); }
        w.finish()
    }
}

/// `LOAD_LONG_TERM_KEYS`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadLongTermKeys {
    pub keys: Vec<LtkInfo>,
}

impl LoadLongTermKeys {
    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<LoadLongTermKeys> {
        let mut r = Reader::new(buf);
        let n = r.u16()? as usize;
        if r.remaining() != n * MGMT_LTK_INFO_SIZE { return None; }
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n { keys.push(LtkInfo::read(&mut r)?); }
        Some(LoadLongTermKeys { keys })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(2 + MGMT_LTK_INFO_SIZE * self.keys.len());
        w.u16(self.keys.len() as u16);
        for k in &self.keys { k.write(&mut w); }
        w.finish()
    }
}

/// `LOAD_IRKS`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadIrks {
    pub irks: Vec<IrkInfo>,
}

impl LoadIrks {
    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<LoadIrks> {
        let mut r = Reader::new(buf);
        let n = r.u16()? as usize;
        if r.remaining() != n * MGMT_IRK_INFO_SIZE { return None; }
        let mut irks = Vec::with_capacity(n);
        for _ in 0..n { irks.push(IrkInfo::read(&mut r)?); }
        Some(LoadIrks { irks })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(2 + MGMT_IRK_INFO_SIZE * self.irks.len());
        w.u16(self.irks.len() as u16);
        for k in &self.irks { k.write(&mut w); }
        w.finish()
    }
}

/// `LOAD_CONN_PARAM`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadConnParam {
    pub params: Vec<ConnParam>,
}

impl LoadConnParam {
    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<LoadConnParam> {
        let mut r = Reader::new(buf);
        let n = r.u16()? as usize;
        if r.remaining() != n * MGMT_CONN_PARAM_SIZE { return None; }
        let mut params = Vec::with_capacity(n);
        for _ in 0..n { params.push(ConnParam::read(&mut r)?); }
        Some(LoadConnParam { params })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(2 + MGMT_CONN_PARAM_SIZE * self.params.len());
        w.u16(self.params.len() as u16);
        for p in &self.params { p.write(&mut w); }
        w.finish()
    }
}

/// `SET_BLOCKED_KEYS`: keys the stack must never use, whatever produced them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetBlockedKeys {
    pub keys: Vec<BlockedKeyInfo>,
}

impl SetBlockedKeys {
    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<SetBlockedKeys> {
        let mut r = Reader::new(buf);
        let n = r.u16()? as usize;
        if r.remaining() != n * MGMT_BLOCKED_KEY_INFO_SIZE { return None; }
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n { keys.push(BlockedKeyInfo::read(&mut r)?); }
        Some(SetBlockedKeys { keys })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(2 + MGMT_BLOCKED_KEY_INFO_SIZE * self.keys.len());
        w.u16(self.keys.len() as u16);
        for k in &self.keys { k.write(&mut w); }
        w.finish()
    }
}

/// `ADD_REMOTE_OOB_DATA`, in either of its two widths. The short form carries
/// only the legacy pairing hash and randomiser; the long form adds the secure
/// connections pair. The width itself is what says which was sent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AddRemoteOobData {
    pub addr: AddrInfo,
    pub hash192: [u8; MGMT_KEY_LEN],
    pub rand192: [u8; MGMT_KEY_LEN],
    /// Present only in the extended form.
    pub sc: Option<([u8; MGMT_KEY_LEN], [u8; MGMT_KEY_LEN])>,
}

impl AddRemoteOobData {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<AddRemoteOobData> {
        let mut r = Reader::new(buf);
        let addr = AddrInfo::read(&mut r)?;
        let hash192 = r.array::<MGMT_KEY_LEN>()?;
        let rand192 = r.array::<MGMT_KEY_LEN>()?;
        let sc = if r.done() {
            None
        } else {
            let h = r.array::<MGMT_KEY_LEN>()?;
            let n = r.array::<MGMT_KEY_LEN>()?;
            if !r.done() { return None; }
            Some((h, n))
        };
        Some(AddRemoteOobData { addr, hash192, rand192, sc })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let cap = if self.sc.is_some() { MGMT_ADD_REMOTE_OOB_EXT_DATA_SIZE }
                  else { MGMT_ADD_REMOTE_OOB_DATA_SIZE };
        let mut w = Writer::with_capacity(cap);
        self.addr.write(&mut w);
        w.bytes(&self.hash192);
        w.bytes(&self.rand192);
        if let Some((h, n)) = &self.sc {
            w.bytes(h);
            w.bytes(n);
        }
        w.finish()
    }
}

/// `READ_LOCAL_OOB_EXT_DATA`: which address type the caller wants data for.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ReadLocalOobExtData {
    pub addr_type: u8,
}

impl ReadLocalOobExtData {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<ReadLocalOobExtData> {
        if buf.len() != 1 { return None; }
        Some(ReadLocalOobExtData { addr_type: buf[0] })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { alloc::vec![self.addr_type] }
}

/// Width of a bare address command, for callers sizing a buffer.
pub const ADDR_ONLY_SIZE: usize = MGMT_ADDR_INFO_SIZE;

#[cfg(test)]
#[path = "../tests/cmd_keys.rs"]
mod tests;
