//! Bonding, and the replies that answer a pairing prompt.
//!
//! The negative replies and the cancel carry only the address — decode those
//! with `AddrInfo::decode`, which is the same record. Only the commands that
//! carry something beyond the address need a type of their own.

use alloc::vec::Vec;

use crate::mgmt::codec::{Reader, Writer};
use crate::mgmt::types::AddrInfo;
use crate::uapi::mgmt::limits::{MGMT_ADDR_INFO_SIZE, MGMT_PIN_LEN};
use crate::uapi::mgmt::op::MGMT_PIN_CODE_REPLY_SIZE;

/// `PAIR_DEVICE`: the peer and the local capability to pair with. The capability
/// is per-command rather than per-controller so one client can pair with a
/// prompt while another pairs without.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PairDevice {
    pub addr: AddrInfo,
    pub io_cap: u8,
}

impl PairDevice {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<PairDevice> {
        let mut r = Reader::new(buf);
        let addr = AddrInfo::read(&mut r)?;
        let io_cap = r.u8()?;
        if !r.done() { return None; }
        Some(PairDevice { addr, io_cap })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 1);
        self.addr.write(&mut w);
        w.u8(self.io_cap);
        w.finish()
    }
}

/// `UNPAIR_DEVICE`: the peer, and whether to tear down a live link to it as
/// well as forgetting its keys.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UnpairDevice {
    pub addr: AddrInfo,
    pub disconnect: u8,
}

impl UnpairDevice {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<UnpairDevice> {
        let mut r = Reader::new(buf);
        let addr = AddrInfo::read(&mut r)?;
        let disconnect = r.u8()?;
        if !r.done() { return None; }
        Some(UnpairDevice { addr, disconnect })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 1);
        self.addr.write(&mut w);
        w.u8(self.disconnect);
        w.finish()
    }
}

/// `PIN_CODE_REPLY`: the PIN, in a fixed-width slot with its true length beside
/// it. The length is authoritative; the bytes past it are padding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PinCodeReply {
    pub addr: AddrInfo,
    pub pin_len: u8,
    pub pin_code: [u8; MGMT_PIN_LEN],
}

impl PinCodeReply {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<PinCodeReply> {
        let mut r = Reader::new(buf);
        let addr = AddrInfo::read(&mut r)?;
        let pin_len = r.u8()?;
        let pin_code = r.array::<MGMT_PIN_LEN>()?;
        if !r.done() { return None; }
        Some(PinCodeReply { addr, pin_len, pin_code })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_PIN_CODE_REPLY_SIZE);
        self.addr.write(&mut w);
        w.u8(self.pin_len);
        w.bytes(&self.pin_code);
        w.finish()
    }

    /// A declared length past the slot would read padding as PIN material. # C: O(1)
    pub fn len_is_valid(&self) -> bool {
        self.pin_len as usize > 0 && self.pin_len as usize <= MGMT_PIN_LEN
    }

    /// The PIN itself, or `None` when the declared length does not fit. # C: O(1)
    pub fn pin(&self) -> Option<&[u8]> {
        if !self.len_is_valid() { return None; }
        Some(&self.pin_code[..self.pin_len as usize])
    }
}

/// `USER_PASSKEY_REPLY`: the six-digit value the user entered.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UserPasskeyReply {
    pub addr: AddrInfo,
    pub passkey: u32,
}

impl UserPasskeyReply {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<UserPasskeyReply> {
        let mut r = Reader::new(buf);
        let addr = AddrInfo::read(&mut r)?;
        let passkey = r.u32()?;
        if !r.done() { return None; }
        Some(UserPasskeyReply { addr, passkey })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 4);
        self.addr.write(&mut w);
        w.u32(self.passkey);
        w.finish()
    }
}

/// `CONFIRM_NAME`: whether the client already knows the peer's name, which is
/// what decides whether the stack asks the peer for it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConfirmName {
    pub addr: AddrInfo,
    pub name_known: u8,
}

impl ConfirmName {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<ConfirmName> {
        let mut r = Reader::new(buf);
        let addr = AddrInfo::read(&mut r)?;
        let name_known = r.u8()?;
        if !r.done() { return None; }
        Some(ConfirmName { addr, name_known })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 1);
        self.addr.write(&mut w);
        w.u8(self.name_known);
        w.finish()
    }
}

#[cfg(test)]
#[path = "../tests/cmd_pairing.rs"]
mod tests;
