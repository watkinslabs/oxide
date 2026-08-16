//! The device list and its per-device flags.
//!
//! `REMOVE_DEVICE`, `BLOCK_DEVICE`, `UNBLOCK_DEVICE`, `GET_DEVICE_FLAGS`,
//! `GET_CONN_INFO` and `GET_CLOCK_INFO` carry only an address record and decode
//! with `AddrInfo::decode`.

use alloc::vec::Vec;

use crate::mgmt::codec::{Reader, Writer};
use crate::mgmt::types::AddrInfo;
use crate::uapi::mgmt::flags::{
    MGMT_DEV_ACTION_ALLOW_CONNECT, MGMT_DEV_ACTION_AUTO_CONNECT,
    MGMT_DEV_ACTION_BACKGROUND_SCAN,
};
use crate::uapi::mgmt::limits::MGMT_ADDR_INFO_SIZE;
use crate::uapi::bt::BDADDR_BREDR;

/// `ADD_DEVICE`: the peer and what the stack should do about it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AddDevice {
    pub addr: AddrInfo,
    pub action: u8,
}

impl AddDevice {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<AddDevice> {
        let mut r = Reader::new(buf);
        let addr = AddrInfo::read(&mut r)?;
        let action = r.u8()?;
        if !r.done() { return None; }
        Some(AddDevice { addr, action })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 1);
        self.addr.write(&mut w);
        w.u8(self.action);
        w.finish()
    }

    /// Whether the action names one of the three behaviours. # C: O(1)
    pub fn action_is_valid(&self) -> bool {
        matches!(self.action,
            MGMT_DEV_ACTION_BACKGROUND_SCAN
            | MGMT_DEV_ACTION_ALLOW_CONNECT
            | MGMT_DEV_ACTION_AUTO_CONNECT)
    }

    /// Whether the combination is one the transport can honour. A BR/EDR entry
    /// exists to accept an incoming connection and nothing else, so the two
    /// scan-driven actions are meaningless on it and are refused rather than
    /// stored as an entry that never fires. # C: O(1)
    pub fn is_acceptable(&self) -> bool {
        if !self.addr.type_is_valid() || self.addr.bdaddr.is_any() { return false; }
        if !self.action_is_valid() { return false; }
        if self.addr.addr_type == BDADDR_BREDR && self.action != MGMT_DEV_ACTION_ALLOW_CONNECT {
            return false;
        }
        true
    }
}

/// `SET_DEVICE_FLAGS`: the flag word to store against a device already on the
/// list. Only flags the stack reports as supported for that device may be set.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetDeviceFlags {
    pub addr: AddrInfo,
    pub current_flags: u32,
}

impl SetDeviceFlags {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<SetDeviceFlags> {
        let mut r = Reader::new(buf);
        let addr = AddrInfo::read(&mut r)?;
        let current_flags = r.u32()?;
        if !r.done() { return None; }
        Some(SetDeviceFlags { addr, current_flags })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 4);
        self.addr.write(&mut w);
        w.u32(self.current_flags);
        w.finish()
    }

    /// Whether every requested flag is one the device supports. # C: O(1)
    pub fn within(&self, supported: u32) -> bool { self.current_flags & !supported == 0 }
}

#[cfg(test)]
#[path = "../tests/cmd_device.rs"]
mod tests;
