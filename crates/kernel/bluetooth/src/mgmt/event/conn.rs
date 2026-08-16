//! Link lifecycle and pairing prompts.
//!
//! `USER_PASSKEY_REQUEST`, `DEVICE_BLOCKED`, `DEVICE_UNBLOCKED`,
//! `DEVICE_UNPAIRED` and `DEVICE_REMOVED` carry only an address record and use
//! `AddrInfo::encode`.

use alloc::vec::Vec;

use crate::mgmt::codec::{Reader, Writer};
use crate::mgmt::types::AddrInfo;
use crate::uapi::mgmt::limits::MGMT_ADDR_INFO_SIZE;

/// `DEVICE_CONNECTED`: the peer, why the link exists, and whatever the peer
/// advertised or answered with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceConnected {
    pub addr: AddrInfo,
    pub flags: u32,
    pub eir: Vec<u8>,
}

impl DeviceConnected {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 6 + self.eir.len());
        self.addr.write(&mut w);
        w.u32(self.flags);
        w.u16(self.eir.len() as u16);
        w.bytes(&self.eir);
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<DeviceConnected> {
        let mut r = Reader::new(buf);
        let addr = AddrInfo::read(&mut r)?;
        let flags = r.u32()?;
        let n = r.u16()? as usize;
        let eir = r.take(n)?.to_vec();
        if !r.done() { return None; }
        Some(DeviceConnected { addr, flags, eir })
    }
}

/// `DEVICE_DISCONNECTED`: who ended the link and why.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DeviceDisconnected {
    pub addr: AddrInfo,
    pub reason: u8,
}

impl DeviceDisconnected {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 1);
        self.addr.write(&mut w);
        w.u8(self.reason);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<DeviceDisconnected> {
        let mut r = Reader::new(buf);
        let v = DeviceDisconnected { addr: AddrInfo::read(&mut r)?, reason: r.u8()? };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `CONNECT_FAILED` and `AUTH_FAILED`: the peer and the status that explains it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AddrStatus {
    pub addr: AddrInfo,
    pub status: u8,
}

impl AddrStatus {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 1);
        self.addr.write(&mut w);
        w.u8(self.status);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<AddrStatus> {
        let mut r = Reader::new(buf);
        let v = AddrStatus { addr: AddrInfo::read(&mut r)?, status: r.u8()? };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `PIN_CODE_REQUEST`: whether the peer is asking for a 16-digit PIN.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PinCodeRequest {
    pub addr: AddrInfo,
    pub secure: u8,
}

impl PinCodeRequest {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 1);
        self.addr.write(&mut w);
        w.u8(self.secure);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<PinCodeRequest> {
        let mut r = Reader::new(buf);
        let v = PinCodeRequest { addr: AddrInfo::read(&mut r)?, secure: r.u8()? };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `USER_CONFIRM_REQUEST`: the value to show. The hint says whether the user is
/// being asked to compare it or merely to accept the pairing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UserConfirmRequest {
    pub addr: AddrInfo,
    pub confirm_hint: u8,
    pub value: u32,
}

impl UserConfirmRequest {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 5);
        self.addr.write(&mut w);
        w.u8(self.confirm_hint);
        w.u32(self.value);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<UserConfirmRequest> {
        let mut r = Reader::new(buf);
        let v = UserConfirmRequest {
            addr: AddrInfo::read(&mut r)?, confirm_hint: r.u8()?, value: r.u32()?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `PASSKEY_NOTIFY`: the passkey the user is to type on the peer, and how many
/// digits the peer has taken so far.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PasskeyNotify {
    pub addr: AddrInfo,
    pub passkey: u32,
    pub entered: u8,
}

impl PasskeyNotify {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 5);
        self.addr.write(&mut w);
        w.u32(self.passkey);
        w.u8(self.entered);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<PasskeyNotify> {
        let mut r = Reader::new(buf);
        let v = PasskeyNotify {
            addr: AddrInfo::read(&mut r)?, passkey: r.u32()?, entered: r.u8()?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `DEVICE_ADDED`: the peer and the action it was added with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DeviceAdded {
    pub addr: AddrInfo,
    pub action: u8,
}

impl DeviceAdded {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 1);
        self.addr.write(&mut w);
        w.u8(self.action);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<DeviceAdded> {
        let mut r = Reader::new(buf);
        let v = DeviceAdded { addr: AddrInfo::read(&mut r)?, action: r.u8()? };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `NEW_CONN_PARAM`: parameters a peer asked for, with a hint saying whether
/// they are worth remembering across reconnections.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NewConnParam {
    pub addr: AddrInfo,
    pub store_hint: u8,
    pub min_interval: u16,
    pub max_interval: u16,
    pub latency: u16,
    pub timeout: u16,
}

impl NewConnParam {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 9);
        self.addr.write(&mut w);
        w.u8(self.store_hint);
        w.u16(self.min_interval);
        w.u16(self.max_interval);
        w.u16(self.latency);
        w.u16(self.timeout);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<NewConnParam> {
        let mut r = Reader::new(buf);
        let v = NewConnParam {
            addr: AddrInfo::read(&mut r)?,
            store_hint: r.u8()?,
            min_interval: r.u16()?,
            max_interval: r.u16()?,
            latency: r.u16()?,
            timeout: r.u16()?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

#[cfg(test)]
#[path = "../tests/event_conn.rs"]
mod tests;
