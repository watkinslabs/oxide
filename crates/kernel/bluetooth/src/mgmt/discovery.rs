//! Discovery: which transports a scan may use, and the two records a scan
//! produces.
//!
//! The type byte is a bitmask over address types, not an enumeration, so only
//! three of its values mean anything. Each demands the matching transport be
//! both present in the hardware and switched on, and the two failures are
//! distinct: absent hardware is unsupported, a disabled transport is refused.

use alloc::vec::Vec;

use super::codec::{Reader, Writer};
use super::types::AddrInfo;
use crate::uapi::mgmt::flags::{DISCOV_TYPE_BREDR, DISCOV_TYPE_INTERLEAVED, DISCOV_TYPE_LE};
use crate::uapi::mgmt::limits::MGMT_UUID_LEN;
use crate::uapi::mgmt::op::MGMT_START_SERVICE_DISCOVERY_SIZE;
use crate::uapi::mgmt::status::{
    MGMT_STATUS_INVALID_PARAMS, MGMT_STATUS_NOT_SUPPORTED, MGMT_STATUS_REJECTED,
    MGMT_STATUS_SUCCESS,
};

/// What a controller can and will do on one transport.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TransportSupport {
    /// The hardware has the radio.
    pub capable: bool,
    /// The transport is switched on.
    pub enabled: bool,
}

impl TransportSupport {
    /// # C: O(1)
    pub fn new(capable: bool, enabled: bool) -> TransportSupport {
        TransportSupport { capable, enabled }
    }

    /// Absent hardware and a disabled transport are different answers. # C: O(1)
    pub fn status(&self) -> u8 {
        if !self.capable { MGMT_STATUS_NOT_SUPPORTED }
        else if !self.enabled { MGMT_STATUS_REJECTED }
        else { MGMT_STATUS_SUCCESS }
    }
}

/// Whether a discovery type may run, and why not when it may not. An
/// interleaved scan needs BOTH transports, and reports the LE failure first. # C: O(1)
pub fn discovery_type_status(
    disc_type: u8,
    bredr: TransportSupport,
    le: TransportSupport,
) -> u8 {
    match disc_type {
        DISCOV_TYPE_LE => le.status(),
        DISCOV_TYPE_INTERLEAVED => {
            let s = le.status();
            if s != MGMT_STATUS_SUCCESS { return s; }
            bredr.status()
        }
        DISCOV_TYPE_BREDR => bredr.status(),
        _ => MGMT_STATUS_INVALID_PARAMS,
    }
}

/// `START_SERVICE_DISCOVERY` parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceDiscovery {
    pub disc_type: u8,
    pub rssi: i8,
    pub uuids: Vec<[u8; MGMT_UUID_LEN]>,
}

/// Largest UUID count the length field can describe.
pub const MAX_SERVICE_UUID_COUNT: usize =
    (u16::MAX as usize - MGMT_START_SERVICE_DISCOVERY_SIZE) / MGMT_UUID_LEN;

impl ServiceDiscovery {
    /// Decode the command. The declared UUID count must account for exactly the
    /// bytes present: a count that overstates reads nothing extra, and one that
    /// understates would leave a tail nobody parses. # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<ServiceDiscovery> {
        let mut r = Reader::new(buf);
        let disc_type = r.u8()?;
        let rssi = r.i8()?;
        let count = r.u16()? as usize;
        if count > MAX_SERVICE_UUID_COUNT { return None; }
        let mut uuids = Vec::with_capacity(count);
        for _ in 0..count { uuids.push(r.array::<MGMT_UUID_LEN>()?); }
        if !r.done() { return None; }
        Some(ServiceDiscovery { disc_type, rssi, uuids })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(
            MGMT_START_SERVICE_DISCOVERY_SIZE + MGMT_UUID_LEN * self.uuids.len());
        w.u8(self.disc_type);
        w.i8(self.rssi);
        w.u16(self.uuids.len() as u16);
        for u in &self.uuids { w.bytes(u); }
        w.finish()
    }
}

/// `DISCOVERING` event: which scan, and whether it is now running.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Discovering {
    pub disc_type: u8,
    pub discovering: bool,
}

impl Discovering {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(2);
        w.u8(self.disc_type);
        w.u8(u8::from(self.discovering));
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<Discovering> {
        let mut r = Reader::new(buf);
        let disc_type = r.u8()?;
        let discovering = r.u8()? != 0;
        if !r.done() { return None; }
        Some(Discovering { disc_type, discovering })
    }
}

/// `DEVICE_FOUND` event: one report, with the advertisement or inquiry result
/// that produced it carried verbatim as EIR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceFound {
    pub addr: AddrInfo,
    pub rssi: i8,
    pub flags: u32,
    pub eir: Vec<u8>,
}

impl DeviceFound {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(14 + self.eir.len());
        self.addr.write(&mut w);
        w.i8(self.rssi);
        w.u32(self.flags);
        w.u16(self.eir.len() as u16);
        w.bytes(&self.eir);
        w.finish()
    }

    /// Decode a report. The declared EIR length must match the bytes that
    /// follow it exactly. # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<DeviceFound> {
        let mut r = Reader::new(buf);
        let addr = AddrInfo::read(&mut r)?;
        let rssi = r.i8()?;
        let flags = r.u32()?;
        let eir_len = r.u16()? as usize;
        let eir = r.take(eir_len)?.to_vec();
        if !r.done() { return None; }
        Some(DeviceFound { addr, rssi, flags, eir })
    }
}

#[cfg(test)]
#[path = "tests/discovery.rs"]
mod tests;
