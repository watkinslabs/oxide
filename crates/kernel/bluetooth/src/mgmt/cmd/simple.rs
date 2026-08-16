//! Fixed-shape setters: the mode byte, the identity fields, and the small
//! parameter blocks. A name field is a fixed-width slot rather than a string,
//! so a short value is zero-padded and a long one cannot run into the field
//! that follows it.

use alloc::vec::Vec;

use crate::mgmt::codec::{Reader, Writer};
use crate::uapi::bt::BdAddr;
use crate::uapi::mgmt::limits::{
    MGMT_MAX_NAME_LENGTH, MGMT_MAX_SHORT_NAME_LENGTH, MGMT_KEY_LEN, MGMT_UUID_LEN,
};
use crate::uapi::mgmt::op::{MGMT_SET_LOCAL_NAME_SIZE, MGMT_SET_PRIVACY_SIZE};

/// A one-byte mode command. Any non-zero value turns the setting on; the
/// commands that accept only zero or one check that themselves.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Mode {
    pub val: u8,
}

impl Mode {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<Mode> {
        if buf.len() != 1 { return None; }
        Some(Mode { val: buf[0] })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { alloc::vec![self.val] }

    /// Whether the byte is one of the two values a boolean mode accepts. # C: O(1)
    pub fn is_boolean(&self) -> bool { self.val <= 1 }

    /// # C: O(1)
    pub fn on(&self) -> bool { self.val != 0 }
}

/// `SET_DISCOVERABLE`: the mode plus how long it lasts, in seconds. A timeout
/// only means anything with the mode on.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetDiscoverable {
    pub val: u8,
    pub timeout: u16,
}

impl SetDiscoverable {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<SetDiscoverable> {
        let mut r = Reader::new(buf);
        let val = r.u8()?;
        let timeout = r.u16()?;
        if !r.done() { return None; }
        Some(SetDiscoverable { val, timeout })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(3);
        w.u8(self.val);
        w.u16(self.timeout);
        w.finish()
    }
}

/// `SET_DEV_CLASS`: the major and minor device class. The service-class bits
/// are derived from the registered UUIDs, not sent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetDevClass {
    pub major: u8,
    pub minor: u8,
}

impl SetDevClass {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<SetDevClass> {
        if buf.len() != 2 { return None; }
        Some(SetDevClass { major: buf[0], minor: buf[1] })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { alloc::vec![self.major, self.minor] }
}

/// `SET_LOCAL_NAME`: both name slots, each fixed width and NUL-terminated
/// inside its slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetLocalName {
    pub name: Vec<u8>,
    pub short_name: Vec<u8>,
}

/// Everything up to the first NUL in a fixed-width slot. # C: O(n)
fn slot_value(slot: &[u8]) -> Vec<u8> {
    let end = slot.iter().position(|b| *b == 0).unwrap_or(slot.len());
    slot[..end].to_vec()
}

impl SetLocalName {
    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<SetLocalName> {
        if buf.len() != MGMT_SET_LOCAL_NAME_SIZE { return None; }
        let (n, s) = buf.split_at(MGMT_MAX_NAME_LENGTH);
        Some(SetLocalName { name: slot_value(n), short_name: slot_value(s) })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_SET_LOCAL_NAME_SIZE);
        w.fixed(&self.name, MGMT_MAX_NAME_LENGTH);
        w.fixed(&self.short_name, MGMT_MAX_SHORT_NAME_LENGTH);
        w.finish()
    }

    /// Whether both values fit their slots with room for the terminator. # C: O(1)
    pub fn fits(&self) -> bool {
        self.name.len() < MGMT_MAX_NAME_LENGTH
            && self.short_name.len() < MGMT_MAX_SHORT_NAME_LENGTH
    }
}

/// `ADD_UUID`: a service UUID and the class-of-device hint it contributes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AddUuid {
    pub uuid: [u8; MGMT_UUID_LEN],
    pub svc_hint: u8,
}

impl AddUuid {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<AddUuid> {
        let mut r = Reader::new(buf);
        let uuid = r.array::<MGMT_UUID_LEN>()?;
        let svc_hint = r.u8()?;
        if !r.done() { return None; }
        Some(AddUuid { uuid, svc_hint })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_UUID_LEN + 1);
        w.bytes(&self.uuid);
        w.u8(self.svc_hint);
        w.finish()
    }
}

/// `REMOVE_UUID`: the UUID to drop, or all-zero to drop every one.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RemoveUuid {
    pub uuid: [u8; MGMT_UUID_LEN],
}

impl RemoveUuid {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<RemoveUuid> {
        let mut r = Reader::new(buf);
        let uuid = r.array::<MGMT_UUID_LEN>()?;
        if !r.done() { return None; }
        Some(RemoveUuid { uuid })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { self.uuid.to_vec() }

    /// Whether this asks for every UUID to be dropped. # C: O(1)
    pub fn is_all(&self) -> bool { self.uuid == [0u8; MGMT_UUID_LEN] }
}

/// `SET_DEVICE_ID`: the device-identification record advertised in EIR.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetDeviceId {
    pub source: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

impl SetDeviceId {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<SetDeviceId> {
        let mut r = Reader::new(buf);
        let v = SetDeviceId {
            source: r.u16()?, vendor: r.u16()?, product: r.u16()?, version: r.u16()?,
        };
        if !r.done() { return None; }
        Some(v)
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(8);
        w.u16(self.source);
        w.u16(self.vendor);
        w.u16(self.product);
        w.u16(self.version);
        w.finish()
    }
}

/// A bare address command: `SET_STATIC_ADDRESS` and `SET_PUBLIC_ADDRESS`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetAddress {
    pub bdaddr: BdAddr,
}

impl SetAddress {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<SetAddress> {
        let mut r = Reader::new(buf);
        let bdaddr = r.addr()?;
        if !r.done() { return None; }
        Some(SetAddress { bdaddr })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { self.bdaddr.as_bytes().to_vec() }
}

/// `SET_SCAN_PARAMS`: the LE background-scan interval and window.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetScanParams {
    pub interval: u16,
    pub window: u16,
}

impl SetScanParams {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<SetScanParams> {
        let mut r = Reader::new(buf);
        let v = SetScanParams { interval: r.u16()?, window: r.u16()? };
        if !r.done() { return None; }
        Some(v)
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(4);
        w.u16(self.interval);
        w.u16(self.window);
        w.finish()
    }

    /// The window is the listening part of the interval and cannot exceed it. # C: O(1)
    pub fn is_consistent(&self) -> bool { self.window <= self.interval }
}

/// `SET_PRIVACY`: the mode plus the identity-resolving key to use with it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetPrivacy {
    pub privacy: u8,
    pub irk: [u8; MGMT_KEY_LEN],
}

impl SetPrivacy {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<SetPrivacy> {
        let mut r = Reader::new(buf);
        let privacy = r.u8()?;
        let irk = r.array::<MGMT_KEY_LEN>()?;
        if !r.done() { return None; }
        Some(SetPrivacy { privacy, irk })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_SET_PRIVACY_SIZE);
        w.u8(self.privacy);
        w.bytes(&self.irk);
        w.finish()
    }
}

/// A one-word command: `SET_APPEARANCE` takes the appearance value.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetAppearance {
    pub appearance: u16,
}

impl SetAppearance {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<SetAppearance> {
        let mut r = Reader::new(buf);
        let appearance = r.u16()?;
        if !r.done() { return None; }
        Some(SetAppearance { appearance })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { self.appearance.to_le_bytes().to_vec() }
}

/// `SET_PHY_CONFIGURATION`: the PHY bits to select.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetPhyConfiguration {
    pub selected_phys: u32,
}

impl SetPhyConfiguration {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<SetPhyConfiguration> {
        let mut r = Reader::new(buf);
        let selected_phys = r.u32()?;
        if !r.done() { return None; }
        Some(SetPhyConfiguration { selected_phys })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { self.selected_phys.to_le_bytes().to_vec() }
}

/// `SET_IO_CAPABILITY`: the local input and output capability pairing uses to
/// pick a method.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetIoCapability {
    pub io_capability: u8,
}

impl SetIoCapability {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<SetIoCapability> {
        if buf.len() != 1 { return None; }
        Some(SetIoCapability { io_capability: buf[0] })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { alloc::vec![self.io_capability] }

    /// Whether the operand names a real capability. # C: O(1)
    pub fn is_valid(&self) -> bool {
        self.io_capability <= crate::uapi::mgmt::flags::MGMT_IO_CAPABILITY_MAX
    }
}

#[cfg(test)]
#[path = "../tests/cmd_simple.rs"]
mod tests;
