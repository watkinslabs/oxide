//! Controller-wide notifications, advertising, monitors and mesh.
//!
//! `NEW_SETTINGS` is a bare settings word — `Settings::encode_current` builds
//! it. `ADVERTISING_ADDED`/`ADVERTISING_REMOVED` are one instance byte, and the
//! two monitor events are one handle; `mgmt::rsp::conn` owns both shapes.

use alloc::vec::Vec;

use crate::mgmt::codec::{Reader, Writer};
use crate::mgmt::types::AddrInfo;
use crate::uapi::mgmt::limits::{
    MGMT_ADDR_INFO_SIZE, MGMT_DEV_CLASS_LEN, MGMT_MAX_NAME_LENGTH, MGMT_MAX_SHORT_NAME_LENGTH,
};

/// `CONTROLLER_ERROR`: the controller reported a fault of its own.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ControllerError {
    pub error_code: u8,
}

impl ControllerError {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { alloc::vec![self.error_code] }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<ControllerError> {
        if buf.len() != 1 { return None; }
        Some(ControllerError { error_code: buf[0] })
    }
}

/// `CLASS_OF_DEV_CHANGED`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ClassOfDevChanged {
    pub dev_class: [u8; MGMT_DEV_CLASS_LEN],
}

impl ClassOfDevChanged {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { self.dev_class.to_vec() }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<ClassOfDevChanged> {
        let mut r = Reader::new(buf);
        let dev_class = r.array::<MGMT_DEV_CLASS_LEN>()?;
        if !r.done() { return None; }
        Some(ClassOfDevChanged { dev_class })
    }
}

/// `LOCAL_NAME_CHANGED`: both slots, at the same widths the setter used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNameChanged {
    pub name: Vec<u8>,
    pub short_name: Vec<u8>,
}

fn slot_value(slot: &[u8]) -> Vec<u8> {
    let end = slot.iter().position(|b| *b == 0).unwrap_or(slot.len());
    slot[..end].to_vec()
}

impl LocalNameChanged {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_MAX_NAME_LENGTH + MGMT_MAX_SHORT_NAME_LENGTH);
        w.fixed(&self.name, MGMT_MAX_NAME_LENGTH);
        w.fixed(&self.short_name, MGMT_MAX_SHORT_NAME_LENGTH);
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<LocalNameChanged> {
        if buf.len() != MGMT_MAX_NAME_LENGTH + MGMT_MAX_SHORT_NAME_LENGTH { return None; }
        let (n, s) = buf.split_at(MGMT_MAX_NAME_LENGTH);
        Some(LocalNameChanged { name: slot_value(n), short_name: slot_value(s) })
    }
}

/// `EXT_INFO_CHANGED`: the identity, redelivered as EIR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtInfoChanged {
    pub eir: Vec<u8>,
}

impl ExtInfoChanged {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(2 + self.eir.len());
        w.u16(self.eir.len() as u16);
        w.bytes(&self.eir);
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<ExtInfoChanged> {
        let mut r = Reader::new(buf);
        let n = r.u16()? as usize;
        let eir = r.take(n)?.to_vec();
        if !r.done() { return None; }
        Some(ExtInfoChanged { eir })
    }
}

/// `PHY_CONFIGURATION_CHANGED`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PhyConfigurationChanged {
    pub selected_phys: u32,
}

impl PhyConfigurationChanged {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { self.selected_phys.to_le_bytes().to_vec() }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<PhyConfigurationChanged> {
        let mut r = Reader::new(buf);
        let selected_phys = r.u32()?;
        if !r.done() { return None; }
        Some(PhyConfigurationChanged { selected_phys })
    }
}

/// `CONTROLLER_SUSPEND`: what the controller was left doing across suspend.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ControllerSuspend {
    pub suspend_state: u8,
}

impl ControllerSuspend {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { alloc::vec![self.suspend_state] }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<ControllerSuspend> {
        if buf.len() != 1 { return None; }
        Some(ControllerSuspend { suspend_state: buf[0] })
    }
}

/// `CONTROLLER_RESUME`: what woke the host, and which peer did it when a peer
/// did. The address is all-zero for a wake that was not Bluetooth's doing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ControllerResume {
    pub wake_reason: u8,
    pub addr: AddrInfo,
}

impl ControllerResume {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(1 + MGMT_ADDR_INFO_SIZE);
        w.u8(self.wake_reason);
        self.addr.write(&mut w);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<ControllerResume> {
        let mut r = Reader::new(buf);
        let v = ControllerResume { wake_reason: r.u8()?, addr: AddrInfo::read(&mut r)? };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `ADV_MONITOR_DEVICE_FOUND`: a device report attributed to the monitor that
/// matched it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvMonitorDeviceFound {
    pub monitor_handle: u16,
    pub addr: AddrInfo,
    pub rssi: i8,
    pub flags: u32,
    pub eir: Vec<u8>,
}

impl AdvMonitorDeviceFound {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(2 + MGMT_ADDR_INFO_SIZE + 7 + self.eir.len());
        w.u16(self.monitor_handle);
        self.addr.write(&mut w);
        w.i8(self.rssi);
        w.u32(self.flags);
        w.u16(self.eir.len() as u16);
        w.bytes(&self.eir);
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<AdvMonitorDeviceFound> {
        let mut r = Reader::new(buf);
        let monitor_handle = r.u16()?;
        let addr = AddrInfo::read(&mut r)?;
        let rssi = r.i8()?;
        let flags = r.u32()?;
        let n = r.u16()? as usize;
        let eir = r.take(n)?.to_vec();
        if !r.done() { return None; }
        Some(AdvMonitorDeviceFound { monitor_handle, addr, rssi, flags, eir })
    }
}

/// `ADV_MONITOR_DEVICE_LOST`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AdvMonitorDeviceLost {
    pub monitor_handle: u16,
    pub addr: AddrInfo,
}

impl AdvMonitorDeviceLost {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(2 + MGMT_ADDR_INFO_SIZE);
        w.u16(self.monitor_handle);
        self.addr.write(&mut w);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<AdvMonitorDeviceLost> {
        let mut r = Reader::new(buf);
        let v = AdvMonitorDeviceLost {
            monitor_handle: r.u16()?, addr: AddrInfo::read(&mut r)?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `MESH_DEVICE_FOUND`: a mesh advertisement, with the instant it arrived so a
/// client can order reports that the stack batched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshDeviceFound {
    pub addr: AddrInfo,
    pub rssi: i8,
    pub instant: u64,
    pub flags: u32,
    pub eir: Vec<u8>,
}

impl MeshDeviceFound {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 15 + self.eir.len());
        self.addr.write(&mut w);
        w.i8(self.rssi);
        w.u64(self.instant);
        w.u32(self.flags);
        w.u16(self.eir.len() as u16);
        w.bytes(&self.eir);
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<MeshDeviceFound> {
        let mut r = Reader::new(buf);
        let addr = AddrInfo::read(&mut r)?;
        let rssi = r.i8()?;
        let instant = r.u64()?;
        let flags = r.u32()?;
        let n = r.u16()? as usize;
        let eir = r.take(n)?.to_vec();
        if !r.done() { return None; }
        Some(MeshDeviceFound { addr, rssi, instant, flags, eir })
    }
}

/// `MESH_PACKET_CMPLT`: the send that finished.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MeshPacketCmplt {
    pub handle: u8,
}

impl MeshPacketCmplt {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { alloc::vec![self.handle] }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<MeshPacketCmplt> {
        if buf.len() != 1 { return None; }
        Some(MeshPacketCmplt { handle: buf[0] })
    }
}

#[cfg(test)]
#[path = "../tests/event_misc.rs"]
mod tests;
