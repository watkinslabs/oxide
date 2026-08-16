//! Per-peer answers and the small handle-or-instance replies.

use alloc::vec::Vec;

use crate::mgmt::codec::{Reader, Writer};
use crate::mgmt::types::AddrInfo;
use crate::uapi::mgmt::limits::{MGMT_ADDR_INFO_SIZE, MGMT_UUID_LEN};

/// `GET_CONNECTIONS`: every live link, as address records.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct GetConnections {
    pub conns: Vec<AddrInfo>,
}

impl GetConnections {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(2 + MGMT_ADDR_INFO_SIZE * self.conns.len());
        w.u16(self.conns.len() as u16);
        for c in &self.conns { c.write(&mut w); }
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<GetConnections> {
        let mut r = Reader::new(buf);
        let n = r.u16()? as usize;
        if r.remaining() != n * MGMT_ADDR_INFO_SIZE { return None; }
        let mut conns = Vec::with_capacity(n);
        for _ in 0..n { conns.push(AddrInfo::read(&mut r)?); }
        Some(GetConnections { conns })
    }
}

/// `GET_CONN_INFO`: the signal strength of one link and the power it is driven
/// at, alongside the most the controller could drive it at.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GetConnInfo {
    pub addr: AddrInfo,
    pub rssi: i8,
    pub tx_power: i8,
    pub max_tx_power: i8,
}

impl GetConnInfo {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 3);
        self.addr.write(&mut w);
        w.i8(self.rssi);
        w.i8(self.tx_power);
        w.i8(self.max_tx_power);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<GetConnInfo> {
        let mut r = Reader::new(buf);
        let v = GetConnInfo {
            addr: AddrInfo::read(&mut r)?,
            rssi: r.i8()?,
            tx_power: r.i8()?,
            max_tx_power: r.i8()?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `GET_CLOCK_INFO`: the local clock, and the piconet clock when the address
/// names a live link rather than the controller itself.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GetClockInfo {
    pub addr: AddrInfo,
    pub local_clock: u32,
    pub piconet_clock: u32,
    pub accuracy: u16,
}

impl GetClockInfo {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 10);
        self.addr.write(&mut w);
        w.u32(self.local_clock);
        w.u32(self.piconet_clock);
        w.u16(self.accuracy);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<GetClockInfo> {
        let mut r = Reader::new(buf);
        let v = GetClockInfo {
            addr: AddrInfo::read(&mut r)?,
            local_clock: r.u32()?,
            piconet_clock: r.u32()?,
            accuracy: r.u16()?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `GET_DEVICE_FLAGS`, and the change event that reports the same three fields.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DeviceFlags {
    pub addr: AddrInfo,
    pub supported_flags: u32,
    pub current_flags: u32,
}

impl DeviceFlags {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE + 8);
        self.addr.write(&mut w);
        w.u32(self.supported_flags);
        w.u32(self.current_flags);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<DeviceFlags> {
        let mut r = Reader::new(buf);
        let v = DeviceFlags {
            addr: AddrInfo::read(&mut r)?,
            supported_flags: r.u32()?,
            current_flags: r.u32()?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

/// A response that is one advertising instance number.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InstanceRsp {
    pub instance: u8,
}

impl InstanceRsp {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { alloc::vec![self.instance] }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<InstanceRsp> {
        if buf.len() != 1 { return None; }
        Some(InstanceRsp { instance: buf[0] })
    }
}

/// `GET_ADV_SIZE_INFO`: how many data bytes the requested flags leave free.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AdvSizeInfo {
    pub instance: u8,
    pub flags: u32,
    pub max_adv_data_len: u8,
    pub max_scan_rsp_len: u8,
}

impl AdvSizeInfo {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(7);
        w.u8(self.instance);
        w.u32(self.flags);
        w.u8(self.max_adv_data_len);
        w.u8(self.max_scan_rsp_len);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<AdvSizeInfo> {
        let mut r = Reader::new(buf);
        let v = AdvSizeInfo {
            instance: r.u8()?,
            flags: r.u32()?,
            max_adv_data_len: r.u8()?,
            max_scan_rsp_len: r.u8()?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `ADD_EXT_ADV_PARAMS`: the power the controller settled on and the room that
/// leaves for data.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExtAdvParamsRsp {
    pub instance: u8,
    pub tx_power: i8,
    pub max_adv_data_len: u8,
    pub max_scan_rsp_len: u8,
}

impl ExtAdvParamsRsp {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(4);
        w.u8(self.instance);
        w.i8(self.tx_power);
        w.u8(self.max_adv_data_len);
        w.u8(self.max_scan_rsp_len);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<ExtAdvParamsRsp> {
        let mut r = Reader::new(buf);
        let v = ExtAdvParamsRsp {
            instance: r.u8()?,
            tx_power: r.i8()?,
            max_adv_data_len: r.u8()?,
            max_scan_rsp_len: r.u8()?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

/// A response that is one advertising-monitor handle, shared by the add and
/// remove commands and by the two monitor events.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MonitorHandle {
    pub monitor_handle: u16,
}

impl MonitorHandle {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { self.monitor_handle.to_le_bytes().to_vec() }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<MonitorHandle> {
        let mut r = Reader::new(buf);
        let monitor_handle = r.u16()?;
        if !r.done() { return None; }
        Some(MonitorHandle { monitor_handle })
    }
}

/// `SET_EXP_FEATURE`, and the change event: the feature and its new flags.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExpFeatureState {
    pub uuid: [u8; MGMT_UUID_LEN],
    pub flags: u32,
}

impl ExpFeatureState {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_UUID_LEN + 4);
        w.bytes(&self.uuid);
        w.u32(self.flags);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<ExpFeatureState> {
        let mut r = Reader::new(buf);
        let v = ExpFeatureState { uuid: r.array::<MGMT_UUID_LEN>()?, flags: r.u32()? };
        if !r.done() { return None; }
        Some(v)
    }
}

#[cfg(test)]
#[path = "../tests/rsp_conn.rs"]
mod tests;
