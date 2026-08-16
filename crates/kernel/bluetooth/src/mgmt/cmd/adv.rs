//! Advertising instances, extended advertising, monitors, mesh, and the
//! pass-through command.
//!
//! These are the variable-length commands: each declares how much data follows
//! and the declared amount must account for exactly the bytes present. The
//! table admits them on a minimum length; the exact accounting is here.

use alloc::vec::Vec;

use crate::mgmt::codec::{Reader, Writer};
use crate::mgmt::types::{AddrInfo, AdvPattern, AdvRssiThresholds};
use crate::uapi::mgmt::limits::{
    MGMT_ADV_PATTERN_SIZE, MGMT_ADV_RSSI_THRESHOLDS_SIZE, MGMT_UUID_LEN,
};
use crate::uapi::mgmt::op::{
    MGMT_ADD_ADVERTISING_SIZE, MGMT_ADD_EXT_ADV_DATA_SIZE, MGMT_ADD_EXT_ADV_PARAMS_MIN_SIZE,
    MGMT_MESH_SEND_SIZE, MGMT_SET_MESH_RECEIVER_SIZE,
};

/// `ADD_ADVERTISING`: the instance, its flags and timings, then the two data
/// blocks laid end to end.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddAdvertising {
    pub instance: u8,
    pub flags: u32,
    pub duration: u16,
    pub timeout: u16,
    pub adv_data: Vec<u8>,
    pub scan_rsp: Vec<u8>,
}

impl AddAdvertising {
    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<AddAdvertising> {
        let mut r = Reader::new(buf);
        let instance = r.u8()?;
        let flags = r.u32()?;
        let duration = r.u16()?;
        let timeout = r.u16()?;
        let adv_len = r.u8()? as usize;
        let rsp_len = r.u8()? as usize;
        if r.remaining() != adv_len + rsp_len { return None; }
        let adv_data = r.take(adv_len)?.to_vec();
        let scan_rsp = r.take(rsp_len)?.to_vec();
        Some(AddAdvertising { instance, flags, duration, timeout, adv_data, scan_rsp })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(
            MGMT_ADD_ADVERTISING_SIZE + self.adv_data.len() + self.scan_rsp.len());
        w.u8(self.instance);
        w.u32(self.flags);
        w.u16(self.duration);
        w.u16(self.timeout);
        w.u8(self.adv_data.len() as u8);
        w.u8(self.scan_rsp.len() as u8);
        w.bytes(&self.adv_data);
        w.bytes(&self.scan_rsp);
        w.finish()
    }
}

/// A command naming one advertising instance: `REMOVE_ADVERTISING`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Instance {
    pub instance: u8,
}

impl Instance {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<Instance> {
        if buf.len() != 1 { return None; }
        Some(Instance { instance: buf[0] })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { alloc::vec![self.instance] }
}

/// `GET_ADV_SIZE_INFO`: how much room the flags leave for data.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GetAdvSizeInfo {
    pub instance: u8,
    pub flags: u32,
}

impl GetAdvSizeInfo {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<GetAdvSizeInfo> {
        let mut r = Reader::new(buf);
        let instance = r.u8()?;
        let flags = r.u32()?;
        if !r.done() { return None; }
        Some(GetAdvSizeInfo { instance, flags })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(5);
        w.u8(self.instance);
        w.u32(self.flags);
        w.finish()
    }
}

/// `ADD_EXT_ADV_PARAMS`: the parameters half of extended advertising. Which
/// fields the caller actually set is carried in the flags word, so a value the
/// caller did not claim to set is ignored rather than applied.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AddExtAdvParams {
    pub instance: u8,
    pub flags: u32,
    pub duration: u16,
    pub timeout: u16,
    pub min_interval: u32,
    pub max_interval: u32,
    pub tx_power: i8,
}

impl AddExtAdvParams {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<AddExtAdvParams> {
        let mut r = Reader::new(buf);
        let v = AddExtAdvParams {
            instance: r.u8()?,
            flags: r.u32()?,
            duration: r.u16()?,
            timeout: r.u16()?,
            min_interval: r.u32()?,
            max_interval: r.u32()?,
            tx_power: r.i8()?,
        };
        if !r.done() { return None; }
        Some(v)
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADD_EXT_ADV_PARAMS_MIN_SIZE);
        w.u8(self.instance);
        w.u32(self.flags);
        w.u16(self.duration);
        w.u16(self.timeout);
        w.u32(self.min_interval);
        w.u32(self.max_interval);
        w.i8(self.tx_power);
        w.finish()
    }
}

/// `ADD_EXT_ADV_DATA`: the data half of extended advertising.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddExtAdvData {
    pub instance: u8,
    pub adv_data: Vec<u8>,
    pub scan_rsp: Vec<u8>,
}

impl AddExtAdvData {
    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<AddExtAdvData> {
        let mut r = Reader::new(buf);
        let instance = r.u8()?;
        let adv_len = r.u8()? as usize;
        let rsp_len = r.u8()? as usize;
        if r.remaining() != adv_len + rsp_len { return None; }
        let adv_data = r.take(adv_len)?.to_vec();
        let scan_rsp = r.take(rsp_len)?.to_vec();
        Some(AddExtAdvData { instance, adv_data, scan_rsp })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(
            MGMT_ADD_EXT_ADV_DATA_SIZE + self.adv_data.len() + self.scan_rsp.len());
        w.u8(self.instance);
        w.u8(self.adv_data.len() as u8);
        w.u8(self.scan_rsp.len() as u8);
        w.bytes(&self.adv_data);
        w.bytes(&self.scan_rsp);
        w.finish()
    }
}

/// `ADD_ADV_PATTERNS_MONITOR`, and the RSSI-thresholded variant. The thresholds
/// are absent in the plain form and the stack supplies its own defaults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddAdvPatternsMonitor {
    pub rssi: Option<AdvRssiThresholds>,
    pub patterns: Vec<AdvPattern>,
}

impl AddAdvPatternsMonitor {
    /// Decode the plain form. # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<AddAdvPatternsMonitor> {
        let mut r = Reader::new(buf);
        let patterns = read_patterns(&mut r)?;
        Some(AddAdvPatternsMonitor { rssi: None, patterns })
    }

    /// Decode the thresholded form. # C: O(n)
    pub fn decode_rssi(buf: &[u8]) -> Option<AddAdvPatternsMonitor> {
        let mut r = Reader::new(buf);
        let rssi = AdvRssiThresholds::read(&mut r)?;
        let patterns = read_patterns(&mut r)?;
        Some(AddAdvPatternsMonitor { rssi: Some(rssi), patterns })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let head = if self.rssi.is_some() { MGMT_ADV_RSSI_THRESHOLDS_SIZE } else { 0 };
        let mut w = Writer::with_capacity(
            head + 1 + MGMT_ADV_PATTERN_SIZE * self.patterns.len());
        if let Some(t) = &self.rssi { t.write(&mut w); }
        w.u8(self.patterns.len() as u8);
        for p in &self.patterns { p.write(&mut w); }
        w.finish()
    }

    /// Whether every pattern's matched window fits its value field. # C: O(n)
    pub fn windows_are_valid(&self) -> bool {
        !self.patterns.is_empty() && self.patterns.iter().all(AdvPattern::window_is_valid)
    }
}

fn read_patterns(r: &mut Reader) -> Option<Vec<AdvPattern>> {
    let n = r.u8()? as usize;
    if r.remaining() != n * MGMT_ADV_PATTERN_SIZE { return None; }
    let mut v = Vec::with_capacity(n);
    for _ in 0..n { v.push(AdvPattern::read(r)?); }
    Some(v)
}

/// `REMOVE_ADV_MONITOR`: the handle to drop, or zero to drop every one.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RemoveAdvMonitor {
    pub monitor_handle: u16,
}

impl RemoveAdvMonitor {
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<RemoveAdvMonitor> {
        let mut r = Reader::new(buf);
        let monitor_handle = r.u16()?;
        if !r.done() { return None; }
        Some(RemoveAdvMonitor { monitor_handle })
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> { self.monitor_handle.to_le_bytes().to_vec() }
}

/// `SET_EXP_FEATURE`: the feature's UUID and whatever parameter it defines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetExpFeature {
    pub uuid: [u8; MGMT_UUID_LEN],
    pub param: Vec<u8>,
}

impl SetExpFeature {
    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<SetExpFeature> {
        let mut r = Reader::new(buf);
        let uuid = r.array::<MGMT_UUID_LEN>()?;
        Some(SetExpFeature { uuid, param: r.rest().to_vec() })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_UUID_LEN + self.param.len());
        w.bytes(&self.uuid);
        w.bytes(&self.param);
        w.finish()
    }
}

/// `SET_MESH_RECEIVER`: the scan duty cycle, and which advertising data types
/// the receiver should report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetMeshReceiver {
    pub enable: u8,
    pub window: u16,
    pub period: u16,
    pub ad_types: Vec<u8>,
}

/// Scan window and period bounds a mesh receiver accepts, in units of 0.625 ms.
pub const MESH_SCAN_MIN: u16 = 0x0004;
pub const MESH_SCAN_MAX: u16 = 0x4000;

impl SetMeshReceiver {
    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<SetMeshReceiver> {
        let mut r = Reader::new(buf);
        let enable = r.u8()?;
        let window = r.u16()?;
        let period = r.u16()?;
        let n = r.u8()? as usize;
        if r.remaining() != n { return None; }
        let ad_types = r.take(n)?.to_vec();
        Some(SetMeshReceiver { enable, window, period, ad_types })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_SET_MESH_RECEIVER_SIZE + self.ad_types.len());
        w.u8(self.enable);
        w.u16(self.window);
        w.u16(self.period);
        w.u8(self.ad_types.len() as u8);
        w.bytes(&self.ad_types);
        w.finish()
    }

    /// Whether the duty cycle is one the controller can be asked for: both
    /// values in range, and the window no longer than the period it sits in. # C: O(1)
    pub fn duty_cycle_is_valid(&self) -> bool {
        let ok = |v: u16| (MESH_SCAN_MIN..=MESH_SCAN_MAX).contains(&v);
        self.enable <= 1 && ok(self.period) && ok(self.window) && self.window <= self.period
    }
}

/// `MESH_SEND`: one mesh advertisement, repeated `cnt` times.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshSend {
    pub addr: AddrInfo,
    pub instant: u64,
    pub delay: u16,
    pub cnt: u8,
    pub adv_data: Vec<u8>,
}

/// Largest advertising payload a mesh send may carry.
pub const MESH_MAX_ADV_DATA: usize = 31;

impl MeshSend {
    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<MeshSend> {
        let mut r = Reader::new(buf);
        let addr = AddrInfo::read(&mut r)?;
        let instant = r.u64()?;
        let delay = r.u16()?;
        let cnt = r.u8()?;
        let n = r.u8()? as usize;
        if r.remaining() != n { return None; }
        let adv_data = r.take(n)?.to_vec();
        Some(MeshSend { addr, instant, delay, cnt, adv_data })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_MESH_SEND_SIZE + self.adv_data.len());
        self.addr.write(&mut w);
        w.u64(self.instant);
        w.u16(self.delay);
        w.u8(self.cnt);
        w.u8(self.adv_data.len() as u8);
        w.bytes(&self.adv_data);
        w.finish()
    }

    /// An empty or over-long payload is refused rather than truncated. # C: O(1)
    pub fn data_len_is_valid(&self) -> bool {
        !self.adv_data.is_empty() && self.adv_data.len() <= MESH_MAX_ADV_DATA
    }
}

/// `HCI_CMD_SYNC`: run one controller command and wait for the named event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HciCmdSync {
    pub opcode: u16,
    pub event: u8,
    pub timeout: u8,
    pub params: Vec<u8>,
}

impl HciCmdSync {
    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<HciCmdSync> {
        let mut r = Reader::new(buf);
        let opcode = r.u16()?;
        let event = r.u8()?;
        let timeout = r.u8()?;
        let n = r.u16()? as usize;
        if r.remaining() != n { return None; }
        let params = r.take(n)?.to_vec();
        Some(HciCmdSync { opcode, event, timeout, params })
    }

    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(6 + self.params.len());
        w.u16(self.opcode);
        w.u8(self.event);
        w.u8(self.timeout);
        w.u16(self.params.len() as u16);
        w.bytes(&self.params);
        w.finish()
    }
}

#[cfg(test)]
#[path = "../tests/cmd_adv.rs"]
mod tests;
