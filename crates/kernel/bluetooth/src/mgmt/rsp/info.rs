//! Controller descriptions and capability reads.

use alloc::vec::Vec;

use crate::mgmt::codec::{Reader, Writer};
use crate::uapi::bt::BdAddr;
use crate::uapi::mgmt::limits::{
    MGMT_DEV_CLASS_LEN, MGMT_KEY_LEN, MGMT_MAX_NAME_LENGTH, MGMT_MAX_SHORT_NAME_LENGTH,
    MGMT_MESH_HANDLES_MAX, MGMT_UUID_LEN,
};

/// `READ_VERSION`: the interface this stack speaks.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ReadVersion {
    pub version: u8,
    pub revision: u16,
}

impl ReadVersion {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(3);
        w.u8(self.version);
        w.u16(self.revision);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<ReadVersion> {
        let mut r = Reader::new(buf);
        let v = ReadVersion { version: r.u8()?, revision: r.u16()? };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `READ_INFO`: the whole description of one controller. Both name slots are
/// fixed width, so a client always reads the same offsets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadInfo {
    pub bdaddr: BdAddr,
    pub version: u8,
    pub manufacturer: u16,
    pub supported_settings: u32,
    pub current_settings: u32,
    pub dev_class: [u8; MGMT_DEV_CLASS_LEN],
    pub name: Vec<u8>,
    pub short_name: Vec<u8>,
}

/// Width of the `READ_INFO` response.
pub const READ_INFO_RSP_SIZE: usize =
    6 + 1 + 2 + 4 + 4 + MGMT_DEV_CLASS_LEN + MGMT_MAX_NAME_LENGTH + MGMT_MAX_SHORT_NAME_LENGTH;

fn slot_value(slot: &[u8]) -> Vec<u8> {
    let end = slot.iter().position(|b| *b == 0).unwrap_or(slot.len());
    slot[..end].to_vec()
}

impl ReadInfo {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(READ_INFO_RSP_SIZE);
        w.addr(&self.bdaddr);
        w.u8(self.version);
        w.u16(self.manufacturer);
        w.u32(self.supported_settings);
        w.u32(self.current_settings);
        w.bytes(&self.dev_class);
        w.fixed(&self.name, MGMT_MAX_NAME_LENGTH);
        w.fixed(&self.short_name, MGMT_MAX_SHORT_NAME_LENGTH);
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<ReadInfo> {
        let mut r = Reader::new(buf);
        let bdaddr = r.addr()?;
        let version = r.u8()?;
        let manufacturer = r.u16()?;
        let supported_settings = r.u32()?;
        let current_settings = r.u32()?;
        let dev_class = r.array::<MGMT_DEV_CLASS_LEN>()?;
        let name = slot_value(r.take(MGMT_MAX_NAME_LENGTH)?);
        let short_name = slot_value(r.take(MGMT_MAX_SHORT_NAME_LENGTH)?);
        if !r.done() { return None; }
        Some(ReadInfo {
            bdaddr, version, manufacturer, supported_settings, current_settings,
            dev_class, name, short_name,
        })
    }
}

/// `READ_EXT_INFO`: the same identity, with the name and class delivered as EIR
/// rather than as fixed slots, so new fields can be added without moving any.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadExtInfo {
    pub bdaddr: BdAddr,
    pub version: u8,
    pub manufacturer: u16,
    pub supported_settings: u32,
    pub current_settings: u32,
    pub eir: Vec<u8>,
}

impl ReadExtInfo {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(19 + self.eir.len());
        w.addr(&self.bdaddr);
        w.u8(self.version);
        w.u16(self.manufacturer);
        w.u32(self.supported_settings);
        w.u32(self.current_settings);
        w.u16(self.eir.len() as u16);
        w.bytes(&self.eir);
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<ReadExtInfo> {
        let mut r = Reader::new(buf);
        let bdaddr = r.addr()?;
        let version = r.u8()?;
        let manufacturer = r.u16()?;
        let supported_settings = r.u32()?;
        let current_settings = r.u32()?;
        let n = r.u16()? as usize;
        let eir = r.take(n)?.to_vec();
        if !r.done() { return None; }
        Some(ReadExtInfo {
            bdaddr, version, manufacturer, supported_settings, current_settings, eir,
        })
    }
}

/// `READ_CONFIG_INFO`: which configuration options exist and which are still
/// missing before the controller can be used.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ReadConfigInfo {
    pub manufacturer: u16,
    pub supported_options: u32,
    pub missing_options: u32,
}

impl ReadConfigInfo {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(10);
        w.u16(self.manufacturer);
        w.u32(self.supported_options);
        w.u32(self.missing_options);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<ReadConfigInfo> {
        let mut r = Reader::new(buf);
        let v = ReadConfigInfo {
            manufacturer: r.u16()?, supported_options: r.u32()?, missing_options: r.u32()?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

/// One capability record: a 16-bit type, a length, and that many value bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tlv {
    pub tlv_type: u16,
    pub value: Vec<u8>,
}

impl Tlv {
    /// # C: O(n)
    pub fn write(&self, w: &mut Writer) {
        w.u16(self.tlv_type);
        w.u8(self.value.len() as u8);
        w.bytes(&self.value);
    }

    /// # C: O(n)
    pub fn read(r: &mut Reader) -> Option<Tlv> {
        let tlv_type = r.u16()?;
        let n = r.u8()? as usize;
        Some(Tlv { tlv_type, value: r.take(n)?.to_vec() })
    }
}

/// `READ_CONTROLLER_CAP`: a length-prefixed run of capability records.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ReadControllerCap {
    pub caps: Vec<Tlv>,
}

impl ReadControllerCap {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Writer::new();
        for t in &self.caps { t.write(&mut body); }
        let body = body.finish();
        let mut w = Writer::with_capacity(2 + body.len());
        w.u16(body.len() as u16);
        w.bytes(&body);
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<ReadControllerCap> {
        let mut r = Reader::new(buf);
        let n = r.u16()? as usize;
        let body = r.take(n)?;
        if !r.done() { return None; }
        let mut br = Reader::new(body);
        let mut caps = Vec::new();
        while !br.done() { caps.push(Tlv::read(&mut br)?); }
        Some(ReadControllerCap { caps })
    }
}

/// `READ_ADV_FEATURES`: what advertising the controller can do, and which
/// instances are configured right now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadAdvFeatures {
    pub supported_flags: u32,
    pub max_adv_data_len: u8,
    pub max_scan_rsp_len: u8,
    pub max_instances: u8,
    pub instances: Vec<u8>,
}

impl ReadAdvFeatures {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(8 + self.instances.len());
        w.u32(self.supported_flags);
        w.u8(self.max_adv_data_len);
        w.u8(self.max_scan_rsp_len);
        w.u8(self.max_instances);
        w.u8(self.instances.len() as u8);
        w.bytes(&self.instances);
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<ReadAdvFeatures> {
        let mut r = Reader::new(buf);
        let supported_flags = r.u32()?;
        let max_adv_data_len = r.u8()?;
        let max_scan_rsp_len = r.u8()?;
        let max_instances = r.u8()?;
        let n = r.u8()? as usize;
        let instances = r.take(n)?.to_vec();
        if !r.done() { return None; }
        Some(ReadAdvFeatures {
            supported_flags, max_adv_data_len, max_scan_rsp_len, max_instances, instances,
        })
    }
}

/// `GET_PHY_CONFIGURATION`: what the controller has, what it will let the host
/// choose, and what is chosen.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PhyConfiguration {
    pub supported_phys: u32,
    pub configurable_phys: u32,
    pub selected_phys: u32,
}

impl PhyConfiguration {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(12);
        w.u32(self.supported_phys);
        w.u32(self.configurable_phys);
        w.u32(self.selected_phys);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<PhyConfiguration> {
        let mut r = Reader::new(buf);
        let v = PhyConfiguration {
            supported_phys: r.u32()?, configurable_phys: r.u32()?, selected_phys: r.u32()?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

/// `READ_ADV_MONITOR_FEATURES`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadAdvMonitorFeatures {
    pub supported_features: u32,
    pub enabled_features: u32,
    pub max_num_handles: u16,
    pub max_num_patterns: u8,
    pub handles: Vec<u16>,
}

impl ReadAdvMonitorFeatures {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(13 + 2 * self.handles.len());
        w.u32(self.supported_features);
        w.u32(self.enabled_features);
        w.u16(self.max_num_handles);
        w.u8(self.max_num_patterns);
        w.u16(self.handles.len() as u16);
        for h in &self.handles { w.u16(*h); }
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<ReadAdvMonitorFeatures> {
        let mut r = Reader::new(buf);
        let supported_features = r.u32()?;
        let enabled_features = r.u32()?;
        let max_num_handles = r.u16()?;
        let max_num_patterns = r.u8()?;
        let n = r.u16()? as usize;
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n { handles.push(r.u16()?); }
        if !r.done() { return None; }
        Some(ReadAdvMonitorFeatures {
            supported_features, enabled_features, max_num_handles, max_num_patterns, handles,
        })
    }
}

/// `MESH_READ_FEATURES`: the handle slots, always reported at full width.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MeshReadFeatures {
    pub index: u16,
    pub max_handles: u8,
    pub used_handles: u8,
    pub handles: [u8; MGMT_MESH_HANDLES_MAX],
}

impl MeshReadFeatures {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(4 + MGMT_MESH_HANDLES_MAX);
        w.u16(self.index);
        w.u8(self.max_handles);
        w.u8(self.used_handles);
        w.bytes(&self.handles);
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<MeshReadFeatures> {
        let mut r = Reader::new(buf);
        let v = MeshReadFeatures {
            index: r.u16()?,
            max_handles: r.u8()?,
            used_handles: r.u8()?,
            handles: r.array::<MGMT_MESH_HANDLES_MAX>()?,
        };
        if !r.done() { return None; }
        Some(v)
    }
}

/// One experimental feature: its UUID and the flags that say whether it exists,
/// whether it is on, and whether it may be turned on.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExpFeature {
    pub uuid: [u8; MGMT_UUID_LEN],
    pub flags: u32,
}

/// `READ_EXP_FEATURES_INFO`.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ReadExpFeaturesInfo {
    pub features: Vec<ExpFeature>,
}

impl ReadExpFeaturesInfo {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(2 + 20 * self.features.len());
        w.u16(self.features.len() as u16);
        for f in &self.features {
            w.bytes(&f.uuid);
            w.u32(f.flags);
        }
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<ReadExpFeaturesInfo> {
        let mut r = Reader::new(buf);
        let n = r.u16()? as usize;
        let mut features = Vec::with_capacity(n);
        for _ in 0..n {
            features.push(ExpFeature { uuid: r.array::<MGMT_UUID_LEN>()?, flags: r.u32()? });
        }
        if !r.done() { return None; }
        Some(ReadExpFeaturesInfo { features })
    }
}

/// `READ_LOCAL_OOB_DATA`: the legacy hash and randomiser, and the secure
/// connections pair when the controller has one.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ReadLocalOobData {
    pub hash192: [u8; MGMT_KEY_LEN],
    pub rand192: [u8; MGMT_KEY_LEN],
    pub sc: Option<([u8; MGMT_KEY_LEN], [u8; MGMT_KEY_LEN])>,
}

impl ReadLocalOobData {
    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(4 * MGMT_KEY_LEN);
        w.bytes(&self.hash192);
        w.bytes(&self.rand192);
        if let Some((h, n)) = &self.sc {
            w.bytes(h);
            w.bytes(n);
        }
        w.finish()
    }

    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<ReadLocalOobData> {
        let mut r = Reader::new(buf);
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
        Some(ReadLocalOobData { hash192, rand192, sc })
    }
}

/// `READ_LOCAL_OOB_EXT_DATA`, and the update event that carries the same shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalOobExtData {
    pub addr_type: u8,
    pub eir: Vec<u8>,
}

impl LocalOobExtData {
    /// # C: O(n)
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(3 + self.eir.len());
        w.u8(self.addr_type);
        w.u16(self.eir.len() as u16);
        w.bytes(&self.eir);
        w.finish()
    }

    /// # C: O(n)
    pub fn decode(buf: &[u8]) -> Option<LocalOobExtData> {
        let mut r = Reader::new(buf);
        let addr_type = r.u8()?;
        let n = r.u16()? as usize;
        let eir = r.take(n)?.to_vec();
        if !r.done() { return None; }
        Some(LocalOobExtData { addr_type, eir })
    }
}

#[cfg(test)]
#[path = "../tests/rsp_info.rs"]
mod tests;
