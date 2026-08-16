//! Records that appear inside more than one command or event: the address
//! pair every device-directed message starts with, the four key kinds the load
//! commands carry, connection parameters, blocked keys and monitor patterns.
//!
//! A peer is the address AND its type; the two are never separated, which is
//! why `AddrInfo` is one value rather than two fields at each call site.

use super::codec::{Reader, Writer};
use crate::uapi::bt::{BdAddr, BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM};
use crate::uapi::mgmt::limits::{
    MGMT_ADDR_INFO_SIZE, MGMT_ADV_PATTERN_VALUE_LEN, MGMT_KEY_LEN,
};

/// Address together with the address type it was seen on.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct AddrInfo {
    pub bdaddr: BdAddr,
    pub addr_type: u8,
}

impl AddrInfo {
    /// # C: O(1)
    pub fn new(bdaddr: BdAddr, addr_type: u8) -> AddrInfo { AddrInfo { bdaddr, addr_type } }

    /// # C: O(1)
    pub fn read(r: &mut Reader) -> Option<AddrInfo> {
        Some(AddrInfo { bdaddr: r.addr()?, addr_type: r.u8()? })
    }

    /// # C: O(1)
    pub fn write(&self, w: &mut Writer) {
        w.addr(&self.bdaddr);
        w.u8(self.addr_type);
    }

    /// Whether the type names one of the three transports. A command carrying
    /// any other value is rejected before the address is looked at. # C: O(1)
    pub fn type_is_valid(&self) -> bool {
        matches!(self.addr_type, BDADDR_BREDR | BDADDR_LE_PUBLIC | BDADDR_LE_RANDOM)
    }

    /// Whether the type names an LE transport. # C: O(1)
    pub fn is_le(&self) -> bool {
        matches!(self.addr_type, BDADDR_LE_PUBLIC | BDADDR_LE_RANDOM)
    }

    /// Decode a payload that is exactly one address record — the shape of every
    /// command and event that names a peer and nothing else. # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<AddrInfo> {
        let mut r = Reader::new(buf);
        let a = AddrInfo::read(&mut r)?;
        if !r.done() { return None; }
        Some(a)
    }

    /// # C: O(1)
    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        let mut w = Writer::with_capacity(MGMT_ADDR_INFO_SIZE);
        self.write(&mut w);
        w.finish()
    }
}

/// A BR/EDR link key with the PIN length that produced it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LinkKeyInfo {
    pub addr: AddrInfo,
    pub key_type: u8,
    pub val: [u8; MGMT_KEY_LEN],
    pub pin_len: u8,
}

impl LinkKeyInfo {
    /// # C: O(1)
    pub fn read(r: &mut Reader) -> Option<LinkKeyInfo> {
        Some(LinkKeyInfo {
            addr: AddrInfo::read(r)?,
            key_type: r.u8()?,
            val: r.array::<MGMT_KEY_LEN>()?,
            pin_len: r.u8()?,
        })
    }

    /// # C: O(1)
    pub fn write(&self, w: &mut Writer) {
        self.addr.write(w);
        w.u8(self.key_type);
        w.bytes(&self.val);
        w.u8(self.pin_len);
    }
}

/// An LE long-term key. `initiator` says which side generated it, and the
/// diversifier/random pair identifies it on a legacy reconnection.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LtkInfo {
    pub addr: AddrInfo,
    pub key_type: u8,
    pub initiator: u8,
    pub enc_size: u8,
    pub ediv: u16,
    pub rand: u64,
    pub val: [u8; MGMT_KEY_LEN],
}

impl LtkInfo {
    /// # C: O(1)
    pub fn read(r: &mut Reader) -> Option<LtkInfo> {
        Some(LtkInfo {
            addr: AddrInfo::read(r)?,
            key_type: r.u8()?,
            initiator: r.u8()?,
            enc_size: r.u8()?,
            ediv: r.u16()?,
            rand: r.u64()?,
            val: r.array::<MGMT_KEY_LEN>()?,
        })
    }

    /// # C: O(1)
    pub fn write(&self, w: &mut Writer) {
        self.addr.write(w);
        w.u8(self.key_type);
        w.u8(self.initiator);
        w.u8(self.enc_size);
        w.u16(self.ediv);
        w.u64(self.rand);
        w.bytes(&self.val);
    }
}

/// An identity-resolving key, bound to the identity address that owns it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IrkInfo {
    pub addr: AddrInfo,
    pub val: [u8; MGMT_KEY_LEN],
}

impl IrkInfo {
    /// # C: O(1)
    pub fn read(r: &mut Reader) -> Option<IrkInfo> {
        Some(IrkInfo { addr: AddrInfo::read(r)?, val: r.array::<MGMT_KEY_LEN>()? })
    }

    /// # C: O(1)
    pub fn write(&self, w: &mut Writer) {
        self.addr.write(w);
        w.bytes(&self.val);
    }
}

/// A connection-signature-resolving key. Its type says whose key it is and
/// whether the pairing that produced it was authenticated.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CsrkInfo {
    pub addr: AddrInfo,
    pub key_type: u8,
    pub val: [u8; MGMT_KEY_LEN],
}

impl CsrkInfo {
    /// # C: O(1)
    pub fn read(r: &mut Reader) -> Option<CsrkInfo> {
        Some(CsrkInfo {
            addr: AddrInfo::read(r)?,
            key_type: r.u8()?,
            val: r.array::<MGMT_KEY_LEN>()?,
        })
    }

    /// # C: O(1)
    pub fn write(&self, w: &mut Writer) {
        self.addr.write(w);
        w.u8(self.key_type);
        w.bytes(&self.val);
    }
}

/// Preferred LE connection parameters for one peer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConnParam {
    pub addr: AddrInfo,
    pub min_interval: u16,
    pub max_interval: u16,
    pub latency: u16,
    pub timeout: u16,
}

impl ConnParam {
    /// # C: O(1)
    pub fn read(r: &mut Reader) -> Option<ConnParam> {
        Some(ConnParam {
            addr: AddrInfo::read(r)?,
            min_interval: r.u16()?,
            max_interval: r.u16()?,
            latency: r.u16()?,
            timeout: r.u16()?,
        })
    }

    /// # C: O(1)
    pub fn write(&self, w: &mut Writer) {
        self.addr.write(w);
        w.u16(self.min_interval);
        w.u16(self.max_interval);
        w.u16(self.latency);
        w.u16(self.timeout);
    }
}

/// A key the stack must refuse to use, whatever produced it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BlockedKeyInfo {
    pub key_type: u8,
    pub val: [u8; MGMT_KEY_LEN],
}

impl BlockedKeyInfo {
    /// # C: O(1)
    pub fn read(r: &mut Reader) -> Option<BlockedKeyInfo> {
        Some(BlockedKeyInfo { key_type: r.u8()?, val: r.array::<MGMT_KEY_LEN>()? })
    }

    /// # C: O(1)
    pub fn write(&self, w: &mut Writer) {
        w.u8(self.key_type);
        w.bytes(&self.val);
    }
}

/// One advertising-monitor pattern. The value field is always its full width on
/// the wire; `length` says how much of it participates in the match.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AdvPattern {
    pub ad_type: u8,
    pub offset: u8,
    pub length: u8,
    pub value: [u8; MGMT_ADV_PATTERN_VALUE_LEN],
}

impl AdvPattern {
    /// # C: O(1)
    pub fn read(r: &mut Reader) -> Option<AdvPattern> {
        Some(AdvPattern {
            ad_type: r.u8()?,
            offset: r.u8()?,
            length: r.u8()?,
            value: r.array::<MGMT_ADV_PATTERN_VALUE_LEN>()?,
        })
    }

    /// # C: O(1)
    pub fn write(&self, w: &mut Writer) {
        w.u8(self.ad_type);
        w.u8(self.offset);
        w.u8(self.length);
        w.bytes(&self.value);
    }

    /// Whether the matched window fits inside the value field. A pattern whose
    /// offset plus length runs past the field can never match and is refused
    /// rather than silently clamped. # C: O(1)
    pub fn window_is_valid(&self) -> bool {
        self.length as usize > 0
            && self.offset as usize + self.length as usize <= MGMT_ADV_PATTERN_VALUE_LEN
    }
}

/// RSSI thresholds and timeouts an advertising monitor applies.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AdvRssiThresholds {
    pub high_threshold: i8,
    pub high_threshold_timeout: u16,
    pub low_threshold: i8,
    pub low_threshold_timeout: u16,
    pub sampling_period: u8,
}

impl AdvRssiThresholds {
    /// # C: O(1)
    pub fn read(r: &mut Reader) -> Option<AdvRssiThresholds> {
        Some(AdvRssiThresholds {
            high_threshold: r.i8()?,
            high_threshold_timeout: r.u16()?,
            low_threshold: r.i8()?,
            low_threshold_timeout: r.u16()?,
            sampling_period: r.u8()?,
        })
    }

    /// # C: O(1)
    pub fn write(&self, w: &mut Writer) {
        w.i8(self.high_threshold);
        w.u16(self.high_threshold_timeout);
        w.i8(self.low_threshold);
        w.u16(self.low_threshold_timeout);
        w.u8(self.sampling_period);
    }
}

#[cfg(test)]
#[path = "tests/types.rs"]
mod tests;
