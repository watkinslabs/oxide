//! SCMI Performance protocol v1–v4.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{Error, Result, Transport};

const PROTOCOL: u8 = 0x13;
const VERSION: u8 = 0;
const ATTRIBUTES: u8 = 1;
const NEGOTIATE_VERSION: u8 = 0x10;
const DOMAIN_ATTRIBUTES: u8 = 3;
const DESCRIBE_LEVELS: u8 = 4;
const LEVEL_SET: u8 = 7;
const LEVEL_GET: u8 = 8;
const SUPPORTED_VERSION: u32 = 0x0004_0000;
const MAX_OPPS: usize = 64;
const SET_PERF_LEVEL: u32 = 1 << 30;
const SET_LIMITS: u32 = 1 << 31;
const LEVEL_INDEXING: u32 = 1 << 25;

/// A firmware operating point translated into an exact CPU frequency.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OperatingPoint {
    /// CPU frequency in hertz.
    pub frequency_hz: u64,
    /// SCMI performance value advertised by the protocol.
    pub performance_level: u32,
    /// SCMI wire level, which is an opaque index in v4 indexed mode.
    pub wire_level: u32,
    /// Firmware-reported transition latency in microseconds.
    pub transition_latency_us: u16,
    /// Whether this level is above firmware's sustained frequency.
    pub turbo: bool,
}

/// One SCMI performance domain and its advertised OPP ladder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Domain {
    /// Firmware performance-domain ID.
    pub id: u32,
    /// Whether SCMI accepts performance-level requests for this domain.
    pub can_set_level: bool,
    /// Whether SCMI accepts domain limit requests for this domain.
    pub can_set_limits: bool,
    /// Advertised sustained frequency in hertz.
    pub sustained_frequency_hz: u64,
    /// Firmware rate limit in microseconds.
    pub rate_limit_us: u32,
    /// Highest-performance OPP latency, in nanoseconds.
    pub transition_latency_ns: u64,
    /// OPPs sorted by increasing performance level.
    pub opps: Vec<OperatingPoint>,
    multiplier: u64,
    level_indexing: bool,
}

/// Client for one SCMI Performance protocol instance.
pub struct Performance { transport: Arc<dyn Transport>, version: u32, domains: u16 }

impl Performance {
    /// Open the Performance protocol and collect its top-level attributes.
    ///
    /// An unqueryable or newer protocol follows Linux's best-effort rule and
    /// uses the newest layout this client understands (v4). # C: O(transport)
    pub fn open(transport: Arc<dyn Transport>) -> Result<Self> {
        let mut response = [0u8; 4];
        let platform_version = match call(&transport, VERSION, &[], &mut response) {
            Ok(length) if length >= response.len() => le32(&response, 0).ok_or(Error::Malformed)?,
            Ok(_) => return Err(Error::Malformed),
            Err(_) => SUPPORTED_VERSION,
        };
        let version = if platform_version <= SUPPORTED_VERSION { platform_version } else {
            let _ = call(&transport, NEGOTIATE_VERSION, &SUPPORTED_VERSION.to_le_bytes(), &mut []);
            SUPPORTED_VERSION
        };
        let mut attributes = [0u8; 16];
        let length = call(&transport, ATTRIBUTES, &[], &mut attributes)?;
        if length < attributes.len() { return Err(Error::Malformed); }
        Ok(Self { transport, version, domains: le16(&attributes, 0).ok_or(Error::Malformed)? })
    }

    /// Number of firmware performance domains. # C: O(1)
    pub const fn domains(&self) -> u16 { self.domains }

    /// Effective SCMI protocol version used by this client. # C: O(1)
    pub const fn version(&self) -> u32 { self.version }

    /// Decode one complete performance-domain OPP ladder. # C: O(opps × transport)
    pub fn domain(&self, id: u32) -> Result<Domain> {
        if id >= u32::from(self.domains) { return Err(Error::Invalid); }
        let mut attributes = [0u8; 32];
        let length = call(&self.transport, DOMAIN_ATTRIBUTES, &id.to_le_bytes(), &mut attributes)?;
        if length < attributes.len() { return Err(Error::Malformed); }
        let flags = le32(&attributes, 0).ok_or(Error::Malformed)?;
        let sustained_khz = le32(&attributes, 8).ok_or(Error::Malformed)?;
        let sustained_level = le32(&attributes, 12).ok_or(Error::Malformed)?;
        let level_indexing = major(self.version) >= 4 && flags & LEVEL_INDEXING != 0;
        let multiplier = if sustained_khz == 0 || sustained_level == 0 || level_indexing {
            1_000
        } else {
            u64::from(sustained_khz).checked_mul(1_000).ok_or(Error::Range)? / u64::from(sustained_level)
        };
        if multiplier == 0 { return Err(Error::Range); }
        let mut domain = Domain {
            id, can_set_level: flags & SET_PERF_LEVEL != 0, can_set_limits: flags & SET_LIMITS != 0,
            sustained_frequency_hz: u64::from(sustained_khz).checked_mul(1_000).ok_or(Error::Range)?,
            rate_limit_us: le32(&attributes, 4).ok_or(Error::Malformed)? & 0x000f_ffff,
            transition_latency_ns: 0, opps: Vec::new(), multiplier, level_indexing,
        };
        let mut start = 0u32;
        loop {
            let mut tx = [0u8; 8];
            tx[..4].copy_from_slice(&id.to_le_bytes());
            tx[4..].copy_from_slice(&start.to_le_bytes());
            let mut response = [0u8; 4 + MAX_OPPS * 20];
            let length = call(&self.transport, DESCRIBE_LEVELS, &tx, &mut response)?;
            if length < 4 { return Err(Error::Malformed); }
            let returned = usize::from(le16(&response, 0).ok_or(Error::Malformed)?);
            let remaining = le16(&response, 2).ok_or(Error::Malformed)?;
            let record = if major(self.version) >= 4 { 20 } else { 12 };
            if returned > MAX_OPPS || length < 4 + returned.checked_mul(record).ok_or(Error::Range)? {
                return Err(Error::Malformed);
            }
            if returned == 0 && remaining != 0 { return Err(Error::Malformed); }
            for index in 0..returned { append_opp(&mut domain, &response[4 + index * record..], record)?; }
            start = start.checked_add(u32::try_from(returned).map_err(|_| Error::Range)?).ok_or(Error::Range)?;
            if domain.opps.len() > MAX_OPPS { return Err(Error::Range); }
            if remaining == 0 { break; }
        }
        if domain.opps.is_empty() { return Err(Error::NotFound); }
        domain.opps.sort_unstable_by_key(|opp| opp.performance_level);
        domain.transition_latency_ns = u64::from(domain.opps.last().ok_or(Error::NotFound)?.transition_latency_us)
            .checked_mul(1_000).ok_or(Error::Range)?;
        Ok(domain)
    }

    /// Select an advertised OPP by table index. # C: O(transport)
    pub fn set_index(&self, domain: &Domain, index: usize) -> Result<()> {
        if !domain.can_set_level { return Err(Error::Unsupported); }
        let level = domain.opps.get(index).ok_or(Error::Invalid)?.wire_level;
        let mut tx = [0u8; 8];
        tx[..4].copy_from_slice(&domain.id.to_le_bytes());
        tx[4..].copy_from_slice(&level.to_le_bytes());
        call(&self.transport, LEVEL_SET, &tx, &mut []).map(|_| ())
    }

    /// Read the exact current frequency from firmware. # C: O(transport + opps)
    pub fn frequency_hz(&self, domain: &Domain) -> Result<u64> {
        let mut rx = [0u8; 4];
        let length = call(&self.transport, LEVEL_GET, &domain.id.to_le_bytes(), &mut rx)?;
        if length < rx.len() { return Err(Error::Malformed); }
        let level = le32(&rx, 0).ok_or(Error::Malformed)?;
        if domain.level_indexing {
            return domain.opps.iter().find(|opp| opp.wire_level == level)
                .map(|opp| opp.frequency_hz).ok_or(Error::Protocol);
        }
        u64::from(level).checked_mul(domain.multiplier).ok_or(Error::Range)
    }
}

fn append_opp(domain: &mut Domain, record: &[u8], width: usize) -> Result<()> {
    let performance_level = le32(record, 0).ok_or(Error::Malformed)?;
    if domain.opps.iter().any(|opp| opp.performance_level == performance_level) { return Ok(()); }
    let transition_latency_us = le16(record, 8).ok_or(Error::Malformed)?;
    let (frequency_hz, wire_level) = if width == 20 && domain.level_indexing {
        (u64::from(le32(record, 12).ok_or(Error::Malformed)?).checked_mul(domain.multiplier).ok_or(Error::Range)?,
         le32(record, 16).ok_or(Error::Malformed)?)
    } else {
        (u64::from(performance_level).checked_mul(domain.multiplier).ok_or(Error::Range)?, performance_level)
    };
    if frequency_hz == 0 || domain.opps.iter().any(|opp| opp.wire_level == wire_level) { return Err(Error::Malformed); }
    domain.opps.push(OperatingPoint {
        frequency_hz, performance_level, wire_level, transition_latency_us,
        turbo: frequency_hz > domain.sustained_frequency_hz,
    });
    Ok(())
}

fn call(transport: &Arc<dyn Transport>, command: u8, tx: &[u8], rx: &mut [u8]) -> Result<usize> {
    let length = transport.call(PROTOCOL, command, tx, rx)?;
    (length <= rx.len()).then_some(length).ok_or(Error::Malformed)
}

fn le16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes.get(offset..offset.checked_add(2)?).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn le32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes.get(offset..offset.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn major(version: u32) -> u32 { version >> 16 }
