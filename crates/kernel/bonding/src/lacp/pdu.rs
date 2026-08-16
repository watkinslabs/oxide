// LACPDU wire format: fixed-length TLV chain carrying actor, partner and
// collector information followed by a terminator.

use crate::limits::{AD_COLLECTOR_MAX_DELAY, AD_COLLECTOR_TLV_LEN, AD_INFO_TLV_LEN, LACPDU_LEN};

/// Slow-protocol subtype that marks a frame as an LACPDU.
pub const LACP_SUBTYPE: u8 = 0x01;
/// Protocol version carried in every emitted LACPDU.
pub const LACP_VERSION: u8 = 0x01;
/// TLV type of the actor information block.
pub const TLV_TYPE_ACTOR_INFO: u8 = 0x01;
/// TLV type of the partner information block.
pub const TLV_TYPE_PARTNER_INFO: u8 = 0x02;
/// TLV type of the collector information block.
pub const TLV_TYPE_COLLECTOR_INFO: u8 = 0x03;
/// TLV type that closes the chain.
pub const TLV_TYPE_TERMINATOR: u8 = 0x00;
/// Length octet of the terminator TLV.
pub const TERMINATOR_LENGTH: u8 = 0x00;

/// Byte offsets of each field within the LACPDU body.
const OFF_SUBTYPE: usize = 0;
const OFF_VERSION: usize = 1;
const OFF_ACTOR_TLV: usize = 2;
const OFF_ACTOR_LEN: usize = 3;
const OFF_ACTOR_SYS_PRIO: usize = 4;
const OFF_ACTOR_SYS: usize = 6;
const OFF_ACTOR_KEY: usize = 12;
const OFF_ACTOR_PORT_PRIO: usize = 14;
const OFF_ACTOR_PORT: usize = 16;
const OFF_ACTOR_STATE: usize = 18;
const OFF_PARTNER_TLV: usize = 22;
const OFF_PARTNER_LEN: usize = 23;
const OFF_PARTNER_SYS_PRIO: usize = 24;
const OFF_PARTNER_SYS: usize = 26;
const OFF_PARTNER_KEY: usize = 32;
const OFF_PARTNER_PORT_PRIO: usize = 34;
const OFF_PARTNER_PORT: usize = 36;
const OFF_PARTNER_STATE: usize = 38;
const OFF_COLLECTOR_TLV: usize = 42;
const OFF_COLLECTOR_LEN: usize = 43;
const OFF_COLLECTOR_MAX_DELAY: usize = 44;
const OFF_TERMINATOR_TLV: usize = 58;
const OFF_TERMINATOR_LEN: usize = 59;

/// Why a received frame is not a usable LACPDU.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PduError {
    /// Fewer bytes than the fixed body length.
    Truncated,
    /// Slow-protocol subtype is not the LACP one.
    WrongSubtype,
    /// Protocol version this implementation does not speak.
    BadVersion,
    /// A TLV type or length octet does not match the fixed layout.
    BadTlv,
}

/// One side's advertised aggregation identity and state.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PortInfo {
    pub system_priority: u16,
    pub system: [u8; 6],
    pub key: u16,
    pub port_priority: u16,
    pub port: u16,
    /// `LACP_STATE_*` bit set.
    pub state: u8,
}

/// Decoded LACPDU contents.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Lacpdu {
    pub actor: PortInfo,
    pub partner: PortInfo,
    pub collector_max_delay: u16,
}

fn be16(buf: &[u8], off: usize) -> u16 { u16::from_be_bytes([buf[off], buf[off + 1]]) }

fn put_be16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_be_bytes());
}

fn mac(buf: &[u8], off: usize) -> [u8; 6] {
    let mut m = [0u8; 6];
    m.copy_from_slice(&buf[off..off + 6]);
    m
}

impl Lacpdu {
    /// Serialise into the fixed-length body an aggregation frame carries.
    /// # C: O(1)
    pub fn encode(&self) -> [u8; LACPDU_LEN] {
        let mut b = [0u8; LACPDU_LEN];
        b[OFF_SUBTYPE] = LACP_SUBTYPE;
        b[OFF_VERSION] = LACP_VERSION;

        b[OFF_ACTOR_TLV] = TLV_TYPE_ACTOR_INFO;
        b[OFF_ACTOR_LEN] = AD_INFO_TLV_LEN;
        put_be16(&mut b, OFF_ACTOR_SYS_PRIO, self.actor.system_priority);
        b[OFF_ACTOR_SYS..OFF_ACTOR_SYS + 6].copy_from_slice(&self.actor.system);
        put_be16(&mut b, OFF_ACTOR_KEY, self.actor.key);
        put_be16(&mut b, OFF_ACTOR_PORT_PRIO, self.actor.port_priority);
        put_be16(&mut b, OFF_ACTOR_PORT, self.actor.port);
        b[OFF_ACTOR_STATE] = self.actor.state;

        b[OFF_PARTNER_TLV] = TLV_TYPE_PARTNER_INFO;
        b[OFF_PARTNER_LEN] = AD_INFO_TLV_LEN;
        put_be16(&mut b, OFF_PARTNER_SYS_PRIO, self.partner.system_priority);
        b[OFF_PARTNER_SYS..OFF_PARTNER_SYS + 6].copy_from_slice(&self.partner.system);
        put_be16(&mut b, OFF_PARTNER_KEY, self.partner.key);
        put_be16(&mut b, OFF_PARTNER_PORT_PRIO, self.partner.port_priority);
        put_be16(&mut b, OFF_PARTNER_PORT, self.partner.port);
        b[OFF_PARTNER_STATE] = self.partner.state;

        b[OFF_COLLECTOR_TLV] = TLV_TYPE_COLLECTOR_INFO;
        b[OFF_COLLECTOR_LEN] = AD_COLLECTOR_TLV_LEN;
        put_be16(&mut b, OFF_COLLECTOR_MAX_DELAY, self.collector_max_delay);

        b[OFF_TERMINATOR_TLV] = TLV_TYPE_TERMINATOR;
        b[OFF_TERMINATOR_LEN] = TERMINATOR_LENGTH;
        b
    }

    /// Parse a received body, rejecting anything shorter than the fixed
    /// layout or carrying a foreign subtype, version or TLV chain.
    /// # C: O(1)
    pub fn decode(buf: &[u8]) -> Result<Lacpdu, PduError> {
        if buf.len() < LACPDU_LEN { return Err(PduError::Truncated); }
        if buf[OFF_SUBTYPE] != LACP_SUBTYPE { return Err(PduError::WrongSubtype); }
        if buf[OFF_VERSION] != LACP_VERSION { return Err(PduError::BadVersion); }
        if buf[OFF_ACTOR_TLV] != TLV_TYPE_ACTOR_INFO
            || buf[OFF_ACTOR_LEN] != AD_INFO_TLV_LEN
            || buf[OFF_PARTNER_TLV] != TLV_TYPE_PARTNER_INFO
            || buf[OFF_PARTNER_LEN] != AD_INFO_TLV_LEN
            || buf[OFF_COLLECTOR_TLV] != TLV_TYPE_COLLECTOR_INFO
            || buf[OFF_COLLECTOR_LEN] != AD_COLLECTOR_TLV_LEN
            || buf[OFF_TERMINATOR_TLV] != TLV_TYPE_TERMINATOR
            || buf[OFF_TERMINATOR_LEN] != TERMINATOR_LENGTH
        {
            return Err(PduError::BadTlv);
        }
        Ok(Lacpdu {
            actor: PortInfo {
                system_priority: be16(buf, OFF_ACTOR_SYS_PRIO),
                system: mac(buf, OFF_ACTOR_SYS),
                key: be16(buf, OFF_ACTOR_KEY),
                port_priority: be16(buf, OFF_ACTOR_PORT_PRIO),
                port: be16(buf, OFF_ACTOR_PORT),
                state: buf[OFF_ACTOR_STATE],
            },
            partner: PortInfo {
                system_priority: be16(buf, OFF_PARTNER_SYS_PRIO),
                system: mac(buf, OFF_PARTNER_SYS),
                key: be16(buf, OFF_PARTNER_KEY),
                port_priority: be16(buf, OFF_PARTNER_PORT_PRIO),
                port: be16(buf, OFF_PARTNER_PORT),
                state: buf[OFF_PARTNER_STATE],
            },
            collector_max_delay: be16(buf, OFF_COLLECTOR_MAX_DELAY),
        })
    }

    /// Frame this port would emit, with the collector delay the wire format
    /// fixes for an aggregation port.
    /// # C: O(1)
    pub fn from_ports(actor: PortInfo, partner: PortInfo) -> Lacpdu {
        Lacpdu { actor, partner, collector_max_delay: AD_COLLECTOR_MAX_DELAY }
    }
}
