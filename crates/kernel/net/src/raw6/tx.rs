use alloc::vec::Vec;

use crate::addr::{IpProto, Ipv6Addr, NetIfaceId};
use crate::ipv6::IPV6_HDR_LEN;
use crate::netdev::{NetError, NetResult};

use super::{Raw6Checksum, Raw6Endpoint};

const CSUM_MANGLED_0: u16 = 0xffff;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Raw6SendMode { KernelHeader, CallerHeader }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRaw6Send {
    pub mode: Raw6SendMode,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next_header: u8,
    pub bytes: Vec<u8>,
}

impl Raw6Endpoint {
    /// Prepare payload/checksum or preserve one caller-supplied IPv6 packet. # C: O(bytes)
    pub(crate) fn prepare_send(&self, route_src: Ipv6Addr, route_dst: Ipv6Addr,
                        protocol_override: Option<u8>, bytes: &[u8])
        -> NetResult<PreparedRaw6Send>
    {
        let state = self.state.lock();
        if !state.accepting { return Err(NetError::Enotconn); }
        if state.header_included {
            if bytes.len() < IPV6_HDR_LEN { return Err(NetError::Einval); }
            return Ok(PreparedRaw6Send {
                mode: Raw6SendMode::CallerHeader, src: route_src, dst: route_dst,
                next_header: bytes[6], bytes: bytes.to_vec(),
            });
        }
        let next_header = if self.protocol() == IpProto::Raw as u8 {
            protocol_override.ok_or(NetError::Einval)?
        } else {
            self.protocol()
        };
        let mut payload = bytes.to_vec();
        apply_checksum(state.checksum, route_src, route_dst, next_header, &mut payload)?;
        Ok(PreparedRaw6Send {
            mode: Raw6SendMode::KernelHeader, src: route_src, dst: route_dst,
            next_header, bytes: payload,
        })
    }

    /// Snapshot address and interface constraints used by transmit routing. # C: O(1)
    pub(crate) fn tx_binding(&self) -> (super::Raw6Address, Option<NetIfaceId>) {
        let state = self.state.lock();
        (state.local, state.bound_iface)
    }
}

fn apply_checksum(config: Raw6Checksum, src: Ipv6Addr, dst: Ipv6Addr, protocol: u8,
                  payload: &mut [u8]) -> NetResult<()> {
    let Raw6Checksum::Offset(offset) = config else { return Ok(()) };
    let offset = offset as usize;
    let end = offset.checked_add(2).ok_or(NetError::Einval)?;
    if end > payload.len() { return Err(NetError::Einval); }
    payload[offset] = 0;
    payload[offset + 1] = 0;
    let checksum = match upper_layer_checksum(src, dst, protocol, payload) {
        0 => CSUM_MANGLED_0,
        checksum => checksum,
    };
    payload[offset..end].copy_from_slice(&checksum.to_be_bytes());
    Ok(())
}

fn upper_layer_checksum(src: Ipv6Addr, dst: Ipv6Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u64;
    add_bytes(&mut sum, &src.0);
    add_bytes(&mut sum, &dst.0);
    let len = (payload.len() as u32).to_be_bytes();
    add_bytes(&mut sum, &len);
    add_bytes(&mut sum, &[0, 0, 0, protocol]);
    add_bytes(&mut sum, payload);
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

fn add_bytes(sum: &mut u64, bytes: &[u8]) {
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 { u16::from_be_bytes([chunk[0], chunk[1]]) }
            else { (chunk[0] as u16) << 8 };
        *sum += word as u64;
    }
}
