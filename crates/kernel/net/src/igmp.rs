// IGMPv1/v2 host messages. The stack tracks host memberships and emits
// IGMPv2 reports/leaves; queries are accepted in v1/v2's shared 8-byte form.

use crate::addr::Ipv4Addr;
use crate::ipv4::ip_checksum;

pub const IGMP_LEN: usize = 8;
pub const IGMP_TYPE_QUERY: u8 = 0x11;
pub const IGMP_TYPE_V2_REPORT: u8 = 0x16;
pub const IGMP_TYPE_LEAVE: u8 = 0x17;
pub const IGMP_TYPE_V3_REPORT: u8 = 0x22;
pub const IGMP_V3_RECORD_MODE_IS_INCLUDE: u8 = 1;
pub const IGMP_V3_RECORD_MODE_IS_EXCLUDE: u8 = 2;
pub const IGMP_V3_RECORD_CHANGE_TO_INCLUDE: u8 = 3;
pub const IGMP_V3_RECORD_CHANGE_TO_EXCLUDE: u8 = 4;
pub const IPV4_ALL_HOSTS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);
pub const IPV4_ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);
pub const IPV4_IGMPV3_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IgmpError { Short, BadChecksum, BadType }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IgmpQuery {
    pub max_resp_time: u8,
    pub group: Ipv4Addr,
}

impl IgmpQuery {
    /// Parse an IGMP membership query. # C: O(N)
    pub fn parse(buf: &[u8]) -> Result<Self, IgmpError> {
        if buf.len() < IGMP_LEN { return Err(IgmpError::Short); }
        if ip_checksum(&buf[..IGMP_LEN]) != 0 { return Err(IgmpError::BadChecksum); }
        if buf[0] != IGMP_TYPE_QUERY { return Err(IgmpError::BadType); }
        Ok(Self {
            max_resp_time: buf[1],
            group: Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]),
        })
    }
}

/// Build an IGMPv2 report/leave packet body. # C: O(1)
pub fn build_igmp_msg(typ: u8, group: Ipv4Addr) -> [u8; IGMP_LEN] {
    let mut out = [0u8; IGMP_LEN];
    out[0] = typ;
    out[4..8].copy_from_slice(&group.octets());
    let cs = ip_checksum(&out);
    out[2..4].copy_from_slice(&cs.to_be_bytes());
    out
}

/// Build a single-record IGMPv3 membership report. # C: O(N sources)
pub fn build_igmpv3_report(record_type: u8, group: Ipv4Addr, sources: &[Ipv4Addr])
    -> alloc::vec::Vec<u8>
{
    let nsrc = sources.len().min(u16::MAX as usize);
    let mut out = alloc::vec![0u8; 8 + 8 + 4 * nsrc];
    out[0] = IGMP_TYPE_V3_REPORT;
    out[6..8].copy_from_slice(&1u16.to_be_bytes());
    out[8] = record_type;
    out[10..12].copy_from_slice(&(nsrc as u16).to_be_bytes());
    out[12..16].copy_from_slice(&group.octets());
    for (i, src) in sources.iter().take(nsrc).enumerate() {
        out[16 + 4 * i..20 + 4 * i].copy_from_slice(&src.octets());
    }
    let cs = ip_checksum(&out);
    out[2..4].copy_from_slice(&cs.to_be_bytes());
    out
}

/// Build an IGMP membership query for tests. # C: O(1)
pub fn build_igmp_query(group: Ipv4Addr, max_resp_time: u8) -> [u8; IGMP_LEN] {
    let mut out = [0u8; IGMP_LEN];
    out[0] = IGMP_TYPE_QUERY;
    out[1] = max_resp_time;
    out[4..8].copy_from_slice(&group.octets());
    let cs = ip_checksum(&out);
    out[2..4].copy_from_slice(&cs.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_round_trip() {
        let group = Ipv4Addr::new(224, 1, 2, 3);
        let q = build_igmp_query(group, 10);
        let parsed = IgmpQuery::parse(&q).unwrap();
        assert_eq!(parsed.group, group);
        assert_eq!(parsed.max_resp_time, 10);
    }

    #[test]
    fn igmpv3_report_layout_and_checksum() {
        let group = Ipv4Addr::new(239, 1, 2, 3);
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let r = build_igmpv3_report(IGMP_V3_RECORD_MODE_IS_INCLUDE, group, &[src]);
        assert_eq!(r[0], IGMP_TYPE_V3_REPORT);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1);
        assert_eq!(r[8], IGMP_V3_RECORD_MODE_IS_INCLUDE);
        assert_eq!(u16::from_be_bytes([r[10], r[11]]), 1);
        assert_eq!(&r[12..16], &group.octets());
        assert_eq!(&r[16..20], &src.octets());
        assert_eq!(ip_checksum(&r), 0);
    }
}
