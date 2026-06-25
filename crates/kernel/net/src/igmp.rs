// IGMPv1/v2 host messages. The stack tracks host memberships and emits
// IGMPv2 reports/leaves; queries are accepted in v1/v2's shared 8-byte form.

use crate::addr::Ipv4Addr;
use crate::ipv4::ip_checksum;

pub const IGMP_LEN: usize = 8;
pub const IGMP_TYPE_QUERY: u8 = 0x11;
pub const IGMP_TYPE_V2_REPORT: u8 = 0x16;
pub const IGMP_TYPE_LEAVE: u8 = 0x17;
pub const IPV4_ALL_HOSTS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);
pub const IPV4_ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);

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
}
