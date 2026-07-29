extern crate alloc;

use alloc::vec::Vec;

use crate::nlmsg_align;
use crate::rtnetlink::rta;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RouteNexthop {
    pub gateway: Option<[u8; 4]>,
    pub oif:     u32,
    pub flags:   u8,
    pub hops:    u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteAttrs {
    pub dst:       Option<[u8; 4]>,
    pub gateway:   Option<[u8; 4]>,
    pub oif:       Option<u32>,
    pub prefsrc:   Option<[u8; 4]>,
    pub table:     Option<u32>,
    pub metric:    Option<u32>,
    pub mtu:       Option<u32>,
    pub multipath: Vec<RouteNexthop>,
}

const RTAX_MTU: u16 = 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RouteAttrError { Invalid, Unsupported }

fn parse_u32(payload: &[u8]) -> Option<u32> {
    if payload.len() != 4 { return None; }
    Some(u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]))
}

fn parse_metrics(attrs: &[u8]) -> Result<Option<u32>, RouteAttrError> {
    let off = 0;
    while off + 4 <= attrs.len() {
        let len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let kind = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if len < 4 || off + len > attrs.len() { return Err(RouteAttrError::Invalid); }
        if kind == RTAX_MTU {
            return parse_u32(&attrs[off + 4..off + len]).map(Some).ok_or(RouteAttrError::Invalid);
        }
        return Err(RouteAttrError::Unsupported);
    }
    if attrs[off..].iter().any(|byte| *byte != 0) { return Err(RouteAttrError::Invalid); }
    Ok(None)
}

/// Parse nested attributes in one `struct rtnexthop`. # C: O(N attrs)
fn parse_nh_attrs(attrs: &[u8]) -> Result<Option<[u8; 4]>, RouteAttrError> {
    let mut gw = None;
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { return Err(RouteAttrError::Invalid); }
        let payload = &attrs[off + 4..off + nla_len];
        if nla_type == rta::RTA_GATEWAY {
            if payload.len() != 4 { return Err(RouteAttrError::Invalid); }
            gw = Some([payload[0], payload[1], payload[2], payload[3]]);
        }
        off += nlmsg_align(nla_len);
    }
    if attrs[off..].iter().any(|byte| *byte != 0) { return Err(RouteAttrError::Invalid); }
    Ok(gw)
}

/// Parse Linux `RTA_MULTIPATH` payload. # C: O(N nexthops + attrs)
fn parse_multipath(payload: &[u8]) -> Result<Vec<RouteNexthop>, RouteAttrError> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 8 <= payload.len() {
        let rtnh_len = u16::from_ne_bytes([payload[off], payload[off + 1]]) as usize;
        if rtnh_len < 8 || off + rtnh_len > payload.len() { return Err(RouteAttrError::Invalid); }
        let flags = payload[off + 2];
        let hops = payload[off + 3];
        let oif = u32::from_ne_bytes([
            payload[off + 4], payload[off + 5], payload[off + 6], payload[off + 7],
        ]);
        if oif == 0 { return Err(RouteAttrError::Invalid); }
        out.push(RouteNexthop {
            gateway: parse_nh_attrs(&payload[off + 8..off + rtnh_len])?,
            oif, flags, hops,
        });
        off += nlmsg_align(rtnh_len);
    }
    if payload[off..].iter().any(|byte| *byte != 0) { return Err(RouteAttrError::Invalid); }
    if out.is_empty() { return Err(RouteAttrError::Invalid); }
    Ok(out)
}

/// Parse RTA_* attributes following an rtmsg. # C: O(N attrs + multipath)
pub fn parse_route_attrs(attrs: &[u8]) -> Result<RouteAttrs, RouteAttrError> {
    let mut out = RouteAttrs {
        dst: None, gateway: None, oif: None, prefsrc: None,
        table: None, metric: None, mtu: None, multipath: Vec::new(),
    };
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { return Err(RouteAttrError::Invalid); }
        let payload = &attrs[off + 4..off + nla_len];
        match (nla_type, payload.len()) {
            (rta::RTA_DST, 4)     => out.dst = Some([payload[0], payload[1], payload[2], payload[3]]),
            (rta::RTA_GATEWAY, 4) => out.gateway = Some([payload[0], payload[1], payload[2], payload[3]]),
            (rta::RTA_OIF, 4)     => out.oif = Some(u32::from_ne_bytes([
                                       payload[0], payload[1], payload[2], payload[3]])),
            (rta::RTA_PREFSRC, 4) => out.prefsrc = Some([payload[0], payload[1], payload[2], payload[3]]),
            (rta::RTA_TABLE, 4) => out.table = parse_u32(payload),
            (rta::RTA_PRIORITY, 4) => out.metric = parse_u32(payload),
            (rta::RTA_METRICS, _) => out.mtu = parse_metrics(payload)?,
            (rta::RTA_MULTIPATH, _) => out.multipath = parse_multipath(payload)?,
            (rta::RTA_SRC | rta::RTA_IIF, _) => return Err(RouteAttrError::Unsupported),
            (rta::RTA_DST | rta::RTA_GATEWAY | rta::RTA_OIF | rta::RTA_PREFSRC
                | rta::RTA_TABLE | rta::RTA_PRIORITY, _) => return Err(RouteAttrError::Invalid),
            _ => {}
        }
        off += nlmsg_align(nla_len);
    }
    if attrs[off..].iter().any(|byte| *byte != 0) { return Err(RouteAttrError::Invalid); }
    if !out.multipath.is_empty() && out.oif.is_some() { return Err(RouteAttrError::Invalid); }
    Ok(out)
}

/// Append an `RTA_MULTIPATH` attr from `(ifindex, gateway)` nexthops. # C: O(N)
pub fn put_multipath_attr(out: &mut Vec<u8>, nexthops: &[RouteNexthop]) {
    let mut payload = Vec::new();
    for nh in nexthops.iter().copied() {
        let start = payload.len();
        payload.extend_from_slice(&0u16.to_ne_bytes());
        payload.push(nh.flags);
        payload.push(nh.hops);
        payload.extend_from_slice(&nh.oif.to_ne_bytes());
        if let Some(g) = nh.gateway {
            crate::rtnetlink::put_nlattr(&mut payload, rta::RTA_GATEWAY, &g);
        }
        let len = payload.len() - start;
        payload[start..start + 2].copy_from_slice(&(len as u16).to_ne_bytes());
        let pad = nlmsg_align(len) - len;
        for _ in 0..pad { payload.push(0); }
    }
    crate::rtnetlink::put_nlattr(out, rta::RTA_MULTIPATH, &payload);
}
