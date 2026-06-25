extern crate alloc;

use alloc::vec::Vec;

use crate::nlmsg_align;
use crate::rtnetlink::rta;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RouteNexthop {
    pub gateway: Option<[u8; 4]>,
    pub oif:     u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteAttrs {
    pub dst:       Option<[u8; 4]>,
    pub gateway:   Option<[u8; 4]>,
    pub oif:       Option<u32>,
    pub prefsrc:   Option<[u8; 4]>,
    pub multipath: Vec<RouteNexthop>,
}

/// Parse nested attributes in one `struct rtnexthop`. # C: O(N attrs)
fn parse_nh_attrs(attrs: &[u8]) -> Option<[u8; 4]> {
    let mut gw = None;
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        let payload = &attrs[off + 4..off + nla_len];
        if nla_type == rta::RTA_GATEWAY && payload.len() == 4 {
            gw = Some([payload[0], payload[1], payload[2], payload[3]]);
        }
        off += nlmsg_align(nla_len);
    }
    gw
}

/// Parse Linux `RTA_MULTIPATH` payload. # C: O(N nexthops + attrs)
fn parse_multipath(payload: &[u8]) -> Vec<RouteNexthop> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 8 <= payload.len() {
        let rtnh_len = u16::from_ne_bytes([payload[off], payload[off + 1]]) as usize;
        if rtnh_len < 8 || off + rtnh_len > payload.len() { break; }
        let oif = u32::from_ne_bytes([
            payload[off + 4], payload[off + 5], payload[off + 6], payload[off + 7],
        ]);
        if oif != 0 {
            out.push(RouteNexthop {
                gateway: parse_nh_attrs(&payload[off + 8..off + rtnh_len]),
                oif,
            });
        }
        off += nlmsg_align(rtnh_len);
    }
    out
}

/// Parse RTA_* attributes following an rtmsg. # C: O(N attrs + multipath)
pub fn parse_route_attrs(attrs: &[u8]) -> RouteAttrs {
    let mut out = RouteAttrs {
        dst: None, gateway: None, oif: None, prefsrc: None, multipath: Vec::new(),
    };
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        let payload = &attrs[off + 4..off + nla_len];
        match (nla_type, payload.len()) {
            (rta::RTA_DST, 4)     => out.dst = Some([payload[0], payload[1], payload[2], payload[3]]),
            (rta::RTA_GATEWAY, 4) => out.gateway = Some([payload[0], payload[1], payload[2], payload[3]]),
            (rta::RTA_OIF, 4)     => out.oif = Some(u32::from_ne_bytes([
                                       payload[0], payload[1], payload[2], payload[3]])),
            (rta::RTA_PREFSRC, 4) => out.prefsrc = Some([payload[0], payload[1], payload[2], payload[3]]),
            (rta::RTA_MULTIPATH, _) => out.multipath = parse_multipath(payload),
            _ => {}
        }
        off += nlmsg_align(nla_len);
    }
    out
}

/// Append an `RTA_MULTIPATH` attr from `(ifindex, gateway)` nexthops. # C: O(N)
pub fn put_multipath_attr(out: &mut Vec<u8>, nexthops: &[(u32, Option<[u8; 4]>)]) {
    let mut payload = Vec::new();
    for (oif, gw) in nexthops.iter().copied() {
        let start = payload.len();
        payload.extend_from_slice(&0u16.to_ne_bytes());
        payload.push(0);
        payload.push(0);
        payload.extend_from_slice(&oif.to_ne_bytes());
        if let Some(g) = gw {
            crate::rtnetlink::put_nlattr(&mut payload, rta::RTA_GATEWAY, &g);
        }
        let len = payload.len() - start;
        payload[start..start + 2].copy_from_slice(&(len as u16).to_ne_bytes());
        let pad = nlmsg_align(len) - len;
        for _ in 0..pad { payload.push(0); }
    }
    crate::rtnetlink::put_nlattr(out, rta::RTA_MULTIPATH, &payload);
}
