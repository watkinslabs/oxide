extern crate alloc;

use alloc::vec::Vec;

use crate::nlmsg_align;
use crate::rtnetlink::rta;
use crate::rtnetlink::uapi::rtax;

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
    pub metrics:   net::RouteMetrics,
    pub metric_filters: Vec<RouteMetricFilter>,
    pub multipath: Vec<RouteNexthop>,
}

// Route-metric lock-mask conversion.
const RTAX_MTU_MAX: u32 = u16::MAX as u32 - 15;
const RTAX_ADVMSS_MAX: u32 = u16::MAX as u32 - 40;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RouteAttrError { Invalid, Unsupported }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteMetricFilter {
    Scalar { kind: u16, value: u32 },
    Cc(Option<net::TcpCongestionControl>),
    Never,
}

fn parse_u32(payload: &[u8]) -> Option<u32> {
    if payload.len() != 4 { return None; }
    Some(u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]))
}

fn lookup_cc_algo(payload: &[u8]) -> Option<net::TcpCongestionControl> {
    const TCP_CA_NAME_MAX: usize = 16;
    let copied = &payload[..payload.len().min(TCP_CA_NAME_MAX - 1)];
    let end = copied.iter().position(|byte| *byte == 0).unwrap_or(copied.len());
    match &copied[..end] {
        b"reno" => Some(net::TcpCongestionControl::Reno),
        b"cubic" => Some(net::TcpCongestionControl::Cubic),
        _ => None,
    }
}

// Route-metric conversion walks the complete nested
// stream in wire order; later duplicate values replace earlier ones.
fn parse_metrics(attrs: &[u8]) -> Result<net::RouteMetrics, RouteAttrError> {
    let mut metrics = net::RouteMetrics::NONE;
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let kind = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if len < 4 || off + len > attrs.len() { break; }
        if kind > rtax::RTAX_MAX { return Err(RouteAttrError::Invalid); }
        let payload = &attrs[off + 4..off + len];
        if kind == rtax::RTAX_CC_ALGO {
            metrics.cc_algo = Some(lookup_cc_algo(payload).ok_or(RouteAttrError::Invalid)?);
        } else if kind != rtax::RTAX_UNSPEC {
            let value = parse_u32(&attrs[off + 4..off + len])
                .ok_or(RouteAttrError::Invalid)?;
            match kind {
                rtax::RTAX_LOCK => metrics.lock = value,
                rtax::RTAX_MTU => metrics.mtu = value.min(RTAX_MTU_MAX),
                rtax::RTAX_WINDOW => metrics.window = value,
                rtax::RTAX_RTT => metrics.rtt_ms = value,
                rtax::RTAX_RTTVAR => metrics.rttvar_ms = value,
                rtax::RTAX_SSTHRESH => metrics.ssthresh = value,
                rtax::RTAX_CWND => metrics.cwnd = value,
                rtax::RTAX_ADVMSS => metrics.advmss = value.min(RTAX_ADVMSS_MAX),
                rtax::RTAX_REORDERING => metrics.reordering = value,
                rtax::RTAX_HOPLIMIT => metrics.hoplimit = value.min(u8::MAX as u32),
                rtax::RTAX_INITCWND => metrics.initcwnd = value,
                rtax::RTAX_FEATURES if value & !rtax::RTAX_FEATURE_MASK == 0 => {
                    metrics.features = value;
                }
                rtax::RTAX_FEATURES => return Err(RouteAttrError::Invalid),
                rtax::RTAX_RTO_MIN => metrics.rto_min_ms = value,
                rtax::RTAX_INITRWND => metrics.initrwnd = value,
                rtax::RTAX_QUICKACK => metrics.quickack = value,
                rtax::RTAX_FASTOPEN_NO_COOKIE => metrics.fastopen_no_cookie = value,
                _ => return Err(RouteAttrError::Invalid),
            }
        }
        off += nlmsg_align(len);
    }
    Ok(metrics)
}

// Route deletion metric filters use
// raw wire values, compare every duplicate, and turn malformed metrics into a
// failed match rather than an add-path validation error.
fn parse_metric_filters(attrs: &[u8]) -> Vec<RouteMetricFilter> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let kind = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if len < 4 || off + len > attrs.len() {
            out.push(RouteMetricFilter::Never);
            break;
        }
        let payload = &attrs[off + 4..off + len];
        if kind == rtax::RTAX_UNSPEC {
        } else if kind > rtax::RTAX_MAX {
            out.push(RouteMetricFilter::Never);
        } else if kind == rtax::RTAX_CC_ALGO {
            out.push(RouteMetricFilter::Cc(lookup_cc_algo(payload)));
        } else if let Some(value) = parse_u32(payload) {
            out.push(RouteMetricFilter::Scalar { kind, value });
        } else {
            out.push(RouteMetricFilter::Never);
        }
        off += nlmsg_align(len);
    }
    if off < attrs.len() { out.push(RouteMetricFilter::Never); }
    out
}

fn metric_scalar(metrics: net::RouteMetrics, kind: u16) -> Option<u32> {
    Some(match kind {
        rtax::RTAX_LOCK => metrics.lock,
        rtax::RTAX_MTU => metrics.mtu,
        rtax::RTAX_WINDOW => metrics.window,
        rtax::RTAX_RTT => metrics.rtt_ms,
        rtax::RTAX_RTTVAR => metrics.rttvar_ms,
        rtax::RTAX_SSTHRESH => metrics.ssthresh,
        rtax::RTAX_CWND => metrics.cwnd,
        rtax::RTAX_ADVMSS => metrics.advmss,
        rtax::RTAX_REORDERING => metrics.reordering,
        rtax::RTAX_HOPLIMIT => metrics.hoplimit,
        rtax::RTAX_INITCWND => metrics.initcwnd,
        rtax::RTAX_FEATURES => metrics.features,
        rtax::RTAX_RTO_MIN => metrics.rto_min_ms,
        rtax::RTAX_INITRWND => metrics.initrwnd,
        rtax::RTAX_QUICKACK => metrics.quickack,
        rtax::RTAX_FASTOPEN_NO_COOKIE => metrics.fastopen_no_cookie,
        _ => return None,
    })
}

/// Test delete-path `RTA_METRICS` predicates against canonical stored values. # C: O(N)
pub fn route_metrics_match(filters: &[RouteMetricFilter], metrics: net::RouteMetrics) -> bool {
    filters.iter().all(|filter| match *filter {
        RouteMetricFilter::Scalar { kind, value } => metric_scalar(metrics, kind) == Some(value),
        RouteMetricFilter::Cc(value) => metrics.cc_algo == value,
        RouteMetricFilter::Never => false,
    })
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

fn parse_route_attrs_mode(attrs: &[u8], validate_metrics: bool)
    -> Result<RouteAttrs, RouteAttrError>
{
    let mut out = RouteAttrs {
        dst: None, gateway: None, oif: None, prefsrc: None,
        table: None, metric: None, metrics: net::RouteMetrics::NONE,
        metric_filters: Vec::new(), multipath: Vec::new(),
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
            (rta::RTA_METRICS, _) => {
                if validate_metrics { out.metrics = parse_metrics(payload)?; }
                out.metric_filters = parse_metric_filters(payload);
            }
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

/// Parse add/replace `RTA_*` attributes following an rtmsg. # C: O(N attrs + multipath)
pub fn parse_route_attrs(attrs: &[u8]) -> Result<RouteAttrs, RouteAttrError> {
    parse_route_attrs_mode(attrs, true)
}

/// Parse delete selectors without add-path route-metric conversion. # C: O(N attrs + multipath)
pub fn parse_route_attrs_for_delete(attrs: &[u8]) -> Result<RouteAttrs, RouteAttrError> {
    parse_route_attrs_mode(attrs, false)
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

/// Append the complete nonzero `RTA_METRICS` state in ABI order. # C: O(RTAX_MAX)
pub fn put_metrics_attr(out: &mut Vec<u8>, metrics: net::RouteMetrics) {
    if metrics.is_empty() { return; }
    let mut nested = Vec::new();
    let values = [
        (rtax::RTAX_LOCK, metrics.lock),
        (rtax::RTAX_MTU, metrics.mtu),
        (rtax::RTAX_WINDOW, metrics.window),
        (rtax::RTAX_RTT, metrics.rtt_ms),
        (rtax::RTAX_RTTVAR, metrics.rttvar_ms),
        (rtax::RTAX_SSTHRESH, metrics.ssthresh),
        (rtax::RTAX_CWND, metrics.cwnd),
        (rtax::RTAX_ADVMSS, metrics.advmss),
        (rtax::RTAX_REORDERING, metrics.reordering),
        (rtax::RTAX_HOPLIMIT, metrics.hoplimit),
        (rtax::RTAX_INITCWND, metrics.initcwnd),
        (rtax::RTAX_FEATURES, metrics.features),
        (rtax::RTAX_RTO_MIN, metrics.rto_min_ms),
        (rtax::RTAX_INITRWND, metrics.initrwnd),
        (rtax::RTAX_QUICKACK, metrics.quickack),
    ];
    for (kind, value) in values {
        if value != 0 { crate::rtnetlink::put_nlattr_u32(&mut nested, kind, value); }
    }
    if let Some(cc) = metrics.cc_algo {
        let name = match cc {
            net::TcpCongestionControl::Reno => "reno",
            net::TcpCongestionControl::Cubic => "cubic",
        };
        crate::rtnetlink::put_nlattr_str(&mut nested, rtax::RTAX_CC_ALGO, name);
    }
    if metrics.fastopen_no_cookie != 0 {
        crate::rtnetlink::put_nlattr_u32(
            &mut nested, rtax::RTAX_FASTOPEN_NO_COOKIE, metrics.fastopen_no_cookie,
        );
    }
    crate::rtnetlink::put_nlattr(out, rta::RTA_METRICS, &nested);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_metric(attrs: &mut Vec<u8>, kind: u16, value: u32) {
        crate::rtnetlink::put_nlattr(attrs, kind, &value.to_ne_bytes());
    }

    #[test]
    fn metrics_walks_past_lock_and_last_mtu_wins() {
        let mut attrs = Vec::new();
        put_metric(&mut attrs, rtax::RTAX_LOCK, 1 << rtax::RTAX_MTU);
        put_metric(&mut attrs, rtax::RTAX_MTU, 1500);
        put_metric(&mut attrs, rtax::RTAX_MTU, 1400);
        let mut outer = Vec::new();
        crate::rtnetlink::put_nlattr(&mut outer, rta::RTA_METRICS, &attrs);
        let metrics = parse_route_attrs(&outer).unwrap().metrics;
        assert_eq!((metrics.lock, metrics.mtu), (1 << rtax::RTAX_MTU, 1400));
    }

    #[test]
    fn metrics_checks_bad_mtu_after_valid_mtu() {
        let mut attrs = Vec::new();
        put_metric(&mut attrs, rtax::RTAX_MTU, 1500);
        attrs.extend_from_slice(&7u16.to_ne_bytes());
        attrs.extend_from_slice(&rtax::RTAX_MTU.to_ne_bytes());
        attrs.extend_from_slice(&[1, 2, 3]);
        assert_eq!(parse_metrics(&attrs), Err(RouteAttrError::Invalid));
    }

    #[test]
    fn metrics_clamps_mtu_to_the_linux_ipv4_ceiling() {
        let mut attrs = Vec::new();
        put_metric(&mut attrs, rtax::RTAX_MTU, u32::MAX);
        assert_eq!(parse_metrics(&attrs).unwrap().mtu, RTAX_MTU_MAX);
    }

    #[test]
    fn metrics_rejects_types_beyond_linux_rtax_max() {
        let mut attrs = Vec::new();
        put_metric(&mut attrs, rtax::RTAX_MAX + 1, 1);
        assert_eq!(parse_metrics(&attrs), Err(RouteAttrError::Invalid));
    }

    #[test]
    fn metrics_accepts_an_unpadded_final_unspec_attr() {
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&5u16.to_ne_bytes());
        attrs.extend_from_slice(&rtax::RTAX_UNSPEC.to_ne_bytes());
        attrs.push(0xaa);
        assert_eq!(parse_metrics(&attrs), Ok(net::RouteMetrics::NONE));
    }

    #[test]
    fn metrics_ignores_an_invalid_nested_tail_after_valid_prefix() {
        let mut attrs = Vec::new();
        put_metric(&mut attrs, rtax::RTAX_MTU, 1500);
        attrs.extend_from_slice(&[0xff, 0xff, 0xaa]);
        assert_eq!(parse_metrics(&attrs).unwrap().mtu, 1500);
    }

    #[test]
    fn complete_metric_set_round_trips_without_loss() {
        let metrics = net::RouteMetrics {
            lock: 0x55aa,
            mtu: 1500,
            window: 65_535,
            rtt_ms: 12,
            rttvar_ms: 4,
            ssthresh: 32,
            cwnd: 20,
            advmss: 1440,
            reordering: 7,
            hoplimit: 48,
            initcwnd: 14,
            features: rtax::RTAX_FEATURE_ECN | rtax::RTAX_FEATURE_TIMESTAMP,
            rto_min_ms: 125,
            initrwnd: 16,
            quickack: 1,
            cc_algo: Some(net::TcpCongestionControl::Reno),
            fastopen_no_cookie: 1,
        };
        let mut outer = Vec::new();
        put_metrics_attr(&mut outer, metrics);
        assert_eq!(parse_route_attrs(&outer).unwrap().metrics, metrics);
    }

    #[test]
    fn metrics_validates_every_non_string_payload() {
        let mut attrs = Vec::new();
        crate::rtnetlink::put_nlattr(&mut attrs, rtax::RTAX_WINDOW, &[1, 2, 3]);
        assert_eq!(parse_metrics(&attrs), Err(RouteAttrError::Invalid));
    }

    #[test]
    fn metrics_rejects_unknown_feature_bits_and_cc_names() {
        let mut attrs = Vec::new();
        put_metric(&mut attrs, rtax::RTAX_FEATURES, !rtax::RTAX_FEATURE_MASK);
        assert_eq!(parse_metrics(&attrs), Err(RouteAttrError::Invalid));

        attrs.clear();
        crate::rtnetlink::put_nlattr_str(&mut attrs, rtax::RTAX_CC_ALGO, "not-present");
        assert_eq!(parse_metrics(&attrs), Err(RouteAttrError::Invalid));
    }

    #[test]
    fn metrics_clamps_advmss_and_hoplimit() {
        let mut attrs = Vec::new();
        put_metric(&mut attrs, rtax::RTAX_ADVMSS, u32::MAX);
        put_metric(&mut attrs, rtax::RTAX_HOPLIMIT, u32::MAX);
        let metrics = parse_metrics(&attrs).unwrap();
        assert_eq!((metrics.advmss, metrics.hoplimit), (RTAX_ADVMSS_MAX, u8::MAX as u32));
    }

    #[test]
    fn delete_metric_filters_use_raw_values_and_every_duplicate() {
        let stored = net::RouteMetrics { mtu: RTAX_MTU_MAX, ..net::RouteMetrics::NONE };
        let mut attrs = Vec::new();
        put_metric(&mut attrs, rtax::RTAX_MTU, RTAX_MTU_MAX);
        assert!(route_metrics_match(&parse_metric_filters(&attrs), stored));

        put_metric(&mut attrs, rtax::RTAX_MTU, u32::MAX);
        assert!(!route_metrics_match(&parse_metric_filters(&attrs), stored));
    }

    #[test]
    fn delete_unknown_cc_maps_to_the_unset_key() {
        let mut attrs = Vec::new();
        crate::rtnetlink::put_nlattr_str(&mut attrs, rtax::RTAX_CC_ALGO, "not-present");
        assert!(route_metrics_match(
            &parse_metric_filters(&attrs), net::RouteMetrics::NONE,
        ));
    }

    #[test]
    fn delete_malformed_metric_is_a_failed_match_not_a_parse_error() {
        let mut nested = Vec::new();
        crate::rtnetlink::put_nlattr(&mut nested, rtax::RTAX_WINDOW, &[1, 2, 3]);
        let mut outer = Vec::new();
        crate::rtnetlink::put_nlattr(&mut outer, rta::RTA_METRICS, &nested);
        let parsed = parse_route_attrs_for_delete(&outer).unwrap();
        assert!(!route_metrics_match(&parsed.metric_filters, net::RouteMetrics::NONE));

        let mut filters = Vec::new();
        put_metric(&mut filters, rtax::RTAX_MTU, 1_500);
        filters.extend_from_slice(&[0xff, 0xff, 0xaa]);
        assert!(!route_metrics_match(
            &parse_metric_filters(&filters),
            net::RouteMetrics { mtu: 1_500, ..net::RouteMetrics::NONE },
        ));
    }
}
