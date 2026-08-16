// TCP metrics generic-netlink family: projects the canonical per-namespace
// destination metrics cache — the path measurements a closing connection left
// behind and the fast-open state for the same row — and deletes rows from it.
//
// The two microsecond metrics are not stored separately. A round trip is HELD
// in microseconds and reported twice: raw under the microsecond attribute, and
// divided down under the millisecond one, so `ip tcp_metrics` reads a
// consistent pair whichever it looks at.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use super::attr;
use super::family::{self, GenlFamilySpec, GenlOp, PolicyEntry};
use super::message;
use super::uapi::{op_flags, policy_type};
use crate::Nlmsghdr;

/// Family name userspace resolves through `nlctrl`.
pub const TCP_METRICS_FAMILY_NAME: &str = "tcp_metrics";
/// Family protocol version.
pub const TCP_METRICS_FAMILY_VERSION: u8 = 1;

/// `TCP_METRICS_CMD_*` commands.
pub mod cmd {
    pub const GET: u8 = 1;
    pub const DEL: u8 = 2;
}

/// `TCP_METRICS_ATTR_*` attributes.
pub mod attr_id {
    pub const ADDR_IPV4: u16 = 1;
    pub const ADDR_IPV6: u16 = 2;
    pub const AGE: u16 = 3;
    /// Nested `TCP_METRICS_A_METRICS_*` values.
    pub const VALS: u16 = 5;
    pub const FOPEN_MSS: u16 = 6;
    pub const FOPEN_SYN_DROPS: u16 = 7;
    pub const FOPEN_SYN_DROP_TS: u16 = 8;
    pub const FOPEN_COOKIE: u16 = 9;
    pub const SADDR_IPV4: u16 = 10;
    pub const SADDR_IPV6: u16 = 11;
    pub const PAD: u16 = 12;
    pub const MAX: u16 = PAD;
}

const NS_PER_MS: u64 = 1_000_000;
const GET_POLICY: &[PolicyEntry] = &[
    PolicyEntry { attr: attr_id::ADDR_IPV4, kind: policy_type::NL_ATTR_TYPE_U32, min_len: 4, max_len: 4 },
    PolicyEntry { attr: attr_id::ADDR_IPV6, kind: policy_type::NL_ATTR_TYPE_BINARY, min_len: 16, max_len: 16 },
    PolicyEntry { attr: attr_id::SADDR_IPV4, kind: policy_type::NL_ATTR_TYPE_U32, min_len: 4, max_len: 4 },
    PolicyEntry { attr: attr_id::SADDR_IPV6, kind: policy_type::NL_ATTR_TYPE_BINARY, min_len: 16, max_len: 16 },
];

/// Register the TCP metrics family. # C: O(N families)
pub fn init() -> Result<u16, family::GenlRegError> {
    family::register_family(GenlFamilySpec {
        name: TCP_METRICS_FAMILY_NAME, version: TCP_METRICS_FAMILY_VERSION,
        hdrsize: 0, maxattr: attr_id::MAX,
        ops: alloc::vec![
            GenlOp { cmd: cmd::GET,
                flags: op_flags::GENL_CMD_CAP_DO | op_flags::GENL_CMD_CAP_HASPOL,
                policy: GET_POLICY , ..GenlOp::EMPTY},
            GenlOp { cmd: cmd::DEL,
                flags: op_flags::GENL_CMD_CAP_DO | op_flags::GENL_CMD_CAP_HASPOL,
                policy: GET_POLICY , ..GenlOp::EMPTY}],
        mcgrps: Vec::new(), netnsok: true, resv_start_op: cmd::DEL + 1,
    })
}

fn address(attrs: &[u8], v4: u16, v6: u16) -> Result<Option<net::IpAddr>, Errno> {
    if let Some(attr) = attr::find(attrs, v4) {
        let Some(bytes) = attr.payload.get(..4) else { return Err(Errno::Einval); };
        return Ok(Some(net::IpAddr::V4(net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))));
    }
    if let Some(attr) = attr::find(attrs, v6) {
        let Some(bytes) = attr.payload.get(..16) else { return Err(Errno::Einval); };
        let mut octets = [0u8; 16];
        octets.copy_from_slice(bytes);
        return Ok(Some(net::IpAddr::V6(net::Ipv6Addr(octets))));
    }
    Ok(None)
}

fn put_address(out: &mut Vec<u8>, addr: net::IpAddr, v4: u16, v6: u16) {
    match addr {
        net::IpAddr::V4(addr) => attr::put(out, v4, &addr.octets()),
        net::IpAddr::V6(addr) => attr::put(out, v6, &addr.0),
    }
}

/// Emit the `TCP_METRICS_ATTR_VALS` nest. A slot holding nothing is omitted,
/// and an empty nest is not emitted at all — an absent metric and a zero one
/// are the same thing, and a reader must not have to tell them apart.
/// # C: O(metrics)
fn put_vals(out: &mut Vec<u8>, metrics: &net::tcp_metrics::Metrics) {
    use net::tcp_metrics::ids;
    let at = attr::nest_start(out, attr_id::VALS);
    let mut emitted = 0;
    for (metric, value) in metrics.vals.iter().enumerate() {
        let value = *value;
        if value == 0 { continue; }
        // The two microsecond metrics report the stored value raw; the
        // millisecond attribute of the same slot reports it divided down.
        let millis = match metric {
            ids::RTT => { attr::put_u32(out, ids::ATTR_RTT_US, value); emitted += 1;
                Some(ids::millis(value)) }
            ids::RTTVAR => { attr::put_u32(out, ids::ATTR_RTTVAR_US, value); emitted += 1;
                Some(ids::millis(value)) }
            _ => None,
        };
        attr::put_u32(out, ids::attr(metric), millis.unwrap_or(value));
        emitted += 1;
    }
    if emitted == 0 { out.truncate(at); return; }
    attr::nest_end(out, at);
}

/// The destination the request names, resolved against a live namespace.
/// # C: O(1)
fn request(hdr: &Nlmsghdr, attrs: &[u8], net_ns: u64)
    -> Result<(network_namespace::NetworkNamespaceRef, Option<net::IpAddr>, net::IpAddr), Vec<u8>>
{
    let dst = match address(attrs, attr_id::ADDR_IPV4, attr_id::ADDR_IPV6) {
        Ok(Some(dst)) => dst,
        Ok(None) => return Err(message::error(hdr, Err(Errno::Eafnosupport))),
        Err(e) => return Err(message::error(hdr, Err(e))),
    };
    let src = match address(attrs, attr_id::SADDR_IPV4, attr_id::SADDR_IPV6) {
        Ok(src) => src, Err(e) => return Err(message::error(hdr, Err(e))),
    };
    if src.is_some_and(|src| core::mem::discriminant(&src) != core::mem::discriminant(&dst)) {
        return Err(message::error(hdr, Err(Errno::Eafnosupport)));
    }
    let Some(namespace) = network_namespace::lookup_u64(net_ns) else {
        return Err(message::error(hdr, Err(Errno::Enoent)));
    };
    Ok((namespace, src, dst))
}

/// Serve `TCP_METRICS_CMD_DEL`: forget what this namespace learned about one
/// destination. A destination it held nothing for is `ESRCH`. # C: O(log N)
pub fn del(hdr: &Nlmsghdr, attrs: &[u8], net_ns: u64) -> Vec<u8> {
    let (namespace, src, dst) = match request(hdr, attrs, net_ns) {
        Ok(parsed) => parsed, Err(reply) => return reply,
    };
    let held = net::tcp_metrics::forget(&namespace, src, dst);
    message::error(hdr, if held { Ok(()) } else { Err(Errno::Esrch) })
}

/// Serve `TCP_METRICS_CMD_GET` from the namespace's canonical metrics cache.
/// # C: O(log N)
pub fn get(hdr: &Nlmsghdr, attrs: &[u8], net_ns: u64) -> Vec<u8> {
    let (namespace, src, dst) = match request(hdr, attrs, net_ns) {
        Ok(parsed) => parsed, Err(reply) => return reply,
    };
    let Some(metrics) = net::tcp_metrics::row(&namespace, src, dst,
        net::tcp_conn::ka_now_ns()) else {
        return message::error(hdr, Err(Errno::Esrch));
    };
    let Some(family) = family::find_by_name(TCP_METRICS_FAMILY_NAME) else {
        return message::error(hdr, Err(Errno::Enoent));
    };
    let mut out = message::start(hdr.nlmsg_pid, hdr.nlmsg_seq, family.id,
        TCP_METRICS_FAMILY_VERSION, 0, cmd::GET);
    put_address(&mut out, metrics.dst, attr_id::ADDR_IPV4, attr_id::ADDR_IPV6);
    put_address(&mut out, metrics.src, attr_id::SADDR_IPV4, attr_id::SADDR_IPV6);
    attr::put_u64_64bit(&mut out, attr_id::AGE, metrics.age_ns / NS_PER_MS, attr_id::PAD);
    put_vals(&mut out, &metrics);
    if metrics.mss != 0 { attr::put_u16(&mut out, attr_id::FOPEN_MSS, metrics.mss); }
    if metrics.syn_loss != 0 {
        attr::put_u16(&mut out, attr_id::FOPEN_SYN_DROPS, metrics.syn_loss);
        attr::put_u64_64bit(&mut out, attr_id::FOPEN_SYN_DROP_TS,
            metrics.syn_loss_age_ns / NS_PER_MS, attr_id::PAD);
    }
    if let Some(cookie) = metrics.cookie { attr::put(&mut out, attr_id::FOPEN_COOKIE, cookie.as_bytes()); }
    message::end(&mut out, 0);
    out
}
