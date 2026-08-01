// `IPPROTO_IPV6` readback copyout for slot 55. The value table and its length
// rules live in `net::sock_opts::sol_ipv6::get` (`docs/53§4`); this file only
// snapshots socket state and moves bytes.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use net::sock::InetSocket;
use net::sock_opts::sol_ipv6::get::{self as v6get, Ipv6GetState, Value};
use net::sock_opts::sol_ipv6::state::Sticky;
use net::sock_opts::sol_ipv6::uapi::*;
use net::sock_opts::sol_ipv6::{flag, flowlabel};

use super::multicast::{ipv6_group_filter_get, scalar_get};
use super::out::OptOut;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Snapshot the socket state the read table resolves against. # C: O(headers)
fn view(sock: &Arc<InetSocket>) -> Ipv6GetState {
    use net::sock_opts::sol_ipv6::set::{RECVHOPLIMIT, RECVPKTINFO, RECVTCLASS};
    let mut flags = sock.opts.ipv6.flags();
    if sock.opts.ipv6_recvpktinfo.load(Ordering::Acquire) != 0 { flags |= RECVPKTINFO; }
    if sock.opts.ipv6_recvhoplimit.load(Ordering::Acquire) != 0 { flags |= RECVHOPLIMIT; }
    if sock.opts.ipv6_recvtclass.load(Ordering::Acquire) != 0 { flags |= RECVTCLASS; }
    if sock.mcast.multicast_all_v6() { flags &= !flag::MC_ALL_OFF; }
    else { flags |= flag::MC_ALL_OFF; }
    Ipv6GetState {
        flags,
        v6only: sock.opts.ipv6_v6only.load(Ordering::Acquire) != 0,
        recverr: sock.error.recverr6(),
        mc_loop: sock.opts.ipv6_mcast_loop.load(Ordering::Acquire) != 0,
        hop_limit: sock.opts.ipv6_ucast_hops.load(Ordering::Acquire),
        mcast_hops: sock.opts.ipv6_mcast_hops.load(Ordering::Acquire),
        // This stack derives every unset hop limit from the namespace default
        // rather than from the route, so the route step never resolves.
        route_hoplimit: -1,
        default_hoplimit: net::ipv6::IPV6_DEFAULT_HOP_LIMIT as i32,
        mcast_oif: sock.opts.ipv6_mcast_ifindex.load(Ordering::Acquire),
        unicast_if: sock.opts.ipv6.unicast_if(),
        pmtudisc: sock.opts.ipv6_mtu_discover.load(Ordering::Acquire),
        tclass: sock.opts.ipv6_tclass.load(Ordering::Acquire).max(0),
        min_hopcount: sock.opts.ipv6.min_hopcount(),
        srcprefs: sock.opts.ipv6.srcprefs(),
        frag_size: sock.opts.ipv6.frag_size(),
        use_min_mtu: sock.opts.ipv6.use_min_mtu(),
        default_autoflowlabel: false,
        // The path-MTU reads own their route lookup and their own copyout.
        mtu: 0,
        headers: [
            sock.opts.ipv6.header(Sticky::HopOpts),
            sock.opts.ipv6.header(Sticky::RthdrDstOpts),
            sock.opts.ipv6.header(Sticky::Rthdr),
            sock.opts.ipv6.header(Sticky::DstOpts),
        ],
        family: sock.family.load(Ordering::Acquire) as i32,
    }
}

/// `getsockopt(fd, IPPROTO_IPV6, ...)`. # C: O(headers)
pub(super) fn get(sock: &Arc<InetSocket>, optname: u64, out: &OptOut) -> i64 {
    match optname {
        MCAST_MSFILTER => return ipv6_group_filter_get(sock, out.optval, out.optlen_p),
        IPV6_MULTICAST_LOOP =>
            return scalar_get(sock, net::sock_mcast::McastScalarGet::V6Loop, out),
        IPV6_MULTICAST_IF =>
            return scalar_get(sock, net::sock_mcast::McastScalarGet::V6Iface, out),
        IPV6_MTU => return super::path_mtu::socket_path_mtu(sock, true, out),
        IPV6_PATHMTU => return path_mtu_info(sock, out),
        IPV6_FLOWLABEL_MGR => return flow_label(sock, out),
        _ => {}
    }
    let value = match v6get::read(optname, net::sock_opts::describe_ipv6(sock), &view(sock)) {
        Ok(v) => v, Err(e) => return errno(e),
    };
    publish(out, value)
}

/// `IPV6_PATHMTU`: the whole information structure, refused rather than
/// truncated when the caller's buffer cannot hold it. # C: O(log N)
fn path_mtu_info(sock: &Arc<InetSocket>, out: &OptOut) -> i64 {
    let requested = match requested_unchecked(out.optlen_p) { Ok(v) => v, Err(e) => return errno(e) };
    if let Err(e) = v6get::exact_len(IP6_MTUINFO_SIZE, requested) { return errno(e); }
    let Some((ip, _)) = *sock.peer6.lock() else { return errno(Errno::Enotconn); };
    let raw = sock.opts.bound_ifindex.load(Ordering::Acquire);
    let bound = if raw == 0 { None } else { Some(net::NetIfaceId::from_raw(raw)) };
    match net::sock::stack().path_mtu(net::IpAddr::V6(ip), bound, false) {
        Ok(mtu) => out.exact(&v6get::mtuinfo(mtu)),
        Err(error) => crate::net_common::errno_from_neterr(error),
    }
}

/// `IPV6_FLOWLABEL_MGR` read: the caller supplies a request naming what to
/// report, and the answer overwrites it. # C: O(log N)
fn flow_label(sock: &Arc<InetSocket>, out: &OptOut) -> i64 {
    let requested = match requested_unchecked(out.optlen_p) { Ok(v) => v, Err(e) => return errno(e) };
    if let Err(e) = v6get::exact_len(IN6_FLOWLABEL_REQ_SIZE, requested) { return errno(e); }
    let mut bytes = [0u8; IN6_FLOWLABEL_REQ_SIZE];
    if uaccess::copy_from_user(&mut bytes, out.optval).is_err() { return errno(Errno::Efault); }
    let req = flowlabel::FlowReq::parse(&bytes);
    if req.action != IPV6_FL_A_GET { return errno(Errno::Einval); }
    let mut answer = flowlabel::FlowReq::default();
    // The remote query reports the label the last datagram arrived with.
    if req.flags & IPV6_FL_F_REMOTE != 0 {
        answer.label = sock.opts.ipv6.rcv_flowinfo() & IPV6_FLOWINFO_FLOWLABEL;
        return out.exact(&answer.encode());
    }
    if sock.opts.ipv6.flag(flag::REPFLOW) {
        answer.label = sock.opts.ipv6.flow_label();
        return out.exact(&answer.encode());
    }
    let label = sock.opts.ipv6.flow_label();
    let Some(lease) = flowlabel::table().lookup(sock.net_ns(), label) else {
        return errno(Errno::Enoent);
    };
    answer.label = lease.label;
    answer.dst = lease.dst;
    answer.share = lease.share;
    answer.expires = (lease.expires_ns / 1_000_000_000).min(u16::MAX as u64) as u16;
    answer.linger = (lease.linger_ns / 1_000_000_000).min(u16::MAX as u64) as u16;
    out.exact(&answer.encode())
}

fn publish(out: &OptOut, value: Value) -> i64 {
    let requested = match requested_unchecked(out.optlen_p) {
        Ok(v) => v, Err(e) => return errno(e),
    };
    match value {
        // This level never narrows an `int` to a byte, and never screens a
        // negative caller length.
        Value::Int(v) => out.exact(&v.to_ne_bytes()[..v6get::int_len(requested)]),
        Value::Bytes(bytes) => {
            let len = core::cmp::min(requested.max(0) as usize, bytes.len());
            out.exact(&bytes[..len])
        }
        Value::Exact(bytes) => match v6get::exact_len(bytes.len(), requested) {
            Ok(len) => out.exact(&bytes[..len]),
            Err(e) => errno(e),
        },
        Value::Delegated => errno(Errno::Enoprotoopt),
    }
}

fn requested_unchecked(optlen_p: u64) -> Result<i32, Errno> {
    let mut raw = [0u8; 4];
    uaccess::copy_from_user(&mut raw, optlen_p).map_err(|_| Errno::Efault)?;
    Ok(i32::from_ne_bytes(raw))
}
