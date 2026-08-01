#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use crate::net_common::errno_from_neterr;
use super::multicast::{
    SourceOp, ipv6_group_filter, ipv6_mcast_group_req, ipv6_mcast_group_source_req,
    ipv6_mcast_membership,
};
use super::optval::read_i32_required;
use super::uapi::*;

/// `setsockopt(fd, IPPROTO_IPV6, ...)`. # C: O(1)
pub(super) fn set(sock: &Arc<net::sock::InetSocket>, optname: u64,
                  optval: u64, optlen: u32) -> i64 {
    match optname {
        IPV6_JOIN_GROUP => return ipv6_mcast_membership(sock, optval, optlen, true),
        IPV6_LEAVE_GROUP => return ipv6_mcast_membership(sock, optval, optlen, false),
        IPV6_MULTICAST_LOOP if optlen >= 4 && optval == 0 =>
            return encode(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V6Loop(0))),
        IPV6_MULTICAST_IF | IPV6_MULTICAST_HOPS | IPV6_MULTICAST_LOOP if optlen < 4 =>
            return -(Errno::Einval.as_i32() as i64),
        _ => {}
    }
    match optname {
        IPV6_V6ONLY => {
            if let Err(e) = require_v6(sock) { return e; }
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            if sock.local_port.lock().is_some() { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.ipv6_v6only.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        IPV6_RECVERR => {
            if let Err(e) = require_v6(sock) { return e; }
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            sock.error.set_recverr6(v != 0);
        }
        IPV6_MTU_DISCOVER => {
            if let Err(e) = require_v6(sock) { return e; }
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            if !net::uapi::valid_ipv6_pmtudisc(v) { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.ipv6_mtu_discover.store(v, Ordering::Release);
        }
        IPV6_UNICAST_HOPS => {
            if let Err(e) = require_v6(sock) { return e; }
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            if !(-1..=255).contains(&v) { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.ipv6_ucast_hops.store(v, Ordering::Release);
        }
        IPV6_MULTICAST_HOPS => {
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            return encode(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V6Hops(v)));
        }
        IPV6_MULTICAST_LOOP => {
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            return encode(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V6Loop(v)));
        }
        IPV6_MULTICAST_IF => {
            let idx = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            return encode(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V6Iface(idx)));
        }
        IPV6_RECVPKTINFO => {
            if let Err(e) = require_v6(sock) { return e; }
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            sock.opts.ipv6_recvpktinfo.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        IPV6_RECVHOPLIMIT => {
            if let Err(e) = require_v6(sock) { return e; }
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            sock.opts.ipv6_recvhoplimit.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        IPV6_TCLASS => {
            if let Err(e) = require_v6(sock) { return e; }
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            if !(-1..=255).contains(&v) { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.ipv6_tclass.store(v, Ordering::Release);
        }
        IPV6_RECVTCLASS => {
            if let Err(e) = require_v6(sock) { return e; }
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            sock.opts.ipv6_recvtclass.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        MCAST_JOIN_GROUP => return ipv6_mcast_group_req(sock, optval, optlen, true),
        MCAST_LEAVE_GROUP => return ipv6_mcast_group_req(sock, optval, optlen, false),
        MCAST_JOIN_SOURCE_GROUP => return ipv6_mcast_group_source_req(sock, optval, optlen, SourceOp::Join),
        MCAST_LEAVE_SOURCE_GROUP => return ipv6_mcast_group_source_req(sock, optval, optlen, SourceOp::Leave),
        MCAST_BLOCK_SOURCE => return ipv6_mcast_group_source_req(sock, optval, optlen, SourceOp::Block),
        MCAST_UNBLOCK_SOURCE => return ipv6_mcast_group_source_req(sock, optval, optlen, SourceOp::Unblock),
        MCAST_MSFILTER => return ipv6_group_filter(sock, optval, optlen),
        _ => return -(Errno::Enoprotoopt.as_i32() as i64),
    }
    0
}

fn encode(result: net::NetResult<()>) -> i64 {
    match result { Ok(()) => 0, Err(error) => errno_from_neterr(error) }
}

/// Gate IPPROTO_IPV6 options to AF_INET6 sockets, matching the family
/// check already used by the v6 multicast-membership helpers. # C: O(1)
pub(super) fn require_v6(sock: &Arc<net::sock::InetSocket>) -> Result<(), i64> {
    if sock.family.load(Ordering::Acquire) != net::sock::AF_INET6 {
        return Err(-(Errno::Eafnosupport.as_i32() as i64));
    }
    Ok(())
}
