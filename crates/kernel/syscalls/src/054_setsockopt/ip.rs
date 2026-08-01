#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use crate::net_common::errno_from_neterr;
use super::multicast::{
    SourceOp, ipv4_group_filter, ipv4_mcast_group_req, ipv4_mcast_group_source_req,
    ipv4_mcast_if, ipv4_mcast_membership, ipv4_mcast_source_req, ipv4_msfilter,
};
use super::optval::{read_i32_required, read_u8_or_i32_required};
use super::uapi::*;

/// `setsockopt(fd, IPPROTO_IP, ...)`. # C: O(1)
pub(super) fn set(sock: &Arc<net::sock::InetSocket>, optname: u64,
                  optval: u64, optlen: u32) -> i64 {
    match optname {
        IP_ADD_MEMBERSHIP => return ipv4_mcast_membership(sock, optval, optlen, true),
        IP_DROP_MEMBERSHIP => return ipv4_mcast_membership(sock, optval, optlen, false),
        IP_MULTICAST_IF if optlen < 4 => return -(Errno::Einval.as_i32() as i64),
        IP_MULTICAST_TTL | IP_MULTICAST_LOOP if optlen == 0 =>
            return -(Errno::Einval.as_i32() as i64),
        _ => {}
    }
    match optname {
        IP_TOS => {
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            sock.opts.ip_tos.store(v & 0xff, Ordering::Release);
        }
        IP_TTL => {
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            // Linux `ip_setsockopt`: -1 keeps the route-selected hoplimit;
            // otherwise the value must be 1..=255 (0 and < -1 are EINVAL).
            if v != -1 && !(1..=255).contains(&v) { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.ip_ttl.store(v, Ordering::Release);
        }
        IP_PKTINFO => {
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            sock.opts.ip_pktinfo.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        IP_RECVTTL => {
            let v = match read_u8_or_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            sock.opts.ip_recvttl.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        IP_MTU_DISCOVER => {
            let v = match read_u8_or_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            if !net::uapi::valid_ip_pmtudisc(v) { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.ip_mtu_discover.store(v, Ordering::Release);
        }
        IP_RECVERR => {
            let v = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            sock.error.set_recverr4(v != 0);
        }
        IP_MULTICAST_TTL => {
            let v = match read_u8_or_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            return encode(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V4Ttl(v)));
        }
        IP_MULTICAST_LOOP => {
            let v = match read_u8_or_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
            return encode(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V4Loop(v)));
        }
        IP_MULTICAST_IF => return ipv4_mcast_if(sock, optval, optlen),
        IP_ADD_SOURCE_MEMBERSHIP => return ipv4_mcast_source_req(sock, optval, optlen, SourceOp::Join),
        IP_DROP_SOURCE_MEMBERSHIP => return ipv4_mcast_source_req(sock, optval, optlen, SourceOp::Leave),
        IP_BLOCK_SOURCE => return ipv4_mcast_source_req(sock, optval, optlen, SourceOp::Block),
        IP_UNBLOCK_SOURCE => return ipv4_mcast_source_req(sock, optval, optlen, SourceOp::Unblock),
        IP_MSFILTER => return ipv4_msfilter(sock, optval, optlen),
        MCAST_JOIN_GROUP => return ipv4_mcast_group_req(sock, optval, optlen, true),
        MCAST_LEAVE_GROUP => return ipv4_mcast_group_req(sock, optval, optlen, false),
        MCAST_JOIN_SOURCE_GROUP => return ipv4_mcast_group_source_req(sock, optval, optlen, SourceOp::Join),
        MCAST_LEAVE_SOURCE_GROUP => return ipv4_mcast_group_source_req(sock, optval, optlen, SourceOp::Leave),
        MCAST_BLOCK_SOURCE => return ipv4_mcast_group_source_req(sock, optval, optlen, SourceOp::Block),
        MCAST_UNBLOCK_SOURCE => return ipv4_mcast_group_source_req(sock, optval, optlen, SourceOp::Unblock),
        MCAST_MSFILTER => return ipv4_group_filter(sock, optval, optlen),
        _ => return -(Errno::Enoprotoopt.as_i32() as i64),
    }
    0
}

fn encode(result: net::NetResult<()>) -> i64 {
    match result { Ok(()) => 0, Err(error) => errno_from_neterr(error) }
}
