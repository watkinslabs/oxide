#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use hal::USER_VA_END;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::net_common::{errno_from_neterr, fd_file, socket_from_file, vsock_from_file};
use crate::net_trace::trace_enotsock_at;
use super::multicast::{
    SourceOp, ipv4_group_filter, ipv4_mcast_group_req, ipv4_mcast_group_source_req,
    ipv4_mcast_if, ipv4_mcast_membership, ipv4_mcast_source_req, ipv6_mcast_membership,
    ipv4_msfilter, ipv6_group_filter, ipv6_mcast_group_req, ipv6_mcast_group_source_req,
};
use super::raw::raw_setsockopt;
use super::packet::packet_setsockopt;
use super::uapi::*;
use super::vsock::vsock_setsockopt;
/// `setsockopt(fd, level, optname, optval, optlen)` slot 54. # C: O(1)
pub fn sys_setsockopt(args: &SyscallArgs) -> i64 {
    let fd = args.a0;
    let level = args.a1;
    let optname = args.a2;
    let optval = args.a3;
    let signed_optlen = args.a4 as i32;
    let file = match fd_file(fd) {
        Some(file) => file,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if level == SOL_SOCKET && matches!(optname, SO_ATTACH_BPF | SO_ATTACH_FILTER
        | SO_DETACH_FILTER | SO_LOCK_FILTER)
    {
        let target = match socket::FilterFile::from_file(file.clone()) {
            Some(target) => target,
            None => return -(Errno::Enotsock.as_i32() as i64),
        };
        let (namespace, family) = target.option_context();
        if let Err(error) = net::security_admission::check(namespace, family, security::network::Operation::Option) { return errno_from_neterr(error); }
        if signed_optlen < 0 { return -(Errno::Einval.as_i32() as i64); }
        return socket_filter_option(&target, optname, optval, signed_optlen as u32);
    }
    if let Some(target) = crate::netlink_fd::from_file(file.clone()) {
        if signed_optlen < 0 { return -(Errno::Einval.as_i32() as i64); }
        let optlen = signed_optlen as u32;
        return crate::netlink_fd::setsockopt(&target, level, optname, optval, optlen as u64);
    }
    if let Some(vsock) = vsock_from_file(file.clone()) {
        if let Err(error) = vsock.check_option() { return errno_from_neterr(error); }
        return vsock_setsockopt(&vsock, level, optname, optval, signed_optlen);
    }
    let sock = match socket_from_file(file) {
        Some(s) => s,
        None => {
            trace_enotsock_at(fd, b"setsockopt");
            return -(Errno::Enotsock.as_i32() as i64);
        }
    };
    if let Err(error) = net::sock_opts::check_option(&sock) {
        return errno_from_neterr(error);
    }
    if signed_optlen < 0 { return -(Errno::Einval.as_i32() as i64); }
    let optlen = signed_optlen as u32;
    if level == net::uapi::SOL_PACKET {
        return packet_setsockopt(&sock, optname, optval, optlen);
    }
    if let Some(op) = multicast_preflight(level, optname) {
        if let Err(error) = sock.preflight_mcast_set(op) { return errno_from_neterr(error); }
    }
    if let Some(result) = raw_setsockopt(&sock, level, optname, optval, optlen) {
        return result;
    }
    match (level, optname) {
        (IPPROTO_IP, IP_ADD_MEMBERSHIP) => return ipv4_mcast_membership(&sock, optval, optlen, true),
        (IPPROTO_IP, IP_DROP_MEMBERSHIP) => return ipv4_mcast_membership(&sock, optval, optlen, false),
        (IPPROTO_IPV6, IPV6_JOIN_GROUP) => return ipv6_mcast_membership(&sock, optval, optlen, true),
        (IPPROTO_IPV6, IPV6_LEAVE_GROUP) => return ipv6_mcast_membership(&sock, optval, optlen, false),
        _ => {}
    }
    if level == IPPROTO_IPV6 && optname == IPV6_MULTICAST_LOOP {
        if optlen < 4 { return -(Errno::Einval.as_i32() as i64); }
        if optval == 0 {
            return encode_mcast(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V6Loop(0)));
        }
    }
    match (level, optname) {
        (IPPROTO_IP, IP_MULTICAST_IF) if optlen < 4 =>
            return -(Errno::Einval.as_i32() as i64),
        (IPPROTO_IP, IP_MULTICAST_TTL | IP_MULTICAST_LOOP) if optlen == 0 =>
            return -(Errno::Einval.as_i32() as i64),
        (IPPROTO_IPV6, IPV6_MULTICAST_IF | IPV6_MULTICAST_HOPS | IPV6_MULTICAST_LOOP)
            if optlen < 4 => return -(Errno::Einval.as_i32() as i64),
        _ => {}
    }
    if optval == 0 || optval >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let read_i32 = |o: u64| -> Option<i32> {
        if optlen < 4 { return None; }
        let mut bytes = [0u8; 4];
        uaccess::copy_from_user(&mut bytes, o).ok()?;
        Some(i32::from_ne_bytes(bytes))
    };
    let read_i32_required = || -> Result<i32, i64> {
        read_i32(optval).ok_or(if optlen < 4 {
            -(Errno::Einval.as_i32() as i64)
        } else {
            -(Errno::Efault.as_i32() as i64)
        })
    };
    match (level, optname) {
        (SOL_SOCKET, 2) => {
            let v = match read_i32_required() { Ok(v) => v, Err(e) => return e };
            sock.opts.reuseaddr.store(v, Ordering::Release);
        },
        (SOL_SOCKET, 15) => {
            let v = match read_i32_required() { Ok(v) => v, Err(e) => return e };
            sock.opts.reuseport.store(v, Ordering::Release);
        },
        (SOL_SOCKET, 9) => {
            let v = match read_i32_required() { Ok(v) => v, Err(e) => return e };
            sock.opts.keepalive.store(v, Ordering::Release);
            refresh_tcp_keepalive(&sock);
        }
        (SOL_SOCKET, 6) => {
            let v = match read_i32_required() { Ok(v) => v, Err(e) => return e };
            sock.opts.broadcast.store(v, Ordering::Release);
        },
        (SOL_SOCKET, net::uapi::SO_OOBINLINE) => {
            let v = match read_i32_required() { Ok(v) => v, Err(e) => return e };
            sock.opts.oobinline.store((v != 0) as i32, Ordering::Release);
        },
        (SOL_SOCKET, SO_SNDBUF) | (SOL_SOCKET, SO_SNDBUFFORCE) =>
            { let v = match read_i32_required() { Ok(v) => v, Err(e) => return e };
              sock.opts.sndbuf.store(v, Ordering::Release); },
        (SOL_SOCKET, SO_RCVBUF) | (SOL_SOCKET, SO_RCVBUFFORCE) =>
            { let v = match read_i32_required() { Ok(v) => v, Err(e) => return e };
              sock.opts.rcvbuf.store(v, Ordering::Release);
              sync_raw_rcvbuf(&sock, v); },
        (SOL_SOCKET, 16) => {
            let v = match read_i32_required() { Ok(v) => v, Err(e) => return e };
            sock.opts.passcred.store(v, Ordering::Release);
        }
        (SOL_SOCKET, SO_TIMESTAMP_OLD) | (SOL_SOCKET, SO_TIMESTAMPNS_OLD)
        | (SOL_SOCKET, SO_TIMESTAMPING_OLD) | (SOL_SOCKET, SO_TIMESTAMP_NEW)
        | (SOL_SOCKET, SO_TIMESTAMPNS_NEW) | (SOL_SOCKET, SO_TIMESTAMPING_NEW) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            sock.opts.timestamping.store(v, Ordering::Release);
        }
        (SOL_SOCKET, 12) => priority_store(&sock, read_i32(optval)),
        (SOL_SOCKET, 36) => mark_store(&sock, read_i32(optval)),
        (SOL_SOCKET, SO_BINDTODEVICE) => {
            let rc = bind_to_device(&sock, optval, optlen);
            if rc != 0 { return rc; }
        }
        (SOL_SOCKET, 13) => {
            if optlen < 8 { return -(Errno::Einval.as_i32() as i64); }
            let mut bytes = [0u8; 8];
            if uaccess::copy_from_user(&mut bytes, optval).is_err() {
                return -(Errno::Efault.as_i32() as i64);
            }
            sock.opts.linger_on.store(i32::from_ne_bytes(bytes[..4].try_into().unwrap()), Ordering::Release);
            sock.opts.linger_s.store(i32::from_ne_bytes(bytes[4..].try_into().unwrap()), Ordering::Release);
        }
        (SOL_SOCKET, 21) | (SOL_SOCKET, 20) => {
            if optlen < 16 { return -(Errno::Einval.as_i32() as i64); }
            let mut bytes = [0u8; 16];
            if uaccess::copy_from_user(&mut bytes, optval).is_err() {
                return -(Errno::Efault.as_i32() as i64);
            }
            let s = i64::from_ne_bytes(bytes[..8].try_into().unwrap());
            let u = i64::from_ne_bytes(bytes[8..].try_into().unwrap());
            let ns = (s.max(0) as i128 * 1_000_000_000 + u.max(0) as i128 * 1_000)
                .min(i64::MAX as i128) as i64;
            let slot = if optname == 21 { &sock.opts.sndtimeo_ns } else { &sock.opts.rcvtimeo_ns };
            slot.store(ns, Ordering::Release);
        }
        (IPPROTO_IP, IP_TOS) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            sock.opts.ip_tos.store(v & 0xff, Ordering::Release);
        }
        (IPPROTO_IP, IP_TTL) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            if !(1..=255).contains(&v) { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.ip_ttl.store(v, Ordering::Release);
        }
        (IPPROTO_IP, IP_PKTINFO) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            sock.opts.ip_pktinfo.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        (IPPROTO_IP, IP_RECVTTL) => {
            let Some(v) = read_u8_or_i32(optval, optlen) else { return -(Errno::Einval.as_i32() as i64); };
            sock.opts.ip_recvttl.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        (IPPROTO_IP, IP_MTU_DISCOVER) => {
            let Some(v) = read_u8_or_i32(optval, optlen) else { return -(Errno::Einval.as_i32() as i64); };
            if !net::uapi::valid_ip_pmtudisc(v) { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.ip_mtu_discover.store(v, Ordering::Release);
        }
        (IPPROTO_IP, IP_RECVERR) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            sock.error.set_recverr4(v != 0);
        }
        (IPPROTO_IP, IP_MULTICAST_TTL) => {
            let Some(v) = read_u8_or_i32(optval, optlen) else { return -(Errno::Einval.as_i32() as i64); };
            return encode_mcast(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V4Ttl(v)));
        }
        (IPPROTO_IP, IP_MULTICAST_LOOP) => {
            let Some(v) = read_u8_or_i32(optval, optlen) else { return -(Errno::Einval.as_i32() as i64); };
            return encode_mcast(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V4Loop(v)));
        }
        (IPPROTO_IP, IP_MULTICAST_IF) => return ipv4_mcast_if(&sock, optval, optlen),
        (IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP) => return ipv4_mcast_source_req(&sock, optval, optlen, SourceOp::Join),
        (IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP) => return ipv4_mcast_source_req(&sock, optval, optlen, SourceOp::Leave),
        (IPPROTO_IP, IP_BLOCK_SOURCE) => return ipv4_mcast_source_req(&sock, optval, optlen, SourceOp::Block),
        (IPPROTO_IP, IP_UNBLOCK_SOURCE) => return ipv4_mcast_source_req(&sock, optval, optlen, SourceOp::Unblock),
        (IPPROTO_IP, IP_MSFILTER) => return ipv4_msfilter(&sock, optval, optlen),
        (IPPROTO_IP, MCAST_JOIN_GROUP) => return ipv4_mcast_group_req(&sock, optval, optlen, true),
        (IPPROTO_IP, MCAST_LEAVE_GROUP) => return ipv4_mcast_group_req(&sock, optval, optlen, false),
        (IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP) => return ipv4_mcast_group_source_req(&sock, optval, optlen, SourceOp::Join),
        (IPPROTO_IP, MCAST_LEAVE_SOURCE_GROUP) => return ipv4_mcast_group_source_req(&sock, optval, optlen, SourceOp::Leave),
        (IPPROTO_IP, MCAST_BLOCK_SOURCE) => return ipv4_mcast_group_source_req(&sock, optval, optlen, SourceOp::Block),
        (IPPROTO_IP, MCAST_UNBLOCK_SOURCE) => return ipv4_mcast_group_source_req(&sock, optval, optlen, SourceOp::Unblock),
        (IPPROTO_IP, MCAST_MSFILTER) => return ipv4_group_filter(&sock, optval, optlen),
        (IPPROTO_IPV6, IPV6_V6ONLY) => {
            if let Err(e) = require_v6(&sock) { return e; }
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            if sock.local_port.lock().is_some() { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.ipv6_v6only.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        (IPPROTO_IPV6, IPV6_RECVERR) => {
            if let Err(e) = require_v6(&sock) { return e; }
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            sock.error.set_recverr6(v != 0);
        }
        (IPPROTO_IPV6, IPV6_MTU_DISCOVER) => {
            if let Err(e) = require_v6(&sock) { return e; }
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            if !net::uapi::valid_ipv6_pmtudisc(v) { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.ipv6_mtu_discover.store(v, Ordering::Release);
        }
        (IPPROTO_IPV6, IPV6_UNICAST_HOPS) => {
            if let Err(e) = require_v6(&sock) { return e; }
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            if !(-1..=255).contains(&v) { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.ipv6_ucast_hops.store(v, Ordering::Release);
        }
        (IPPROTO_IPV6, IPV6_MULTICAST_HOPS) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            return encode_mcast(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V6Hops(v)));
        }
        (IPPROTO_IPV6, IPV6_MULTICAST_LOOP) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            return encode_mcast(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V6Loop(v)));
        }
        (IPPROTO_IPV6, IPV6_MULTICAST_IF) => {
            let Some(idx) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            return encode_mcast(sock.set_mcast_scalar(net::sock_mcast::McastScalar::V6Iface(idx)));
        }
        (IPPROTO_IPV6, IPV6_RECVPKTINFO) => {
            if let Err(e) = require_v6(&sock) { return e; }
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            sock.opts.ipv6_recvpktinfo.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        (IPPROTO_IPV6, IPV6_RECVHOPLIMIT) => {
            if let Err(e) = require_v6(&sock) { return e; }
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            sock.opts.ipv6_recvhoplimit.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        (IPPROTO_IPV6, MCAST_JOIN_GROUP) => return ipv6_mcast_group_req(&sock, optval, optlen, true),
        (IPPROTO_IPV6, MCAST_LEAVE_GROUP) => return ipv6_mcast_group_req(&sock, optval, optlen, false),
        (IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP) => return ipv6_mcast_group_source_req(&sock, optval, optlen, SourceOp::Join),
        (IPPROTO_IPV6, MCAST_LEAVE_SOURCE_GROUP) => return ipv6_mcast_group_source_req(&sock, optval, optlen, SourceOp::Leave),
        (IPPROTO_IPV6, MCAST_BLOCK_SOURCE) => return ipv6_mcast_group_source_req(&sock, optval, optlen, SourceOp::Block),
        (IPPROTO_IPV6, MCAST_UNBLOCK_SOURCE) => return ipv6_mcast_group_source_req(&sock, optval, optlen, SourceOp::Unblock),
        (IPPROTO_IPV6, MCAST_MSFILTER) => return ipv6_group_filter(&sock, optval, optlen),
        (IPPROTO_TCP, 1) => {
            let v = match read_i32_required() { Ok(v) => v, Err(e) => return e };
            sock.opts.tcp_nodelay.store(v, Ordering::Release);
        }
        (IPPROTO_TCP, TCP_CORK) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            let new = if v != 0 { 1 } else { 0 };
            let old = sock.opts.tcp_cork.swap(new, Ordering::AcqRel);
            if old != 0 && new == 0 {
                let entry = match &*sock.kind.lock() {
                    net::sock::SockKind::TcpConn(entry) => Some(entry.clone()),
                    _ => None,
                };
                if let Some(entry) = entry {
                    let nodelay = sock.opts.tcp_nodelay.load(Ordering::Acquire) != 0;
                    let _ = net::sock::stack().tcp_send(&entry, &[], usize::MAX, nodelay, false);
                    net::sock::drain_loopback();
                }
            }
        }
        (IPPROTO_TCP, TCP_KEEPIDLE) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            if v <= 0 { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.tcp_keepidle_s.store(v, Ordering::Release);
            refresh_tcp_keepalive(&sock);
        }
        (IPPROTO_TCP, TCP_KEEPINTVL) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            if v <= 0 { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.tcp_keepintvl_s.store(v, Ordering::Release);
            refresh_tcp_keepalive(&sock);
        }
        (IPPROTO_TCP, TCP_KEEPCNT) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            if v <= 0 { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.tcp_keepcnt.store(v, Ordering::Release);
            refresh_tcp_keepalive(&sock);
        }
        _ => return -(Errno::Enoprotoopt.as_i32() as i64),
    }
    0
}

fn encode_mcast(result: net::NetResult<()>) -> i64 {
    match result { Ok(()) => 0, Err(error) => errno_from_neterr(error) }
}

fn multicast_preflight(level: u64, optname: u64) -> Option<net::sock_mcast::McastSetOp> {
    use net::sock_mcast::McastSetOp::*;
    match (level, optname) {
        (IPPROTO_IP, IP_MULTICAST_IF) => Some(V4Iface),
        (IPPROTO_IP, IP_MULTICAST_TTL) => Some(V4Ttl),
        (IPPROTO_IP, IP_ADD_MEMBERSHIP | IP_DROP_MEMBERSHIP) => Some(V4Membership),
        (IPPROTO_IP, IP_MULTICAST_LOOP | IP_UNBLOCK_SOURCE | IP_BLOCK_SOURCE
            | IP_ADD_SOURCE_MEMBERSHIP | IP_DROP_SOURCE_MEMBERSHIP | IP_MSFILTER
            | MCAST_JOIN_GROUP | MCAST_BLOCK_SOURCE | MCAST_UNBLOCK_SOURCE
            | MCAST_LEAVE_GROUP | MCAST_JOIN_SOURCE_GROUP | MCAST_LEAVE_SOURCE_GROUP
            | MCAST_MSFILTER) => Some(V4Other),
        (IPPROTO_IPV6, IPV6_MULTICAST_IF | IPV6_MULTICAST_HOPS) => Some(V6IfaceOrHops),
        (IPPROTO_IPV6, IPV6_JOIN_GROUP | IPV6_LEAVE_GROUP) => Some(V6Membership),
        (IPPROTO_IPV6, IPV6_MULTICAST_LOOP | MCAST_JOIN_GROUP | MCAST_BLOCK_SOURCE
            | MCAST_UNBLOCK_SOURCE | MCAST_LEAVE_GROUP | MCAST_JOIN_SOURCE_GROUP
            | MCAST_LEAVE_SOURCE_GROUP | MCAST_MSFILTER) => Some(V6Other),
        _ => None,
    }
}

/// Gate IPPROTO_IPV6 options to AF_INET6 sockets, matching the family
/// check already used by the v6 multicast-membership helpers. # C: O(1)
fn require_v6(sock: &Arc<net::sock::InetSocket>) -> Result<(), i64> {
    if sock.family.load(Ordering::Acquire) != net::sock::AF_INET6 {
        return Err(-(Errno::Eafnosupport.as_i32() as i64));
    }
    Ok(())
}

pub(super) fn read_u8_or_i32(optval: u64, optlen: u32) -> Option<i32> {
    if (1..4).contains(&optlen) {
        let mut byte = [0u8; 1];
        uaccess::copy_from_user(&mut byte, optval).ok()?;
        return Some(byte[0] as i32);
    }
    if optlen >= 4 {
        let mut bytes = [0u8; 4];
        uaccess::copy_from_user(&mut bytes, optval).ok()?;
        return Some(i32::from_ne_bytes(bytes));
    }
    None
}

fn refresh_tcp_keepalive(sock: &Arc<net::sock::InetSocket>) {
    if let net::sock::SockKind::TcpConn(entry) = &*sock.kind.lock() {
        net::sock_opts::apply_tcp_keepalive_opts(sock, entry);
    }
}

fn sync_raw_rcvbuf(sock: &net::sock::InetSocket, value: i32) {
    match &*sock.kind.lock() {
        net::sock::SockKind::Raw4(endpoint) => endpoint.set_rcvbuf(value.max(0) as usize),
        net::sock::SockKind::Raw6(endpoint) => endpoint.set_rcvbuf(value.max(0) as usize),
        _ => {}
    }
}

fn bind_to_device(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    const IFNAMSIZ: usize = 16;
    if optlen as usize > IFNAMSIZ { return -(Errno::Einval.as_i32() as i64); }
    if optlen == 0 { return sock.set_bound_iface(None).map_or_else(errno_from_neterr, |_| 0); }
    let mut name = [0u8; IFNAMSIZ];
    let n = optlen as usize;
    if uaccess::copy_from_user(&mut name[..n], optval).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let end = name[..n].iter().position(|b| *b == 0).unwrap_or(n);
    let iface = if end == 0 {
        None
    } else {
        let s = match core::str::from_utf8(&name[..end]) {
            Ok(s) => s,
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        };
        let net_ns = sock.net_ns();
        match net::sock::stack().ifaces.lookup_name_in_ns(s, net_ns) {
            Some((id, _)) => Some(id),
            None => return -(Errno::Enodev.as_i32() as i64),
        }
    };
    match sock.set_bound_iface(iface) { Ok(()) => 0, Err(e) => errno_from_neterr(e) }
}

fn errno(error: Errno) -> i64 { -(error.as_i32() as i64) }

fn copy_filter_i32(optval: u64, optlen: u32) -> Result<i32, Errno> {
    if optlen < core::mem::size_of::<i32>() as u32 { return Err(Errno::Einval); }
    let mut bytes = [0u8; core::mem::size_of::<i32>()];
    uaccess::copy_from_user(&mut bytes, optval).map_err(|_| Errno::Efault)?;
    Ok(i32::from_ne_bytes(bytes))
}

fn socket_filter_option(target: &socket::FilterFile, optname: u64,
                        optval: u64, optlen: u32) -> i64 {
    let value = match copy_filter_i32(optval, optlen) {
        Ok(value) => value,
        Err(error) => return errno(error),
    };
    let result = match optname {
        SO_ATTACH_BPF => (|| {
            if optlen != core::mem::size_of::<i32>() as u32 { return Err(Errno::Einval); }
            target.ensure_mutable().map_err(filter_errno)?;
            let program = bpf_prog(value)?;
            target.attach(program).map_err(filter_errno)
        })(),
        SO_ATTACH_FILTER => (|| {
            target.require_classic_admin().map_err(filter_errno)?;
            let header = classic_filter_header(optval, optlen)?;
            target.ensure_mutable().map_err(filter_errno)?;
            let program = classic_filter_program(header)?;
            target.attach(program).map_err(filter_errno)
        })(),
        SO_DETACH_FILTER => (|| {
            target.detach().map_err(filter_errno)
        })(),
        SO_LOCK_FILTER => (|| {
            target.set_lock(value != 0).map_err(filter_errno)
        })(),
        _ => Err(Errno::Enoprotoopt),
    };
    match result { Ok(()) => 0, Err(error) => errno(error) }
}

fn filter_errno(error: socket::FilterError) -> Errno {
    match error {
        socket::FilterError::PermissionDenied | socket::FilterError::Locked => Errno::Eperm,
        socket::FilterError::NotAttached => Errno::Enoent,
    }
}

/// Resolve a SOCKET_FILTER BPF fd, preserving bad-fd versus wrong-object errors. # C: O(1)
pub(super) fn bpf_prog(fd: i32) -> Result<net::bpf_filter::FilterProgram, Errno> {
    let cur = sched::live::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; sole reader of the fd-table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let f = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    let prog = f.inode().private::<security::bpf::BpfProgInode>().ok_or(Errno::Einval)?;
    if prog.prog_type != security::bpf::BPF_PROG_TYPE_SOCKET_FILTER {
        return Err(Errno::Einval);
    }
    Ok(net::bpf_filter::FilterProgram {
        kind: net::bpf_filter::FilterKind::Ebpf,
        insns: prog.insns.clone(),
    })
}

/// Copy native `struct sock_fprog` for SO_ATTACH_FILTER. # C: O(1)
pub(super) fn classic_filter_header(optval: u64, optlen: u32) -> Result<(usize, u64), Errno> {
    if optlen != SOCK_FPROG_SIZE { return Err(Errno::Einval); }
    let mut fprog = [0u8; SOCK_FPROG_SIZE as usize];
    uaccess::copy_from_user(&mut fprog, optval).map_err(|_| Errno::Efault)?;
    let len = u16::from_ne_bytes(fprog[..2].try_into().unwrap()) as usize;
    let ptr = u64::from_ne_bytes(fprog[SOCK_FPROG_FILTER_OFFSET as usize..
        SOCK_FPROG_FILTER_OFFSET as usize + core::mem::size_of::<u64>()].try_into().unwrap());
    Ok((len, ptr))
}

pub(super) fn classic_filter_program(header: (usize, u64)) -> Result<net::bpf_filter::FilterProgram, Errno> {
    let (len, ptr) = header;
    if len == 0 || len > BPF_MAXINSNS { return Err(Errno::Einval); }
    let bytes = len.checked_mul(BPF_INSN_SIZE).ok_or(Errno::Einval)?;
    let mut insns = alloc::vec![0u8; bytes];
    uaccess::copy_from_user(&mut insns, ptr).map_err(|_| Errno::Efault)?;
    security::socket_filter::verify(&insns).map_err(|_| Errno::Einval)?;
    Ok(net::bpf_filter::FilterProgram {
        kind: net::bpf_filter::FilterKind::Classic, insns,
    })
}

/// Store SO_PRIORITY when a value is present. # C: O(1)
fn priority_store(s: &Arc<net::sock::InetSocket>, v: Option<i32>) {
    if let Some(v) = v { s.opts.priority.store(v, Ordering::Release); }
}

/// Store SO_MARK when a value is present. # C: O(1)
fn mark_store(s: &Arc<net::sock::InetSocket>, v: Option<i32>) {
    if let Some(v) = v { s.opts.mark.store(v, Ordering::Release); }
}
