#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use hal::USER_VA_END;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::net_common::socket_from_fd;
use crate::net_trace::trace_enotsock_at;

use super::multicast::{
    SourceOp, ipv4_group_filter, ipv4_mcast_group_req, ipv4_mcast_group_source_req,
    ipv4_mcast_if, ipv4_mcast_membership, ipv4_mcast_source_req, ipv6_mcast_membership,
};
use super::uapi::*;

/// `setsockopt(fd, level, optname, optval, optlen)` slot 54. # C: O(1)
pub fn sys_setsockopt(args: &SyscallArgs) -> i64 {
    let fd = args.a0;
    let level = args.a1;
    let optname = args.a2;
    let optval = args.a3;
    let optlen = args.a4 as u32;
    if crate::netlink_fd::is_netlink(fd) {
        return crate::netlink_fd::setsockopt(fd, level, optname, optval, optlen as u64);
    }
    let sock = match socket_from_fd(fd) {
        Some(s) => s,
        None => {
            trace_enotsock_at(fd, b"setsockopt");
            return -(Errno::Enotsock.as_i32() as i64);
        }
    };
    if optval == 0 || optval >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let read_i32 = |o: u64| -> Option<i32> {
        if optlen < 4 || o + 4 > USER_VA_END { return None; }
        // SAFETY: o validated user range; 4-byte aligned int read per Linux ABI.
        Some(unsafe { core::ptr::read_volatile(o as *const i32) })
    };
    match (level, optname) {
        (SOL_SOCKET, 2) => if let Some(v) = read_i32(optval) { sock.opts.reuseaddr.store(v, Ordering::Release); },
        (SOL_SOCKET, 15) => if let Some(v) = read_i32(optval) { sock.opts.reuseport.store(v, Ordering::Release); },
        (SOL_SOCKET, 9) => if let Some(v) = read_i32(optval) {
            sock.opts.keepalive.store(v, Ordering::Release);
            refresh_tcp_keepalive(&sock);
        },
        (SOL_SOCKET, 6) => if let Some(v) = read_i32(optval) { sock.opts.broadcast.store(v, Ordering::Release); },
        (SOL_SOCKET, SO_SNDBUF) | (SOL_SOCKET, SO_SNDBUFFORCE) =>
            if let Some(v) = read_i32(optval) { sock.opts.sndbuf.store(v, Ordering::Release); },
        (SOL_SOCKET, SO_RCVBUF) | (SOL_SOCKET, SO_RCVBUFFORCE) =>
            if let Some(v) = read_i32(optval) { sock.opts.rcvbuf.store(v, Ordering::Release); },
        (SOL_SOCKET, 16) => if let Some(v) = read_i32(optval) { sock.opts.passcred.store(v, Ordering::Release); },
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
            if optlen >= 8 && optval + 8 <= USER_VA_END {
                // SAFETY: optval+8 validated above; struct linger has int l_onoff/l_linger.
                let on = unsafe { core::ptr::read_volatile(optval as *const i32) };
                // SAFETY: optval+8 validated above; second linger int at offset +4.
                let sec = unsafe { core::ptr::read_volatile((optval + 4) as *const i32) };
                sock.opts.linger_on.store(on, Ordering::Release);
                sock.opts.linger_s.store(sec, Ordering::Release);
            }
        }
        (SOL_SOCKET, 21) | (SOL_SOCKET, 20) => {
            if optlen >= 16 && optval + 16 <= USER_VA_END {
                // SAFETY: optval+16 validated above; struct timeval tv_sec is i64 at +0.
                let s = unsafe { core::ptr::read_volatile(optval as *const i64) };
                // SAFETY: optval+16 validated above; struct timeval tv_usec is i64 at +8.
                let u = unsafe { core::ptr::read_volatile((optval + 8) as *const i64) };
                let ns = (s.max(0) as i64) * 1_000_000_000 + (u.max(0) as i64) * 1_000;
                let slot = if optname == 21 { &sock.opts.sndtimeo_ns } else { &sock.opts.rcvtimeo_ns };
                slot.store(ns, Ordering::Release);
            }
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
        (IPPROTO_IP, IP_MULTICAST_TTL) => {
            let Some(v) = read_u8_or_i32(optval, optlen) else { return -(Errno::Einval.as_i32() as i64); };
            if !(0..=255).contains(&v) { return -(Errno::Einval.as_i32() as i64); }
            sock.opts.ip_mcast_ttl.store(v, Ordering::Release);
        }
        (IPPROTO_IP, IP_MULTICAST_LOOP) => {
            let Some(v) = read_u8_or_i32(optval, optlen) else { return -(Errno::Einval.as_i32() as i64); };
            sock.opts.ip_mcast_loop.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        (IPPROTO_IP, IP_MULTICAST_IF) => return ipv4_mcast_if(&sock, optval, optlen),
        (IPPROTO_IP, IP_ADD_MEMBERSHIP) => return ipv4_mcast_membership(&sock, optval, optlen, true),
        (IPPROTO_IP, IP_DROP_MEMBERSHIP) => return ipv4_mcast_membership(&sock, optval, optlen, false),
        (IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP) => return ipv4_mcast_source_req(&sock, optval, optlen, SourceOp::Join),
        (IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP) => return ipv4_mcast_source_req(&sock, optval, optlen, SourceOp::Leave),
        (IPPROTO_IP, IP_BLOCK_SOURCE) => return ipv4_mcast_source_req(&sock, optval, optlen, SourceOp::Block),
        (IPPROTO_IP, IP_UNBLOCK_SOURCE) => return ipv4_mcast_source_req(&sock, optval, optlen, SourceOp::Unblock),
        (IPPROTO_IP, IP_MSFILTER) => return ipv4_mcast_membership_result(ipv4_msfilter(&sock, optval, optlen)),
        (IPPROTO_IP, MCAST_JOIN_GROUP) => return ipv4_mcast_group_req(&sock, optval, optlen, true),
        (IPPROTO_IP, MCAST_LEAVE_GROUP) => return ipv4_mcast_group_req(&sock, optval, optlen, false),
        (IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP) => return ipv4_mcast_group_source_req(&sock, optval, optlen, SourceOp::Join),
        (IPPROTO_IP, MCAST_LEAVE_SOURCE_GROUP) => return ipv4_mcast_group_source_req(&sock, optval, optlen, SourceOp::Leave),
        (IPPROTO_IP, MCAST_BLOCK_SOURCE) => return ipv4_mcast_group_source_req(&sock, optval, optlen, SourceOp::Block),
        (IPPROTO_IP, MCAST_UNBLOCK_SOURCE) => return ipv4_mcast_group_source_req(&sock, optval, optlen, SourceOp::Unblock),
        (IPPROTO_IP, MCAST_MSFILTER) => return ipv4_mcast_membership_result(ipv4_group_filter(&sock, optval, optlen)),
        (IPPROTO_IPV6, IPV6_V6ONLY) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            sock.opts.ipv6_v6only.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        (IPPROTO_IPV6, IPV6_JOIN_GROUP) => return ipv6_mcast_membership(&sock, optval, optlen, true),
        (IPPROTO_IPV6, IPV6_LEAVE_GROUP) => return ipv6_mcast_membership(&sock, optval, optlen, false),
        (IPPROTO_TCP, 1) => if let Some(v) = read_i32(optval) { sock.opts.tcp_nodelay.store(v, Ordering::Release); },
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
        (SOL_SOCKET, 50) => {
            if let (Some(prog_fd), Some(port)) = (read_i32(optval), *sock.local_port.lock()) {
                if let Some(insns) = bpf_prog_insns(prog_fd) {
                    net::sock::stack().set_udp_bpf_filter(port, Some(insns));
                }
            }
        }
        (SOL_SOCKET, 27) => {
            if let Some(port) = *sock.local_port.lock() {
                net::sock::stack().set_udp_bpf_filter(port, None);
            }
        }
        _ => return -(Errno::Enoprotoopt.as_i32() as i64),
    }
    0
}

fn ipv4_mcast_membership_result(rv: i64) -> i64 {
    rv
}

pub(super) fn read_u8_or_i32(optval: u64, optlen: u32) -> Option<i32> {
    if optlen == 1 && optval < USER_VA_END {
        // SAFETY: caller supplied a one-byte integer option in user range.
        return Some(unsafe { core::ptr::read_volatile(optval as *const u8) } as i32);
    }
    if optlen >= 4 && optval + 4 <= USER_VA_END {
        // SAFETY: optval+4 validated in user range; Linux accepts int-shaped forms.
        return Some(unsafe { core::ptr::read_volatile(optval as *const i32) });
    }
    None
}

fn refresh_tcp_keepalive(sock: &Arc<net::sock::InetSocket>) {
    if let net::sock::SockKind::TcpConn(entry) = &*sock.kind.lock() {
        net::sock_opts::apply_tcp_keepalive_opts(sock, entry);
    }
}

fn bind_to_device(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    const IFNAMSIZ: usize = 16;
    if optlen as usize > IFNAMSIZ || optval + optlen as u64 > USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut name = [0u8; IFNAMSIZ];
    let n = optlen as usize;
    for i in 0..n {
        // SAFETY: optval + optlen validated in user range; byte reads are ABI-safe.
        name[i] = unsafe { core::ptr::read_volatile((optval + i as u64) as *const u8) };
    }
    let end = name[..n].iter().position(|b| *b == 0).unwrap_or(n);
    let iface = if end == 0 {
        None
    } else {
        let s = match core::str::from_utf8(&name[..end]) {
            Ok(s) => s,
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        };
        match net::sock::stack().ifaces.lookup_name(s) {
            Some((id, _)) => Some(id),
            None => return -(Errno::Enodev.as_i32() as i64),
        }
    };
    sock.opts.bound_ifindex.store(iface.map(|i| i.raw()).unwrap_or(0), Ordering::Release);
    if let Some(port) = *sock.local_port.lock() {
        let fam = sock.family.load(Ordering::Acquire);
        if fam == net::sock::AF_INET6 { net::sock::stack().set_udp6_bound_iface(port, iface); }
        else { net::sock::stack().set_udp_bound_iface(port, iface); }
    }
    match &*sock.kind.lock() {
        net::sock::SockKind::TcpConn(entry) => entry.set_bound_iface(iface),
        net::sock::SockKind::TcpListener(listener) => listener.set_bound_iface(iface),
        _ => {}
    }
    0
}

/// Resolve a `bpf(BPF_PROG_LOAD)` program fd to its instruction bytes.
/// # C: O(1) fd lookup + clone
fn bpf_prog_insns(fd: i32) -> Option<Vec<u8>> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; sole reader of the fd-table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    let f = fdt.get(fd).ok()?;
    let prog = f.inode().private::<security::bpf::BpfProgInode>()?;
    Some(prog.insns.clone())
}

/// Store SO_PRIORITY when a value is present. # C: O(1)
fn priority_store(s: &Arc<net::sock::InetSocket>, v: Option<i32>) {
    if let Some(v) = v { s.opts.priority.store(v, Ordering::Release); }
}

/// Store SO_MARK when a value is present. # C: O(1)
fn mark_store(s: &Arc<net::sock::InetSocket>, v: Option<i32>) {
    if let Some(v) = v { s.opts.mark.store(v, Ordering::Release); }
}
