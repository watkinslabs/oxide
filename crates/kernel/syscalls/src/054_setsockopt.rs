// 054 setsockopt — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use crate::net_trace::trace_enotsock_at;
use crate::net_common::{errno_from_neterr, socket_from_fd};

/// `setsockopt(fd, level, optname, optval, optlen)` slot 54. # C: O(1)
pub fn sys_setsockopt(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    const SOL_SOCKET: u64  = 1;
    const SO_BINDTODEVICE: u64 = 25;
    const SO_SNDBUF: u64 = 7;
    const SO_RCVBUF: u64 = 8;
    const SO_SNDBUFFORCE: u64 = 32;
    const SO_RCVBUFFORCE: u64 = 33;
    const SO_TIMESTAMP_OLD: u64 = 29;
    const SO_TIMESTAMPNS_OLD: u64 = 35;
    const SO_TIMESTAMPING_OLD: u64 = 37;
    const SO_TIMESTAMP_NEW: u64 = 63;
    const SO_TIMESTAMPNS_NEW: u64 = 64;
    const SO_TIMESTAMPING_NEW: u64 = 65;
    const IPPROTO_IP: u64 = 0;
    const IP_TOS: u64 = 1;
    const IP_TTL: u64 = 2;
    const IP_PKTINFO: u64 = 8;
    const IP_MULTICAST_IF: u64 = 32;
    const IP_MULTICAST_TTL: u64 = 33;
    const IP_MULTICAST_LOOP: u64 = 34;
    const IP_ADD_MEMBERSHIP: u64 = 35;
    const IP_DROP_MEMBERSHIP: u64 = 36;
    const IP_UNBLOCK_SOURCE: u64 = 37;
    const IP_BLOCK_SOURCE: u64 = 38;
    const IP_ADD_SOURCE_MEMBERSHIP: u64 = 39;
    const IP_DROP_SOURCE_MEMBERSHIP: u64 = 40;
    const IP_MSFILTER: u64 = 41;
    const MCAST_JOIN_GROUP: u64 = 42;
    const MCAST_BLOCK_SOURCE: u64 = 43;
    const MCAST_UNBLOCK_SOURCE: u64 = 44;
    const MCAST_LEAVE_GROUP: u64 = 45;
    const MCAST_JOIN_SOURCE_GROUP: u64 = 46;
    const MCAST_LEAVE_SOURCE_GROUP: u64 = 47;
    const MCAST_MSFILTER: u64 = 48;
    const IPPROTO_IPV6: u64 = 41;
    const IPV6_JOIN_GROUP: u64 = 20;
    const IPV6_LEAVE_GROUP: u64 = 21;
    const IPV6_V6ONLY: u64 = 26;
    const IPPROTO_TCP: u64 = 6;
    const TCP_CORK: u64 = 3;
    const TCP_KEEPIDLE: u64 = 4;
    const TCP_KEEPINTVL: u64 = 5;
    const TCP_KEEPCNT: u64 = 6;
    let fd       = args.a0;
    let level    = args.a1;
    let optname  = args.a2;
    let optval   = args.a3;
    let optlen   = args.a4 as u32;
    if crate::netlink_fd::is_netlink(fd) {
        return crate::netlink_fd::setsockopt(fd, level, optname, optval, optlen as u64);
    }
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"setsockopt"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    if optval == 0 || optval >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let read_i32 = |o: u64| -> Option<i32> {
        if optlen < 4 || o + 4 > USER_VA_END { return None; }
        // SAFETY: o validated user range; 4-byte aligned int read per Linux ABI.
        Some(unsafe { core::ptr::read_volatile(o as *const i32) })
    };
    match (level, optname) {
        (SOL_SOCKET, 2)  => if let Some(v) = read_i32(optval) { sock.opts.reuseaddr.store(v, Ordering::Release); },
        (SOL_SOCKET, 15) => if let Some(v) = read_i32(optval) { sock.opts.reuseport.store(v, Ordering::Release); },
        (SOL_SOCKET, 9)  => if let Some(v) = read_i32(optval) {
            sock.opts.keepalive.store(v, Ordering::Release);
            if let net::sock::SockKind::TcpConn(entry) = &*sock.kind.lock() {
                net::sock_opts::apply_tcp_keepalive_opts(&sock, entry);
            }
        },
        (SOL_SOCKET, 6)  => if let Some(v) = read_i32(optval) { sock.opts.broadcast.store(v, Ordering::Release); },
        (SOL_SOCKET, SO_SNDBUF) | (SOL_SOCKET, SO_SNDBUFFORCE) =>
            if let Some(v) = read_i32(optval) { sock.opts.sndbuf.store(v, Ordering::Release); },
        (SOL_SOCKET, SO_RCVBUF) | (SOL_SOCKET, SO_RCVBUFFORCE) =>
            if let Some(v) = read_i32(optval) { sock.opts.rcvbuf.store(v, Ordering::Release); },
        (SOL_SOCKET, 16) => if let Some(v) = read_i32(optval) { sock.opts.passcred.store(v, Ordering::Release); }, // SO_PASSCRED
        (SOL_SOCKET, SO_TIMESTAMP_OLD) | (SOL_SOCKET, SO_TIMESTAMPNS_OLD)
        | (SOL_SOCKET, SO_TIMESTAMPING_OLD) | (SOL_SOCKET, SO_TIMESTAMP_NEW)
        | (SOL_SOCKET, SO_TIMESTAMPNS_NEW) | (SOL_SOCKET, SO_TIMESTAMPING_NEW) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            sock.opts.timestamping.store(v, Ordering::Release);
        }
        (SOL_SOCKET, 12) => priority_store(&sock, read_i32(optval)),
        (SOL_SOCKET, 36) => mark_store(&sock, read_i32(optval)),
        (IPPROTO_IP, IP_TOS) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            sock.opts.ip_tos.store(v & 0xff, Ordering::Release);
        }
        (IPPROTO_IP, IP_TTL) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            if !(1..=255).contains(&v) {
                return -(Errno::Einval.as_i32() as i64);
            }
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
        (IPPROTO_IP, IP_MULTICAST_IF) => {
            let rc = ipv4_mcast_if(&sock, optval, optlen);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, IP_ADD_MEMBERSHIP) => {
            let rc = ipv4_mcast_membership(&sock, optval, optlen, true);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, IP_DROP_MEMBERSHIP) => {
            let rc = ipv4_mcast_membership(&sock, optval, optlen, false);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP) => {
            let rc = ipv4_mcast_source_req(&sock, optval, optlen, SourceOp::Join);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP) => {
            let rc = ipv4_mcast_source_req(&sock, optval, optlen, SourceOp::Leave);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, IP_BLOCK_SOURCE) => {
            let rc = ipv4_mcast_source_req(&sock, optval, optlen, SourceOp::Block);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, IP_UNBLOCK_SOURCE) => {
            let rc = ipv4_mcast_source_req(&sock, optval, optlen, SourceOp::Unblock);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, IP_MSFILTER) => {
            let rc = ipv4_msfilter(&sock, optval, optlen);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, MCAST_JOIN_GROUP) => {
            let rc = ipv4_mcast_group_req(&sock, optval, optlen, true);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, MCAST_LEAVE_GROUP) => {
            let rc = ipv4_mcast_group_req(&sock, optval, optlen, false);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP) => {
            let rc = ipv4_mcast_group_source_req(&sock, optval, optlen, SourceOp::Join);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, MCAST_LEAVE_SOURCE_GROUP) => {
            let rc = ipv4_mcast_group_source_req(&sock, optval, optlen, SourceOp::Leave);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, MCAST_BLOCK_SOURCE) => {
            let rc = ipv4_mcast_group_source_req(&sock, optval, optlen, SourceOp::Block);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, MCAST_UNBLOCK_SOURCE) => {
            let rc = ipv4_mcast_group_source_req(&sock, optval, optlen, SourceOp::Unblock);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IP, MCAST_MSFILTER) => {
            let rc = ipv4_group_filter(&sock, optval, optlen);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IPV6, IPV6_V6ONLY) => {
            let Some(v) = read_i32(optval) else { return -(Errno::Einval.as_i32() as i64); };
            sock.opts.ipv6_v6only.store(if v != 0 { 1 } else { 0 }, Ordering::Release);
        }
        (IPPROTO_IPV6, IPV6_JOIN_GROUP) => {
            let rc = ipv6_mcast_membership(&sock, optval, optlen, true);
            if rc != 0 { return rc; }
        }
        (IPPROTO_IPV6, IPV6_LEAVE_GROUP) => {
            let rc = ipv6_mcast_membership(&sock, optval, optlen, false);
            if rc != 0 { return rc; }
        }
        (SOL_SOCKET, SO_BINDTODEVICE) => {
            let rc = bind_to_device(&sock, optval, optlen);
            if rc != 0 { return rc; }
        }
        (SOL_SOCKET, 13) => {
            // struct linger { int l_onoff; int l_linger; } = 8 bytes
            if optlen >= 8 && optval + 8 <= USER_VA_END {
                // SAFETY: optval+8 validated; reading two i32 ints per linger ABI.
                // SAFETY: optval+8 validated above; struct linger has int l_onoff/l_linger.
                let on = unsafe { core::ptr::read_volatile(optval as *const i32) };
                // SAFETY: optval+8 validated above; second linger int at offset +4.
                let sec = unsafe { core::ptr::read_volatile((optval + 4) as *const i32) };
                sock.opts.linger_on.store(on, Ordering::Release);
                sock.opts.linger_s.store(sec, Ordering::Release);
            }
        }
        (SOL_SOCKET, 21) | (SOL_SOCKET, 20) => {
            // SO_RCVTIMEO_OLD(20) / SO_SNDTIMEO_OLD(21) — struct timeval (16B)
            if optlen >= 16 && optval + 16 <= USER_VA_END {
                // SAFETY: optval+16 validated; struct timeval { i64 sec; i64 usec; } read.
                // SAFETY: optval+16 validated above; struct timeval tv_sec is i64 at +0.
                let s = unsafe { core::ptr::read_volatile(optval as *const i64) };
                // SAFETY: optval+16 validated above; struct timeval tv_usec is i64 at +8.
                let u = unsafe { core::ptr::read_volatile((optval + 8) as *const i64) };
                let ns = (s.max(0) as i64) * 1_000_000_000 + (u.max(0) as i64) * 1_000;
                let slot = if optname == 21 { &sock.opts.sndtimeo_ns } else { &sock.opts.rcvtimeo_ns };
                slot.store(ns, Ordering::Release);
            }
        }
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
        // SO_ATTACH_BPF (50): attach an eBPF program (by its bpf() prog fd) as
        // a socket filter on the bound UDP port. SO_DETACH_BPF/FILTER (27): clear.
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

fn read_u8_or_i32(optval: u64, optlen: u32) -> Option<i32> {
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

fn read_ipv4_at(ptr: u64) -> Option<net::Ipv4Addr> {
    if ptr + 4 > USER_VA_END { return None; }
    // SAFETY: ptr+4 was checked; in_addr is a network-order u32.
    let be = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    Some(net::Ipv4Addr::from_u32(u32::from_be(be)))
}

fn iface_for_v4_addr(addr: net::Ipv4Addr) -> Option<net::NetIfaceId> {
    net::sock::stack().routes.snapshot().into_iter()
        .find(|r| r.src_hint == Some(addr))
        .map(|r| r.iface)
}

fn default_v4_mcast_iface(sock: &alloc::sync::Arc<net::sock::InetSocket>, group: net::Ipv4Addr)
    -> Option<net::NetIfaceId>
{
    use core::sync::atomic::Ordering;
    let raw = sock.opts.ip_mcast_ifindex.load(Ordering::Acquire);
    if raw != 0 { return Some(net::NetIfaceId::from_raw(raw)); }
    let addr = net::Ipv4Addr::from_u32(sock.opts.ip_mcast_ifaddr.load(Ordering::Acquire));
    if !addr.is_unspecified() { return iface_for_v4_addr(addr); }
    let bound = sock.opts.bound_ifindex.load(Ordering::Acquire);
    if bound != 0 { return Some(net::NetIfaceId::from_raw(bound)); }
    if let Some(r) = net::sock::stack().routes.lookup(group) { return Some(r.iface); }
    let routes = net::sock::stack().routes.snapshot();
    if routes.len() == 1 { Some(routes[0].iface) } else { None }
}

fn ipv4_mcast_if(sock: &alloc::sync::Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    use core::sync::atomic::Ordering;
    if sock.family.load(Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 4 || optval + optlen as u64 > USER_VA_END { return -(Errno::Einval.as_i32() as i64); }
    let Some(addr) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let ifindex = if optlen >= 12 {
        // SAFETY: ip_mreqn ifindex sits at byte 8 and optlen/range were checked.
        unsafe { core::ptr::read_volatile((optval + 8) as *const i32).max(0) as u32 }
    } else { 0 };
    if ifindex != 0 && net::sock::stack().ifaces.lookup(net::NetIfaceId::from_raw(ifindex)).is_none() {
        return -(Errno::Enodev.as_i32() as i64);
    }
    if ifindex == 0 && !addr.is_unspecified() && iface_for_v4_addr(addr).is_none() {
        return -(Errno::Enodev.as_i32() as i64);
    }
    sock.opts.ip_mcast_ifaddr.store(addr.as_u32(), Ordering::Release);
    sock.opts.ip_mcast_ifindex.store(ifindex, Ordering::Release);
    0
}

fn ipv4_mcast_membership(
    sock: &alloc::sync::Arc<net::sock::InetSocket>,
    optval: u64,
    optlen: u32,
    join: bool,
) -> i64 {
    use core::sync::atomic::Ordering;
    if sock.family.load(Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 8 || optval + optlen as u64 > USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(req_src) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
    let req_if = if optlen >= 12 {
        // SAFETY: ip_mreqn ifindex sits at byte 8 and optlen/range were checked.
        unsafe { core::ptr::read_volatile((optval + 8) as *const i32).max(0) as u32 }
    } else { 0 };
    let iface = if req_if != 0 {
        net::NetIfaceId::from_raw(req_if)
    } else if !req_src.is_unspecified() {
        match iface_for_v4_addr(req_src) {
            Some(i) => i,
            None => return -(Errno::Enodev.as_i32() as i64),
        }
    } else {
        match default_v4_mcast_iface(sock, group) {
            Some(i) => i,
            None => return -(Errno::Enodev.as_i32() as i64),
        }
    };
    if net::sock::stack().ifaces.lookup(iface).is_none() {
        return -(Errno::Enodev.as_i32() as i64);
    }
    let src = if !req_src.is_unspecified() { req_src } else { *sock.local_ip.lock() };
    let result = if join {
        net::sock::stack().join_ipv4_multicast(iface, group, src)
    } else {
        net::sock::stack().leave_ipv4_multicast(iface, group, src)
    };
    match result {
        Ok(()) => 0,
        Err(e) => errno_from_neterr(e),
    }
}

#[derive(Copy, Clone)]
enum SourceOp { Join, Leave, Block, Unblock }

fn read_u32_at(ptr: u64) -> Option<u32> {
    if ptr + 4 > USER_VA_END { return None; }
    // SAFETY: ptr+4 was checked; scalar ABI field read.
    Some(unsafe { core::ptr::read_volatile(ptr as *const u32) })
}

fn read_sockaddr_storage_v4(ptr: u64) -> Option<net::Ipv4Addr> {
    const AF_INET: u16 = 2;
    if ptr + 16 > USER_VA_END { return None; }
    // SAFETY: sockaddr_storage begins with sockaddr_in-compatible fields.
    let family = unsafe { core::ptr::read_volatile(ptr as *const u16) };
    if family != AF_INET { return None; }
    read_ipv4_at(ptr + 4)
}

fn udp_port(sock: &alloc::sync::Arc<net::sock::InetSocket>) -> Result<u16, i64> {
    if !matches!(&*sock.kind.lock(), net::sock::SockKind::Udp) {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    sock.ensure_bound().map_err(errno_from_neterr)
}

fn resolve_v4_mcast_iface(
    sock: &alloc::sync::Arc<net::sock::InetSocket>,
    group: net::Ipv4Addr,
    ifindex: u32,
    ifaddr: net::Ipv4Addr,
) -> Result<net::NetIfaceId, i64> {
    let iface = if ifindex != 0 {
        net::NetIfaceId::from_raw(ifindex)
    } else if !ifaddr.is_unspecified() {
        iface_for_v4_addr(ifaddr).ok_or(-(Errno::Enodev.as_i32() as i64))?
    } else {
        default_v4_mcast_iface(sock, group).ok_or(-(Errno::Enodev.as_i32() as i64))?
    };
    if net::sock::stack().ifaces.lookup(iface).is_none() {
        return Err(-(Errno::Enodev.as_i32() as i64));
    }
    Ok(iface)
}

fn apply_source_op(
    sock: &alloc::sync::Arc<net::sock::InetSocket>,
    group: net::Ipv4Addr,
    iface: net::NetIfaceId,
    source: net::Ipv4Addr,
    op: SourceOp,
) -> i64 {
    use net::mcast_filter;
    if !group.is_multicast() || source.is_unspecified() {
        return -(Errno::Einval.as_i32() as i64);
    }
    let port = match udp_port(sock) { Ok(p) => p, Err(e) => return e };
    match op {
        SourceOp::Join => {
            let local = *sock.local_ip.lock();
            if let Err(e) = net::sock::stack().join_ipv4_multicast(iface, group, local) {
                return errno_from_neterr(e);
            }
            mcast_filter::add_source(port, iface, group, source);
        }
        SourceOp::Leave => mcast_filter::drop_source(port, iface, group, source),
        SourceOp::Block => mcast_filter::block_source(port, iface, group, source),
        SourceOp::Unblock => mcast_filter::unblock_source(port, iface, group, source),
    }
    0
}

fn ipv4_mcast_source_req(
    sock: &alloc::sync::Arc<net::sock::InetSocket>,
    optval: u64,
    optlen: u32,
    op: SourceOp,
) -> i64 {
    use core::sync::atomic::Ordering;
    if sock.family.load(Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 12 || optval + optlen as u64 > USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(ifaddr) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(source) = read_ipv4_at(optval + 8) else { return -(Errno::Efault.as_i32() as i64); };
    let iface = match resolve_v4_mcast_iface(sock, group, 0, ifaddr) {
        Ok(i) => i,
        Err(e) => return e,
    };
    apply_source_op(sock, group, iface, source, op)
}

fn ipv4_msfilter(
    sock: &alloc::sync::Arc<net::sock::InetSocket>,
    optval: u64,
    optlen: u32,
) -> i64 {
    use core::sync::atomic::Ordering;
    if sock.family.load(Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 16 || optval + optlen as u64 > USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    let Some(group) = read_ipv4_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(ifaddr) = read_ipv4_at(optval + 4) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(mode_raw) = read_u32_at(optval + 8) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(numsrc) = read_u32_at(optval + 12) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() || 16u64.saturating_add(numsrc as u64 * 4) > optlen as u64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mode = match net::mcast_filter::FilterMode::from_u32(mode_raw) {
        Ok(m) => m,
        Err(e) => return errno_from_neterr(e),
    };
    let iface = match resolve_v4_mcast_iface(sock, group, 0, ifaddr) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let port = match udp_port(sock) { Ok(p) => p, Err(e) => return e };
    let mut sources = alloc::vec::Vec::new();
    for i in 0..numsrc as u64 {
        let Some(src) = read_ipv4_at(optval + 16 + i * 4) else { return -(Errno::Efault.as_i32() as i64); };
        if src.is_unspecified() { return -(Errno::Einval.as_i32() as i64); }
        sources.push(src);
    }
    net::mcast_filter::set(port, iface, group, mode, &sources);
    let local = *sock.local_ip.lock();
    match net::sock::stack().join_ipv4_multicast(iface, group, local) {
        Ok(()) => 0,
        Err(e) => errno_from_neterr(e),
    }
}

fn ipv4_mcast_group_req(
    sock: &alloc::sync::Arc<net::sock::InetSocket>,
    optval: u64,
    optlen: u32,
    join: bool,
) -> i64 {
    use core::sync::atomic::Ordering;
    if sock.family.load(Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 136 || optval + optlen as u64 > USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }
    let iface = match resolve_v4_mcast_iface(sock, group, ifindex, net::Ipv4Addr::ANY) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let src = *sock.local_ip.lock();
    let result = if join {
        net::sock::stack().join_ipv4_multicast(iface, group, src)
    } else {
        if let Ok(port) = udp_port(sock) { net::mcast_filter::clear_group(port, iface, group); }
        net::sock::stack().leave_ipv4_multicast(iface, group, src)
    };
    match result {
        Ok(()) => 0,
        Err(e) => errno_from_neterr(e),
    }
}

fn ipv4_mcast_group_source_req(
    sock: &alloc::sync::Arc<net::sock::InetSocket>,
    optval: u64,
    optlen: u32,
    op: SourceOp,
) -> i64 {
    use core::sync::atomic::Ordering;
    if sock.family.load(Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 264 || optval + optlen as u64 > USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(source) = read_sockaddr_storage_v4(optval + 136) else { return -(Errno::Einval.as_i32() as i64); };
    let iface = match resolve_v4_mcast_iface(sock, group, ifindex, net::Ipv4Addr::ANY) {
        Ok(i) => i,
        Err(e) => return e,
    };
    apply_source_op(sock, group, iface, source, op)
}

fn ipv4_group_filter(
    sock: &alloc::sync::Arc<net::sock::InetSocket>,
    optval: u64,
    optlen: u32,
) -> i64 {
    use core::sync::atomic::Ordering;
    if sock.family.load(Ordering::Acquire) != net::sock::AF_INET {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if optlen < 144 || optval + optlen as u64 > USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    let Some(ifindex) = read_u32_at(optval) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(group) = read_sockaddr_storage_v4(optval + 8) else { return -(Errno::Einval.as_i32() as i64); };
    let Some(mode_raw) = read_u32_at(optval + 136) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(numsrc) = read_u32_at(optval + 140) else { return -(Errno::Efault.as_i32() as i64); };
    if !group.is_multicast() || 144u64.saturating_add(numsrc as u64 * 128) > optlen as u64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mode = match net::mcast_filter::FilterMode::from_u32(mode_raw) {
        Ok(m) => m,
        Err(e) => return errno_from_neterr(e),
    };
    let iface = match resolve_v4_mcast_iface(sock, group, ifindex, net::Ipv4Addr::ANY) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let port = match udp_port(sock) { Ok(p) => p, Err(e) => return e };
    let mut sources = alloc::vec::Vec::new();
    for i in 0..numsrc as u64 {
        let Some(src) = read_sockaddr_storage_v4(optval + 144 + i * 128) else {
            return -(Errno::Einval.as_i32() as i64);
        };
        if src.is_unspecified() { return -(Errno::Einval.as_i32() as i64); }
        sources.push(src);
    }
    net::mcast_filter::set(port, iface, group, mode, &sources);
    let local = *sock.local_ip.lock();
    match net::sock::stack().join_ipv4_multicast(iface, group, local) {
        Ok(()) => 0,
        Err(e) => errno_from_neterr(e),
    }
}

fn ipv6_mcast_membership(
    sock: &alloc::sync::Arc<net::sock::InetSocket>,
    optval: u64,
    optlen: u32,
    join: bool,
) -> i64 {
    use core::sync::atomic::Ordering;
    const IPV6_MREQ_LEN: u64 = 20;
    if sock.family.load(Ordering::Acquire) != net::sock::AF_INET6 {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if (optlen as u64) < IPV6_MREQ_LEN {
        return -(Errno::Einval.as_i32() as i64);
    }
    let Some(end) = optval.checked_add(IPV6_MREQ_LEN) else {
        return -(Errno::Efault.as_i32() as i64);
    };
    if end > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }

    let mut addr = [0u8; 16];
    for i in 0..addr.len() {
        // SAFETY: optval + sizeof(ipv6_mreq) was validated in user range.
        addr[i] = unsafe { core::ptr::read_volatile((optval + i as u64) as *const u8) };
    }
    // SAFETY: ipv6_mreq is 16-byte in6_addr followed by a u32 ifindex.
    let req_if = unsafe { core::ptr::read_volatile((optval + 16) as *const u32) };
    let group = net::Ipv6Addr(addr);
    if !group.is_multicast() { return -(Errno::Einval.as_i32() as i64); }

    let iface = if req_if != 0 {
        net::NetIfaceId::from_raw(req_if)
    } else {
        let raw = sock.opts.bound_ifindex.load(Ordering::Acquire);
        if raw == 0 { return -(Errno::Enodev.as_i32() as i64); }
        net::NetIfaceId::from_raw(raw)
    };
    if net::sock::stack().ifaces.lookup(iface).is_none() {
        return -(Errno::Enodev.as_i32() as i64);
    }

    let src = *sock.local_ip6.lock();
    let result = if join {
        net::sock::stack().join_ipv6_multicast(iface, group, src)
    } else {
        net::sock::stack().leave_ipv6_multicast(iface, group, src)
    };
    match result {
        Ok(()) => 0,
        Err(e) => errno_from_neterr(e),
    }
}

fn refresh_tcp_keepalive(sock: &alloc::sync::Arc<net::sock::InetSocket>) {
    if let net::sock::SockKind::TcpConn(entry) = &*sock.kind.lock() {
        net::sock_opts::apply_tcp_keepalive_opts(sock, entry);
    }
}

fn bind_to_device(sock: &alloc::sync::Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    use core::sync::atomic::Ordering;
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
        if fam == net::sock::AF_INET6 {
            net::sock::stack().set_udp6_bound_iface(port, iface);
        } else {
            net::sock::stack().set_udp_bound_iface(port, iface);
        }
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
fn bpf_prog_insns(fd: i32) -> Option<alloc::vec::Vec<u8>> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; sole reader of the fd-table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    let f = fdt.get(fd).ok()?;
    let any = f.inode().as_any()?;
    let prog = any.downcast_ref::<security::bpf::BpfProgInode>()?;
    Some(prog.insns.clone())
}

/// Store SO_PRIORITY when a value is present. # C: O(1)
fn priority_store(s: &alloc::sync::Arc<net::sock::InetSocket>, v: Option<i32>) {
    if let Some(v) = v { s.opts.priority.store(v, core::sync::atomic::Ordering::Release); }
}
/// Store SO_MARK when a value is present. # C: O(1)
fn mark_store(s: &alloc::sync::Arc<net::sock::InetSocket>, v: Option<i32>) {
    if let Some(v) = v { s.opts.mark.store(v, core::sync::atomic::Ordering::Release); }
}
