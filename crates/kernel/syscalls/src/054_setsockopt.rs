// 054 setsockopt — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use crate::net_trace::trace_enotsock_at;
use crate::net_common::socket_from_fd;

/// `setsockopt(fd, level, optname, optval, optlen)` slot 54. # C: O(1)
pub fn sys_setsockopt(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    const SOL_SOCKET: u64  = 1;
    const SO_BINDTODEVICE: u64 = 25;
    const IPPROTO_TCP: u64 = 6;
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
        (SOL_SOCKET, 7)  => if let Some(v) = read_i32(optval) { sock.opts.sndbuf.store(v, Ordering::Release); },
        (SOL_SOCKET, 8)  => if let Some(v) = read_i32(optval) { sock.opts.rcvbuf.store(v, Ordering::Release); },
        (SOL_SOCKET, 16) => if let Some(v) = read_i32(optval) { sock.opts.passcred.store(v, Ordering::Release); }, // SO_PASSCRED
        (SOL_SOCKET, 12) => priority_store(&sock, read_i32(optval)),
        (SOL_SOCKET, 36) => mark_store(&sock, read_i32(optval)),
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
        _ => {}
    }
    0
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
