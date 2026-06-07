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
    const IPPROTO_TCP: u64 = 6;
    let fd       = args.a0;
    let level    = args.a1;
    let optname  = args.a2;
    let optval   = args.a3;
    let optlen   = args.a4 as u32;
    if crate::netlink_fd::is_netlink(fd) {
        return crate::netlink_fd::setsockopt();
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
                entry.conn.lock().ka_enabled = v != 0;
            }
        },
        (SOL_SOCKET, 6)  => if let Some(v) = read_i32(optval) { sock.opts.broadcast.store(v, Ordering::Release); },
        (SOL_SOCKET, 7)  => if let Some(v) = read_i32(optval) { sock.opts.sndbuf.store(v, Ordering::Release); },
        (SOL_SOCKET, 8)  => if let Some(v) = read_i32(optval) { sock.opts.rcvbuf.store(v, Ordering::Release); },
        (SOL_SOCKET, 16) => if let Some(v) = read_i32(optval) { sock.opts.passcred.store(v, Ordering::Release); }, // SO_PASSCRED
        (SOL_SOCKET, 12) => priority_store(&sock, read_i32(optval)),
        (SOL_SOCKET, 36) => mark_store(&sock, read_i32(optval)),
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
        _ => {}
    }
    0
}

/// Store SO_PRIORITY when a value is present. # C: O(1)
fn priority_store(s: &alloc::sync::Arc<net::sock::InetSocket>, v: Option<i32>) {
    if let Some(v) = v { s.opts.priority.store(v, core::sync::atomic::Ordering::Release); }
}
/// Store SO_MARK when a value is present. # C: O(1)
fn mark_store(s: &alloc::sync::Arc<net::sock::InetSocket>, v: Option<i32>) {
    if let Some(v) = v { s.opts.mark.store(v, core::sync::atomic::Ordering::Release); }
}
