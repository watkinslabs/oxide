// 044 sendto — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use net::sock::SockKind;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::{AF_INET6, errno_from_neterr, file_is_nonblock, socket_from_fd};

/// `sendto(fd, buf, len, flags, dest, dest_len)` slot 44.
/// # C: O(payload bytes)
pub fn sys_sendto(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use core::sync::atomic::Ordering;
    const MSG_DONTWAIT: u64 = 0x40;
    let fd     = args.a0;
    let bufp   = args.a1;
    let len    = args.a2 as usize;
    let flags  = args.a3;
    let dest_p = args.a4;
    // F132: netlink fd routing must happen BEFORE socket_from_fd,
    // which only knows InetSocket — netlink would otherwise hit
    // the ENOTSOCK branch despite is_netlink() recognizing it.
    if crate::netlink_fd::is_netlink(fd) {
        if bufp == 0 || bufp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        if len > 65507 { return -(Errno::Emsgsize.as_i32() as i64); }
        return crate::netlink_fd::sendto(fd, bufp, len);
    }
    let sock   = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"sendto"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    if bufp == 0 || bufp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    if len > 65507 { return -(Errno::Emsgsize.as_i32() as i64); }
    // F131/F146: AF_PACKET fast path lives in af_packet.rs.
    if let Some(rv) = crate::af_packet::sendto(&sock, bufp, len, dest_p) {
        return rv;
    }
    let nonblock = (flags & MSG_DONTWAIT) != 0 || file_is_nonblock(fd);
    let timeo = sock.opts.sndtimeo_ns.load(Ordering::Acquire);
    #[cfg(target_arch = "x86_64")]
    let now = || hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = || hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let deadline = if timeo > 0 { Some(now().saturating_add(timeo as u64)) } else { None };
    // SAFETY: ptr range validated; user page mapped under caller's AS.
    let payload: alloc::vec::Vec<u8> = unsafe {
        core::slice::from_raw_parts(bufp as *const u8, len).to_vec()
    };
    // Parse optional destination based on socket family.
    let dest = if dest_p == 0 {
        None
    } else if matches!(*sock.kind.lock(), SockKind::UnixDgram(_)) {
        match read_sockaddr_un_path(dest_p) {
            Some(p) => Some(net::sock::RemoteAddr::UnixPath(p)),
            None    => return -(Errno::Einval.as_i32() as i64),
        }
    } else if read_sa_family(dest_p) == Some(AF_INET6 as u16) {
        // AF_INET6 destination: parse the 28-byte sockaddr_in6 and
        // route through the v6 send path. Reading it as sockaddr_in
        // (the v4 branch below) would mis-read the address as
        // 0.0.0.0 and silently send a v4 datagram into the void.
        match read_sockaddr_in6(dest_p) {
            Some((_fam, port, bytes, _scope)) =>
                Some(net::sock::RemoteAddr::Inet6 { ip: net::Ipv6Addr(bytes), port }),
            None => return -(Errno::Eafnosupport.as_i32() as i64),
        }
    } else {
        match read_sockaddr_any(dest_p) {
            Some((_fam, ip, port)) => Some(net::sock::RemoteAddr::Inet { ip, port }),
            None => return -(Errno::Eafnosupport.as_i32() as i64),
        }
    };
    // Fetch sender creds for AF_UNIX SCM.
    let creds = match sched::live::current() {
        Some(t) => net::sock::SenderCreds {
            pid: t.tgid.load(core::sync::atomic::Ordering::Acquire),
            uid: t.creds.euid.load(core::sync::atomic::Ordering::Acquire),
            gid: t.creds.egid.load(core::sync::atomic::Ordering::Acquire),
        },
        None => net::sock::SenderCreds::default(),
    };
    loop {
        match net::sock::sendto(&sock, &payload, dest.clone(), creds) {
            Ok(n)  => return n as i64,
            Err(net::NetError::Eagain) => {
                if nonblock { return -(Errno::Eagain.as_i32() as i64); }
                if let Some(dl) = deadline { if now() >= dl { return -(Errno::Eagain.as_i32() as i64); } }
                // SAFETY: process ctx; runqueue installed; preempt-off; tick_yield reschedules.
                unsafe { sched::live::tick_yield(); }
            }
            Err(e) => return errno_from_neterr(e),
        }
    }
}
