// 049 bind — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::{AF_INET, AF_INET6, errno_from_neterr, socket_from_fd};

/// `bind(fd, addr, addrlen)` slot 49.
/// # C: O(1)
pub fn sys_bind(args: &SyscallArgs) -> i64 {
    const AF_UNIX: u16 = 1;
    let fd     = args.a0;
    let addr_p = args.a1;
    if crate::netlink_fd::is_netlink(fd) {
        return crate::netlink_fd::bind();
    }
    let sock   = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"bind"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    let family = match read_sa_family(addr_p) {
        Some(f) => f, None => return -(Errno::Efault.as_i32() as i64),
    };
    // Parse the user sockaddr into the typed BoundAddr enum.
    let addr = if family == AF_UNIX as u16 {
        let path = match read_sockaddr_un_path(addr_p) {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        // If the socket is already SOCK_DGRAM, pass its queue along.
        match &*sock.kind.lock() {
            net::sock::SockKind::UnixDgram(q) =>
                net::sock::BoundAddr::UnixDgram { path, queue: q.clone() },
            _ => net::sock::BoundAddr::UnixListener(path),
        }
    } else if family == AF_INET as u16 {
        let sock_fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
        if family != sock_fam { return -(Errno::Einval.as_i32() as i64); }
        let (_fam, ip, port) = match read_sockaddr_any(addr_p) {
            Some(t) => t, None => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        net::sock::BoundAddr::Inet { ip, port }
    } else if family == AF_INET6 as u16 {
        // F180a: AF_INET6 bind via v6 path with the 16-byte address.
        let sock_fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
        if family != sock_fam { return -(Errno::Einval.as_i32() as i64); }
        let (_fam, port, bytes, _scope) = match read_sockaddr_in6(addr_p) {
            Some(t) => t, None => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        net::sock::BoundAddr::Inet6 { ip: net::Ipv6Addr(bytes), port }
    } else if family == 17 /* AF_PACKET */ {
        // F131: sockaddr_ll = u16 family + u16 proto_be + i32 ifindex + tail.
        // SAFETY: addr_p validated < USER_VA_END above; sockaddr_ll spans +0..+20.
        let (proto_be, ifindex) = unsafe {
            let p = core::ptr::read_volatile((addr_p + 2) as *const u16);
            let i = core::ptr::read_volatile((addr_p + 4) as *const i32);
            (p, i)
        };
        let registered = {
            let k = sock.kind.lock();
            if let net::sock::SockKind::Packet { ifindex: ifi, protocol, .. } = &*k {
                ifi.store(ifindex as u32, core::sync::atomic::Ordering::Release);
                protocol.store(proto_be.swap_bytes(), core::sync::atomic::Ordering::Release);
                true
            } else { false }
        };
        if registered {
            // F137: register for rx delivery (e.g. DHCPOFFER frames).
            net::sock::register_packet(&sock);
            return 0;
        }
        return -(Errno::Einval.as_i32() as i64);
    } else {
        return -(Errno::Eafnosupport.as_i32() as i64);
    };
    // F153: also materialise an AF_UNIX path as a tmpfs sock inode
    // so stat(path) returns S_IFSOCK + chmod/unlink flow through VFS.
    let unix_path = match &addr {
        net::sock::BoundAddr::UnixListener(p) => Some(p.clone()),
        net::sock::BoundAddr::UnixDgram { path, .. } => Some(path.clone()),
        _ => None,
    };
    let rv = match net::sock::bind(&sock, addr) {
        Ok(()) => 0, Err(e) => errno_from_neterr(e),
    };
    if rv == 0 {
        if let Some(p) = unix_path {
            fs::tmpfs::register(p, fs::tmpfs::TmpfsSockInode::new() as vfs::InodeRef);
        }
    }
    rv
}
