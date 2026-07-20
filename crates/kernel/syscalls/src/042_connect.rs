// 042 connect — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::{AF_INET, AF_INET6, errno_from_neterr, fd_file, inode_as_inet_socket, vsock_from_file};

/// `connect(fd, sockaddr, addrlen)` slot 42. Parses user sockaddr →
/// `net::sock::RemoteAddr` then calls `net::sock::connect`.
/// # C: O(1) UDP/UNIX, O(SYN-ACK RTT) TCP.
pub fn sys_connect(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let addrlen = args.a2;
    let file = match fd_file(fd) {
        Some(f) => f,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let copied_len = match move_sockaddr_to_kernel_shape(addr_p, addrlen) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if let Some(target) = crate::netlink_fd::from_file(file.clone()) {
        return crate::netlink_fd::connect(&target, addr_p, copied_len);
    }
    if let Some(vs) = vsock_from_file(file.clone()) {
        if let Err(e) = require_sockaddr_vm(copied_len) { return e; }
        let (fam, port, cid) = match read_sockaddr_vm(addr_p) {
            Some(t) => t, None => return -(Errno::Efault.as_i32() as i64),
        };
        const AF_UNSPEC: u16 = 0;
        if fam == AF_UNSPEC {
            return match vs.disconnect() {
                Ok(()) => 0,
                Err(e) => errno_from_neterr(e),
            };
        }
        if fam != 40 { return -(Errno::Einval.as_i32() as i64); }
        if !matches!(vs.so_type.load(Ordering::Acquire) as u32,
            net::socket_args::SOCK_STREAM | net::socket_args::SOCK_SEQPACKET) {
            return -(Errno::Eopnotsupp.as_i32() as i64);
        }
        enum VsockConnect {
            Start,
            Wait(Arc<net::vsock::VsockConn>),
            Err(Errno),
        }
        let action = match &*vs.kind.lock() {
            net::vsock_socket::VsockKind::Init | net::vsock_socket::VsockKind::Bound { .. } =>
                VsockConnect::Start,
            net::vsock_socket::VsockKind::Listener(_) => VsockConnect::Err(Errno::Einval),
            net::vsock_socket::VsockKind::Conn(c) => {
                match *c.st.lock() {
                    net::vsock::VsockState::Connected | net::vsock::VsockState::RcvShutdown => VsockConnect::Err(Errno::Eisconn),
                    net::vsock::VsockState::Connecting => {
                        if vs.is_nonblock() { VsockConnect::Err(Errno::Ealready) } else { VsockConnect::Wait(c.clone()) }
                    }
                    net::vsock::VsockState::Closed => VsockConnect::Err(Errno::Einval),
                }
            }
            net::vsock_socket::VsockKind::Released => VsockConnect::Err(Errno::Ebadf),
        };
        let map_vsock_err = |e| match e {
            net::NetError::Econnrefused => -(Errno::Econnrefused.as_i32() as i64),
            net::NetError::Enetunreach  => -(Errno::Enetunreach.as_i32() as i64),
            net::NetError::Esocktnosupport => -(Errno::Esocktnosupport.as_i32() as i64),
            _ => -(Errno::Etimedout.as_i32() as i64),
        };
        return match action {
            VsockConnect::Err(e) => -(e.as_i32() as i64),
            VsockConnect::Wait(c) => match net::vsock::connect_wait(&c) {
                Ok(()) => 0,
                Err(e) => map_vsock_err(e),
            },
            VsockConnect::Start => match vs.connect_transport(cid, port, vs.is_nonblock()) {
                Ok(()) if vs.is_nonblock() => -(Errno::Einprogress.as_i32() as i64),
                Ok(()) => 0,
                Err(e) => map_vsock_err(e),
            },
        };
    }
    let sock = match inode_as_inet_socket(file.inode()) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"connect"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    const AF_UNIX: u32 = 1;
    const AF_UNSPEC: u32 = 0;
    let family = match read_sa_family_checked(addr_p, copied_len) {
        Ok(f) => f as u32, Err(e) => return e,
    };
    let addr = if family == AF_UNSPEC {
        net::sock::RemoteAddr::Unspec
    } else if family == AF_UNIX {
        let path = match read_sockaddr_un_path_len(addr_p, addrlen) {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        let addr = match crate::namei_common::resolve_unix_addr(path) {
            Ok(a) => a,
            Err(e) => return e,
        };
        net::sock::RemoteAddr::Unix(addr)
    } else if family == AF_INET || family == AF_INET6 {
        let sock_fam = sock.family.load(core::sync::atomic::Ordering::Acquire) as u32;
        // F180b: native v6 dst routes through connect_v6 (UDP stashes
        // the v6 peer, TCP runs tcp_connect_ip). Only the v4-mapped
        // form (::ffff:a.b.c.d) falls through to the v4 path for
        // dual-stack semantics — ::1 / :: / global are genuine v6 and
        // must NOT be mis-stashed as a v4 peer.
        if family == AF_INET6 {
            if let Err(e) = require_sockaddr_in6(copied_len) { return e; }
            if sock_fam != AF_INET6 { return -(Errno::Eafnosupport.as_i32() as i64); }
            if let Some((_, port, bytes, scope_id)) = read_sockaddr_in6(addr_p) {
                let v4_mapped = ipv4_from_v6_mapped(&bytes).is_some();
                if !v4_mapped {
                    return match net::sock::connect(&sock, net::sock::RemoteAddr::Inet6 {
                        ip: net::Ipv6Addr(bytes), port, scope_id,
                    }, file.flags().contains(vfs::OpenFlags::O_NONBLOCK)) {
                        Ok(()) => 0,
                        Err(net::NetError::Eio) => -(Errno::Etimedout.as_i32() as i64),
                        Err(e) => errno_from_neterr(e),
                    };
                }
            }
        } else if let Err(e) = require_sockaddr_in(copied_len) {
            return e;
        } else if sock_fam != AF_INET {
            return -(Errno::Eafnosupport.as_i32() as i64);
        }
        let (_fam, ip, port) = match read_sockaddr_any(addr_p) {
            Some(t) => t, None => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        net::sock::RemoteAddr::Inet { ip, port }
    } else {
        return -(Errno::Eafnosupport.as_i32() as i64);
    };
    match net::sock::connect(&sock, addr, file.flags().contains(vfs::OpenFlags::O_NONBLOCK)) {
        Ok(()) => { net::bind_file(&file, &sock); 0 }
        Err(net::NetError::Eio) => -(Errno::Etimedout.as_i32() as i64),
        Err(e) => errno_from_neterr(e),
    }
}
