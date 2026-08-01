// 042 connect — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::{AF_INET, AF_INET6, errno_from_neterr, fd_file, inode_as_inet_socket, vsock_from_file};

fn copy_sockaddr(addr_p: u64, len: usize) -> Result<net::SockaddrStorage, i64> {
    let mut bytes = [0u8; net::sockaddr::SOCKADDR_STORAGE_LEN];
    if uaccess::copy_from_user(&mut bytes[..len], addr_p).is_err() {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    net::SockaddrStorage::from_bytes(&bytes[..len])
        .ok_or(-(Errno::Einval.as_i32() as i64))
}

fn run_connect_hook(sock: &net::sock::InetSocket, storage: &mut net::SockaddrStorage,
                    transport: Option<(u32, u32)>,
                    op: net::cgroup_bpf::SockAddrOp) -> Result<(), i64> {
    let fields = match op {
        net::cgroup_bpf::SockAddrOp::Connect4 => storage.bpf_fields_v4(),
        net::cgroup_bpf::SockAddrOp::Connect6 => storage.bpf_fields_v6(),
        _ => None,
    };
    let Some((user_ip4, user_ip6, user_port)) = fields
        else { return Err(-(Errno::Einval.as_i32() as i64)); };
    let mut context = net::cgroup_bpf::SockAddr {
        user_family: storage.family().unwrap_or_default() as u32,
        user_ip4, user_ip6, user_port,
    };
    net::cgroup_bpf::run_sock_addr_preflight(sock, transport, op, &mut context)
        .map_err(|error| -(error as i64))?;
    match op {
        net::cgroup_bpf::SockAddrOp::Connect4 =>
            storage.apply_bpf_fields_v4(context.user_ip4, context.user_port),
        net::cgroup_bpf::SockAddrOp::Connect6 =>
            storage.apply_bpf_fields_v6(context.user_ip6, context.user_port),
        _ => {}
    }
    Ok(())
}

/// `connect(fd, sockaddr, addrlen)` slot 42. Copies one sockaddr then commits
/// through protocol-owned connect work.
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
    let mut storage = match copy_sockaddr(addr_p, copied_len) {
        Ok(storage) => storage,
        Err(error) => return error,
    };
    if let Some(target) = crate::netlink_fd::from_file(file.clone()) {
        return crate::netlink_fd::connect(&target, &storage);
    }
    if let Some(vs) = vsock_from_file(file.clone()) {
        if let Err(e) = require_sockaddr_vm(copied_len) { return e; }
        let (fam, port, cid) = match storage.vsock() {
            Some(t) => t, None => return -(Errno::Efault.as_i32() as i64),
        };
        if fam == net::socket_args::AF_UNSPEC as u16 {
            return match vs.disconnect() {
                Ok(()) => 0,
                Err(e) => errno_from_neterr(e),
            };
        }
        if fam != net::socket_args::AF_VSOCK as u16 { return -(Errno::Einval.as_i32() as i64); }
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
    let admission = match net::sock::admit_connect(&sock) {
        Ok(admission) => admission,
        Err(error) => return errno_from_neterr(error),
    };
    let family = match storage.family() {
        Some(family) if copied_len >= 2 => family as u32,
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    let sock_fam = sock.family.load(core::sync::atomic::Ordering::Acquire) as u32;
    let addr = if family == net::socket_args::AF_UNSPEC {
        net::sock::RemoteAddr::Unspec
    } else if sock_fam == AF_INET || sock_fam == AF_INET6 {
        let transaction = match net::sock::preflight_connect_admitted(&sock, admission) {
            Ok(transaction) => transaction,
            Err(error) => return errno_from_neterr(error),
        };
        let transport = transaction.transport();
        let ipv6_v6only = transaction.ipv6_v6only();
        let hook = match net::cgroup_bpf::connect_op(
            sock_fam as u16, family as u16, transport, ipv6_v6only,
        ) {
            Ok(hook) => hook,
            Err(error) => return errno_from_neterr(error),
        };
        if hook == Some(net::cgroup_bpf::SockAddrOp::Connect4) {
            if let Err(error) = require_sockaddr_in(copied_len) { return error; }
        } else if hook == Some(net::cgroup_bpf::SockAddrOp::Connect6) {
            if let Err(error) = require_sockaddr_in6(copied_len) { return error; }
        }
        if let Some(op) = hook {
            if let Err(error) = run_connect_hook(&sock, &mut storage, transport, op) {
                return error;
            }
        }
        if let Err(error) = net::cgroup_bpf::validate_connect_family(
            sock_fam as u16, family as u16, transport, ipv6_v6only,
        ) {
            return errno_from_neterr(error);
        }
        // Port rules for the remote endpoint. Placed after the family and
        // length checks so a malformed address reports its own error.
        if let Err(rv) = crate::landlock::check_socket(
            crate::landlock::sock_proto(&sock), ::landlock::netcheck::Op::Connect, storage.as_bytes(), sock_fam as u16)
        { return rv; }
        let addr = if family == AF_INET {
            if let Err(error) = require_sockaddr_in(copied_len) { return error; }
            let Some((ip, port)) = storage.inet4() else {
                return -(Errno::Einval.as_i32() as i64);
            };
            net::sock::RemoteAddr::Inet { ip, port }
        } else {
            if let Err(error) = require_sockaddr_in6(copied_len) { return error; }
            let Some((ip, port, scope_id)) = storage.inet6() else {
                return -(Errno::Einval.as_i32() as i64);
            };
            net::sock::RemoteAddr::Inet6 { ip, port, scope_id }
        };
        return match transaction.commit(
            addr, file.flags().contains(vfs::OpenFlags::O_NONBLOCK),
        ) {
            Ok(()) => { net::bind_file(&file, &sock); 0 }
            Err(net::NetError::Eio) => -(Errno::Etimedout.as_i32() as i64),
            Err(error) => errno_from_neterr(error),
        };
    } else if family == net::socket_args::AF_UNIX {
        if let Err(error) = net::sockaddr::validate_unix_addr(family as u16, copied_len) {
            return -(error.as_i32() as i64);
        }
        let path = match storage.unix_path() {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        let addr = match crate::namei_common::resolve_unix_addr(path) {
            Ok(a) => a,
            Err(e) => return e,
        };
        net::sock::RemoteAddr::Unix(addr)
    } else {
        return -(Errno::Eafnosupport.as_i32() as i64);
    };
    match net::sock::connect_admitted(
        &sock, addr, file.flags().contains(vfs::OpenFlags::O_NONBLOCK), admission,
    ) {
        Ok(()) => { net::bind_file(&file, &sock); 0 }
        Err(net::NetError::Eio) => -(Errno::Etimedout.as_i32() as i64),
        Err(e) => errno_from_neterr(e),
    }
}
