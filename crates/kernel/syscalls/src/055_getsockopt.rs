// 055 getsockopt — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use net::sock::SockKind;
use crate::net_common::{fd_file, socket_from_file, vsock_from_file};
use crate::net_errno::errno_from_neterr;

#[path = "055_getsockopt/multicast.rs"]
mod multicast;
#[path = "055_getsockopt/out.rs"]
mod out;
#[path = "055_getsockopt/path_mtu.rs"]
mod path_mtu;
#[path = "055_getsockopt/raw.rs"]
mod raw;
#[path = "055_getsockopt/ip.rs"]
mod ip;
#[path = "055_getsockopt/ipv6.rs"]
mod ipv6;
#[path = "055_getsockopt/tcp.rs"]
mod tcp;
#[path = "055_getsockopt/udp.rs"]
mod udp;
#[path = "055_getsockopt/sol_socket.rs"]
mod sol_socket;
#[path = "055_getsockopt/packet.rs"]
mod packet;
#[path = "055_getsockopt/peerpidfd.rs"]
mod peerpidfd;
#[path = "055_getsockopt/packet_abi.rs"]
mod packet_abi;
#[path = "055_getsockopt/uapi.rs"]
mod uapi;
#[path = "055_getsockopt/varlen.rs"]
mod varlen;
use out::OptOut;
use uapi::*;

/// `getsockopt(fd, level, optname, optval, optlen)` slot 55.
///
/// Honored:
/// SOL_SOCKET reads answer from the canonical option table; a socket that
/// pinned no peer identity reports the no-peer `struct ucred` rather than the
/// caller's own credentials. Each protocol level has its own table, and an
/// AF_UNIX socket has none at all above SOL_SOCKET. # C: O(1)
pub fn sys_getsockopt(args: &SyscallArgs) -> i64 {
    let _fd     = args.a0;
    let level   = args.a1;
    let optname = args.a2;
    let optval  = args.a3;
    let optlen_p = args.a4;
    let out = OptOut::new(optval, optlen_p);
    let u64_back = |val: u64| -> i64 {
        const VSOCK_BUFFER_OPTION_BYTES: usize = core::mem::size_of::<u64>();
        let mut raw_len = [0u8; core::mem::size_of::<i32>()];
        if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() { return -(Errno::Efault.as_i32() as i64); }
        let requested = i32::from_ne_bytes(raw_len);
        if requested < VSOCK_BUFFER_OPTION_BYTES as i32 { return -(Errno::Einval.as_i32() as i64); }
        if uaccess::copy_to_user(optval, &val.to_ne_bytes()).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        if uaccess::copy_to_user(optlen_p, &(VSOCK_BUFFER_OPTION_BYTES as u32).to_ne_bytes()).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        0
    };
    let timeval_back = |timeout_ns: u64| -> i64 {
        const VSOCK_TIMEVAL_FIELD_BYTES: usize = core::mem::size_of::<i64>();
        const VSOCK_TIMEVAL_BYTES: usize = VSOCK_TIMEVAL_FIELD_BYTES * 2;
        let mut raw_len = [0u8; core::mem::size_of::<i32>()];
        if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() { return -(Errno::Efault.as_i32() as i64); }
        let requested = i32::from_ne_bytes(raw_len);
        if requested < VSOCK_TIMEVAL_BYTES as i32 { return -(Errno::Einval.as_i32() as i64); }
        let seconds = timeout_ns / net::uapi::VSOCK_NANOSECONDS_PER_SECOND;
        let microseconds = (timeout_ns % net::uapi::VSOCK_NANOSECONDS_PER_SECOND)
            / net::uapi::VSOCK_NANOSECONDS_PER_MICROSECOND;
        let Ok(seconds) = i64::try_from(seconds) else { return -(Errno::Erange.as_i32() as i64); };
        let Ok(microseconds) = i64::try_from(microseconds) else { return -(Errno::Erange.as_i32() as i64); };
        let mut bytes = [0u8; VSOCK_TIMEVAL_BYTES];
        bytes[..VSOCK_TIMEVAL_FIELD_BYTES].copy_from_slice(&seconds.to_ne_bytes());
        bytes[VSOCK_TIMEVAL_FIELD_BYTES..].copy_from_slice(&microseconds.to_ne_bytes());
        if uaccess::copy_to_user(optval, &bytes).is_err() { return -(Errno::Efault.as_i32() as i64); }
        if uaccess::copy_to_user(optlen_p, &(VSOCK_TIMEVAL_BYTES as u32).to_ne_bytes()).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        0
    };
    let file = match fd_file(_fd) {
        Some(file) => file,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if level == SOL_SOCKET && optname == SO_ERROR {
        let target = match crate::recvmsg::from_file(file.clone()) {
            Ok(target) => target,
            Err(e) => return e,
        };
        let (namespace, family) = target.option_context();
        if let Err(error) = net::socket_security::option::getsockopt(
            net::socket_security::option::OptSock::plain(namespace, family),
            level as i32, optname as i32)
        { return errno_from_neterr(error); }
        let pending = target.take_error();
        return out.i32(pending);
    }
    if level == SOL_SOCKET && matches!(optname, SO_LOCK_FILTER | SO_GET_FILTER) {
        let target = match socket::FilterFile::from_file(file.clone()) {
            Some(target) => target,
            None => return -(Errno::Enotsock.as_i32() as i64),
        };
        let (namespace, family) = target.option_context();
        if let Err(error) = net::socket_security::option::getsockopt(
            net::socket_security::option::OptSock::plain(namespace, family),
            level as i32, optname as i32)
        { return errno_from_neterr(error); }
        if optname == SO_GET_FILTER { return varlen::get_filter(&target, optval, optlen_p); }
        return out.i32(i32::from(target.is_locked()));
    }
    if let Some(target) = crate::netlink_fd::from_file(file.clone()) {
        return crate::netlink_fd::getsockopt(&target, level, optname, optval, optlen_p);
    }
    if let Some(vsock) = vsock_from_file(file.clone()) {
        if let Err(error) = vsock.check_option(net::socket_security::option::Access::Get,
            level as i32, optname as i32)
        { return errno_from_neterr(error); }
        if level == net::uapi::SOL_VSOCK {
            if net::vsock_socket::VsockSocket::is_vsock_buffer_option(optname) {
                return match vsock.get_vsock_buffer_option(optname) {
                    Ok(value) => u64_back(value),
                    Err(e) => errno_from_neterr(e),
                };
            }
            if net::vsock_socket::VsockSocket::is_vsock_connect_timeout_option(optname) {
                return timeval_back(vsock.vsock_connect_timeout_ns());
            }
            return -(Errno::Enoprotoopt.as_i32() as i64);
        }
        return match vsock.get_socket_option(level, optname) {
            Ok(value) => out.i32(value),
            Err(e) => errno_from_neterr(e),
        };
    }
    let sock = match socket_from_file(file) {
        Some(sock) => sock,
        None => return -(Errno::Enotsock.as_i32() as i64),
    };
    if let Err(error) = net::socket_security::option::getsockopt(
        net::socket_security::option::inet(&sock), level as i32, optname as i32)
    {
        return errno_from_neterr(error);
    }
    // An AF_UNIX socket carries no protocol-level option table at all: every
    // level above SOL_SOCKET is EOPNOTSUPP, never "unknown option".
    if level != SOL_SOCKET
        && sock.family.load(core::sync::atomic::Ordering::Acquire) == net::sock::AF_UNIX
    {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    if level == net::uapi::SOL_PACKET {
        return packet::packet_getsockopt(&sock, optname, optval, optlen_p);
    }
    if level == SOL_SOCKET && optname == SO_PEERPIDFD {
        return peerpidfd::get(&sock, optval, optlen_p);
    }
    if level == SOL_SOCKET {
        match optname {
            SO_MEMINFO => return varlen::meminfo(&sock, optval, optlen_p),
            SO_PEERGROUPS => {
                let groups = peercred_for_socket(&sock)
                    .map(|cred| cred.groups.as_deref().unwrap_or(&[]).to_vec());
                return varlen::peergroups(groups, optval, optlen_p);
            }
            SO_PEERNAME => return varlen::peername(&sock, optval, optlen_p),
            SO_PEERSEC => return varlen::peersec(&sock, optval, optlen_p),
            _ => {}
        }
    }
    if level == SOL_SOCKET && optname == SO_PEERCRED {
        // `net::sock_opts::peercred` owns the encoding, including the answer
        // for a socket that never pinned a peer identity.
        let snapshot = peercred_for_socket(&sock)
            .map(|cred| { let (pid, uid, gid) = cred.ids(); (pid as i32, uid, gid) });
        // DIAG (debug-dbus): dbus-broker calls this at accept to learn a
        // client's pid; a wrong pid there breaks logind session lookup.
        #[cfg(feature = "debug-dbus")]
        {
            klog::write_raw(b"[PEERCRED fd=");
            klog::write_dec_u64(_fd);
            klog::write_raw(b" -> pid=");
            klog::write_dec_u64(snapshot.map(|(pid, _, _)| pid as u64).unwrap_or(0));
            klog::write_raw(b" src=");
            klog::write_raw(if snapshot.is_some() { b"pair" } else { b"none" });
            klog::write_raw(b"]\n");
        }
        return out.bytes(&net::sock_opts::peercred::ucred_bytes(snapshot));
    }
    if level == SOL_SOCKET {
        // The interface name has its own `ERANGE`-bounded copyout shape.
        if optname == SO_BINDTODEVICE { return bind_to_device_name(&sock, optval, optlen_p); }
        return sol_socket::read(&sock, optname, optval, optlen_p);
    }
    if let Some(result) = raw::get(&sock, level, optname, &out) { return result; }
    match level {
        IPPROTO_IP => ip::get(&sock, optname, &out),
        IPPROTO_IPV6 => ipv6::get(&sock, optname, &out),
        IPPROTO_TCP => tcp::get(&sock, optname, &out),
        IPPROTO_UDP => udp::get(&sock, optname, &out),
        IPPROTO_RAW => -(Errno::Enoprotoopt.as_i32() as i64),
        // Linux getsockopt: an unknown OPTION at a recognized level is
        // ENOPROTOOPT for every family, but an unrecognized LEVEL leaves the
        // chain as EOPNOTSUPP for non-IPv6 sockets while IPv6 reports
        // ENOPROTOOPT. Real programs use recognized levels, so only this
        // malformed-level path changes.
        _ if sock.family.load(core::sync::atomic::Ordering::Acquire)
            != net::sock::AF_INET6 => -(Errno::Eopnotsupp.as_i32() as i64),
        _ => -(Errno::Enoprotoopt.as_i32() as i64),
    }
}

fn peercred_for_socket(sock: &alloc::sync::Arc<net::sock::InetSocket>)
    -> Option<net::PeerCred>
{
    match &*sock.kind.lock() {
        SockKind::Unix(pair, end) => Some(pair.peer_cred(*end)),
        SockKind::UnixMsgPair(pair, end) => Some(pair.peer_cred(*end)),
        SockKind::UnixListener(listener) => Some(listener.owner_cred()),
        _ => None,
    }
}

fn bind_to_device_name(s: &alloc::sync::Arc<net::sock::InetSocket>,
                       optval: u64, optlen_p: u64) -> i64 {
    use core::sync::atomic::Ordering;
    const IFNAMSIZ: usize = 16;
    if optval == 0 || optval >= USER_VA_END || optlen_p == 0 || optlen_p >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let mut raw_len = [0u8; 4];
    if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cap = u32::from_ne_bytes(raw_len) as usize;
    let raw = s.opts.bound_ifindex.load(Ordering::Acquire);
    if raw == 0 {
        if uaccess::copy_to_user(optlen_p, &[0u8; 4]).is_err() {
            return -(Errno::Efault.as_i32() as i64);
        }
        return 0;
    }
    let id = net::NetIfaceId::from_raw(raw);
    let name = match net::sock::stack().ifaces.name_in_ns(id, s.net_ns()) {
        Some(name) => name,
        None => return -(Errno::Enodev.as_i32() as i64),
    };
    let name = name.as_bytes();
    let need = name.len().saturating_add(1);
    if need > IFNAMSIZ || cap < need || optval + need as u64 > USER_VA_END {
        return -(Errno::Erange.as_i32() as i64);
    }
    let mut value = [0u8; IFNAMSIZ];
    value[..name.len()].copy_from_slice(name);
    if uaccess::copy_to_user(optval, &value[..need]).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    if uaccess::copy_to_user(optlen_p, &(need as u32).to_ne_bytes()).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}

pub(crate) use net::sock_opts::identity::{socket_acceptconn, socket_protocol, socket_type};
