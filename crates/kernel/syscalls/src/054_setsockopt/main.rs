#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::net_common::{fd_file, socket_from_file, vsock_from_file};
use crate::net_errno::errno_from_neterr;
use crate::net_trace::trace_enotsock_at;
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
        if signed_optlen < 0 { return -(Errno::Einval.as_i32() as i64); }
        let (namespace, family) = target.option_context();
        if let Err(error) = net::socket_security::option::setsockopt(
            net::socket_security::option::OptSock::plain(namespace, family),
            level as i32, optname as i32)
        { return errno_from_neterr(error); }
        return socket_filter_option(&target, optname, optval, signed_optlen as u32);
    }
    if let Some(target) = crate::netlink_fd::from_file(file.clone()) {
        if signed_optlen < 0 { return -(Errno::Einval.as_i32() as i64); }
        let optlen = signed_optlen as u32;
        // SOL_SOCKET is answered generically for every family and never
        // reaches the family's own table.
        if level == SOL_SOCKET {
            if let Err(error) = net::socket_security::option::setsockopt(
                net::socket_security::option::OptSock::plain(
                    net::net_ns::namespace_id(&target.socket().net_ns),
                    net::socket_args::AF_NETLINK_WIRE),
                level as i32, optname as i32)
            { return errno_from_neterr(error); }
            return crate::netlink_fd::sol_socket::set(&target, optname, optval, optlen as u64);
        }
        return crate::netlink_fd::setsockopt(&target, level, optname, optval, optlen as u64);
    }
    if let Some(vsock) = vsock_from_file(file.clone()) {
        if signed_optlen < 0 { return -(Errno::Einval.as_i32() as i64); }
        if let Err(error) = vsock.check_option(net::socket_security::option::Access::Set,
            level as i32, optname as i32)
        { return errno_from_neterr(error); }
        return vsock_setsockopt(&vsock, level, optname, optval, signed_optlen);
    }
    let sock = match socket_from_file(file) {
        Some(s) => s,
        None => {
            trace_enotsock_at(fd, b"setsockopt");
            return -(Errno::Enotsock.as_i32() as i64);
        }
    };
    if signed_optlen < 0 { return -(Errno::Einval.as_i32() as i64); }
    if let Err(error) = net::socket_security::option::setsockopt(
        net::socket_security::option::inet(&sock), level as i32, optname as i32)
    {
        return errno_from_neterr(error);
    }
    let optlen = signed_optlen as u32;
    if level == SOL_SOCKET {
        if optname == SO_BINDTODEVICE { return bind_to_device(&sock, optval, optlen); }
        return super::sol_socket::set(&sock, optname, optval, optlen);
    }
    // An AF_UNIX socket carries no protocol-level option table at all: every
    // level above SOL_SOCKET is EOPNOTSUPP, never "unknown option".
    if sock.family.load(Ordering::Acquire) == net::sock::AF_UNIX {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    if level == net::uapi::SOL_PACKET {
        return packet_setsockopt(&sock, optname, optval, optlen);
    }
    if let Some(op) = multicast_preflight(level, optname) {
        if let Err(error) = sock.preflight_mcast_set(op) { return errno_from_neterr(error); }
    }
    if let Some(result) = raw_setsockopt(&sock, level, optname, optval, optlen) {
        return result;
    }
    match level {
        IPPROTO_IP => super::ip::set(&sock, optname, optval, optlen),
        IPPROTO_IPV6 => super::ipv6::set(&sock, optname, optval, optlen),
        IPPROTO_TCP => super::tcp::set(&sock, optname, optval, optlen),
        IPPROTO_UDP => super::udp::set(&sock, optname, optval, optlen),
        _ => -(Errno::Enoprotoopt.as_i32() as i64),
    }
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

/// Linux `SOCK_MIN_RCVBUF`/`SOCK_MIN_SNDBUF` for this ABI (measured against the
/// reference kernel: 2304 / 4608).

/// Publish a new receive-buffer size on the live transport. # C: O(1)
pub(super) fn sync_rcvbuf(sock: &net::sock::InetSocket, value: i32) {
    sync_raw_rcvbuf(sock, value);
    sync_tcp_rcvbuf(sock, value);
    // The error queue is admitted against the same receive budget the ordinary
    // receive queue uses, so a socket that names one names it for both.
    sock.error.adopt_rcvbuf(value);
}

fn sync_raw_rcvbuf(sock: &net::sock::InetSocket, value: i32) {
    match &*sock.kind.lock() {
        net::sock::SockKind::Raw4(endpoint) => endpoint.set_rcvbuf(value.max(0) as usize),
        net::sock::SockKind::Raw6(endpoint) => endpoint.set_rcvbuf(value.max(0) as usize),
        _ => {}
    }
}

/// Apply a just-locked `SO_RCVBUF` to a connection that already exists.
/// Connections created later pick it up from `sock.opts` at connect/accept.
/// # C: O(1)
fn sync_tcp_rcvbuf(sock: &net::sock::InetSocket, value: i32) {
    if let net::sock::SockKind::TcpConn(entry) = &*sock.kind.lock() {
        entry.set_rcv_buf_cap(value.max(0) as u32);
    }
}

fn bind_to_device(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen: u32) -> i64 {
    use net::sock_opts::sol_socket::set::bind_device_allowed;
    let bound = sock.opts.base.bound_device();
    if let Err(error) = bind_device_allowed(super::sol_socket::caps_for(sock), bound) {
        return -(error.as_i32() as i64);
    }
    let (name, end) = match super::sol_socket::import_device_name(optval, optlen) {
        Ok(imported) => imported,
        Err(error) => return -(error.as_i32() as i64),
    };
    if end == 0 { return sock.set_bound_iface(None).map_or_else(errno_from_neterr, |_| 0); }
    let Ok(text) = core::str::from_utf8(&name[..end]) else {
        return -(Errno::Enodev.as_i32() as i64);
    };
    let net_ns = sock.net_ns();
    match net::sock::stack().ifaces.lookup_name_in_ns(text, net_ns) {
        Some((id, _)) => super::sol_socket::bind_to_ifindex(sock, id.raw() as i32),
        None => -(Errno::Enodev.as_i32() as i64),
    }
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

