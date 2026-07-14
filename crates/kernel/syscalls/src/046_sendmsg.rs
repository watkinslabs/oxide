// 046 sendmsg — fault-recoverable snapshot import followed by kernel-buffer dispatch.
#![cfg(target_os = "oxide-kernel")]

use net::sock::{RemoteAddr, SockKind};
use syscall::errno::Errno;
use syscall::SyscallArgs;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }
fn family(name: &[u8]) -> Result<u16, i64> {
    if name.len() < 2 { return Err(err(Errno::Einval)); }
    Ok(u16::from_ne_bytes(name[..2].try_into().unwrap()))
}

fn parse_dest(sock: &net::sock::InetSocket, name: &[u8]) -> Result<Option<RemoteAddr>, i64> {
    if name.is_empty() { return Ok(None); }
    if matches!(*sock.kind.lock(), SockKind::UnixDgram(_)) {
        if family(name)? != 1 { return Err(err(Errno::Eafnosupport)); }
        let path = crate::net_sockaddr::unix_path_from_kernel_sockaddr(name)?;
        return crate::namei_common::resolve_unix_addr(path).map(|a| Some(RemoteAddr::Unix(a)));
    }
    match family(name)? {
        2 => {
            if name.len() < 16 { return Err(err(Errno::Einval)); }
            let port = u16::from_be_bytes(name[2..4].try_into().unwrap());
            let ip = net::Ipv4Addr::new(name[4], name[5], name[6], name[7]);
            Ok(Some(RemoteAddr::Inet { ip, port }))
        }
        10 => {
            if name.len() < 28 { return Err(err(Errno::Einval)); }
            let port = u16::from_be_bytes(name[2..4].try_into().unwrap());
            let mut ip = [0u8; 16]; ip.copy_from_slice(&name[8..24]);
            let scope_id = u32::from_ne_bytes(name[24..28].try_into().unwrap());
            Ok(Some(RemoteAddr::Inet6 { ip: net::Ipv6Addr(ip), port, scope_id }))
        }
        _ => Err(err(Errno::Eafnosupport)),
    }
}

/// `sendmsg(fd, msghdr, flags)` slot 46. The fd is pinned before importing the
/// complete user message, then every backend consumes kernel-owned bytes only.
/// # C: O(iov + payload + control)
pub fn sys_sendmsg(args: &SyscallArgs) -> i64 {
    let fd = args.a0;
    let flags = args.a2;
    let file = match crate::net_common::fd_file(fd) { Some(file) => file, None => return err(Errno::Ebadf) };
    let is_netlink = crate::netlink_fd::is_netlink_file(&file);
    let is_vsock = crate::net_common::inode_as_vsock(file.inode()).is_some();
    let inet = crate::net_common::inode_as_inet_socket(file.inode());
    if !is_netlink && !is_vsock && inet.is_none() { return err(Errno::Enotsock); }
    let raw_oob = inet.as_ref().is_some_and(|sock| matches!(*sock.kind.lock(),
        SockKind::Raw4(_) | SockKind::Raw6(_))) && flags & net::uapi::MSG_OOB != 0;
    if raw_oob {
        return match crate::send_user::import_raw_oob(args.a1) {
            Ok(()) => err(Errno::Eopnotsupp), Err(e) => e,
        };
    }
    let user = match crate::send_user::import(args.a1) { Ok(user) => user, Err(e) => return e };

    if is_netlink {
        if let Err(e) = crate::cmsg_parse::validate_non_unix_control(&user.control) { return e; }
        if user.payload_faulted { return err(Errno::Efault); }
        return crate::netlink_fd::sendmsg_imported(&file, &user.name, &user.payload);
    }
    if is_vsock {
        if let Err(e) = crate::cmsg_parse::validate_non_unix_control(&user.control) { return e; }
        if !user.name.is_empty() && user.name.len() < 16 { return err(Errno::Einval); }
        let nonblock = flags & net::uapi::MSG_DONTWAIT != 0
            || file.flags().contains(vfs::OpenFlags::O_NONBLOCK);
        let result = if nonblock { file.inode().write_nonblock(0, &user.payload) }
            else { file.inode().write(0, &user.payload) };
        return match result { Ok(n) => n as i64, Err(e) => -(e as i64) };
    }
    let sock = inet.unwrap();
    let raw_family = match &*sock.kind.lock() {
        SockKind::Raw4(_) => Some(false), SockKind::Raw6(_) => Some(true), _ => None,
    };
    if matches!(*sock.kind.lock(), SockKind::Packet { .. }) {
        if let Err(e) = crate::cmsg_parse::validate_non_unix_control(&user.control) { return e; }
        if user.payload_faulted { return err(Errno::Efault); }
        let addr = match crate::af_packet::decode_send_addr(&user.name) { Ok(addr) => addr, Err(e) => return e };
        if let Some(result) = crate::af_packet::sendto_imported(&sock, &user.payload, addr) { return result; }
    }
    if let Some(ipv6) = raw_family {
        let dest = match parse_dest(&sock, &user.name) { Ok(dest) => dest, Err(e) => return e };
        if let Err(e) = crate::cmsg_parse::validate_non_unix_control(&user.control) { return e; }
        let net_ns = sock.net_ns.load(core::sync::atomic::Ordering::Acquire);
        let cap = sched::live::current().is_some_and(|cur| nscg::proc_ns::has_net_raw_for(cur, net_ns));
        let mut control = match crate::cmsg_parse::parse_raw_control(&user.control, ipv6, cap) {
            Ok(control) => control, Err(e) => return e,
        };
        control.apply_flags(flags);
        if user.payload_faulted { return err(Errno::Efault); }
        return crate::s044_sendto::send_over_socket(
            &sock, &user.payload, dest, flags, fd, &control,
        );
    }
    if user.payload_faulted && matches!(*sock.kind.lock(),
        SockKind::Udp
            | SockKind::UnixDgram(_) | SockKind::UnixMsgPair(_, _))
    { return err(Errno::Efault); }
    if let Some(result) = crate::cmsg_parse::try_sendmsg_with_control(
        &sock, &user.name, &user.payload, &user.control, flags,
    ) { return result; }
    if let Err(e) = crate::cmsg_parse::validate_non_unix_control(&user.control) { return e; }
    let dest = match parse_dest(&sock, &user.name) { Ok(dest) => dest, Err(e) => return e };
    crate::s044_sendto::send_over_socket(&sock, &user.payload, dest, flags, fd,
        &net::send_control::SendControl::default())
}
