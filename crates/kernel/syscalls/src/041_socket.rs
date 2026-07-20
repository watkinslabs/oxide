// 041 socket — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use alloc::sync::Arc;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{File, OpenFlags};
use net::sock::InetSocket;
use net::socket_args::{
    parse_socket_args, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, AF_UNIX, AF_VSOCK,
    SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET, SOCK_STREAM,
};

/// `socket(domain, type, protocol)` slot 41. # C: O(1)
pub fn sys_socket(args: &SyscallArgs) -> i64 {
    let domain = args.a0 as u32;
    let raw    = args.a1 as u32;
    let proto  = args.a2 as u32;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let net_namespace = match cur.network_namespace_snapshot() {
        Some(namespace) => namespace,
        None => return -(Errno::Esrch.as_i32() as i64),
    };
    let spec = match parse_socket_args(domain, raw, proto, nscg::has_net_raw_for(cur, &net_namespace)) {
        Ok(s) => s,
        Err(e) => return -(e.as_i32() as i64),
    };
    let security_context = security::network::Context {
        namespace: net_namespace.id().as_u64(),
        family: spec.family as u16,
        socket_type: spec.typ,
        protocol: spec.protocol,
        operation: security::network::Operation::Create,
    };
    if matches!(security::network::evaluate(security_context), security::network::Verdict::Deny) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    // Linux assigns the DGRAM transport during AF_VSOCK creation. Current
    // virtio-vsock has that transport only while a device endpoint is live;
    // without one, creation fails ENODEV rather than publishing a phantom fd.
    if spec.family == AF_VSOCK && spec.typ == SOCK_DGRAM && !net::vsock::driver_up() {
        return -(Errno::Enodev.as_i32() as i64);
    }
    let inode: vfs::InodeRef = if spec.family == AF_VSOCK {
        net::vsock_socket::make_vsock_socket_inode(Arc::new(
            net::vsock_socket::VsockSocket::new_type_in(spec.typ, net_namespace.clone())))
    } else if spec.family == AF_NETLINK {
        if !netlink_protocol_registered(spec.protocol) {
            return -(Errno::Eprotonosupport.as_i32() as i64);
        }
        let nl_proto = spec.protocol as u16;
        let sock = Arc::new(::netlink::NetlinkSocket::new(nl_proto, &net_namespace));
        // udev/systemd-udevd: a NETLINK_KOBJECT_UEVENT socket subscribes
        // to broadcast device uevents.
        if nl_proto == ::netlink::proto::NETLINK_KOBJECT_UEVENT {
            ::netlink::register_uevent_listener(&sock);
        }
        // NETLINK_ROUTE sockets receive rtnl multicast (RTM_NEW*/DEL*)
        // once subscribed via bind nl_groups / NETLINK_ADD_MEMBERSHIP.
        if nl_proto == ::netlink::proto::NETLINK_ROUTE {
            ::netlink::register_rtnl_listener(&sock);
        }
        ::netlink::make_netlink_socket_inode(sock)
    } else {
        let inet = match (spec.family, spec.typ) {
            (AF_INET,  SOCK_DGRAM)  => InetSocket::new_udp_in(net_namespace.clone()),
            (AF_INET,  SOCK_STREAM) => InetSocket::new_tcp_in(net_namespace.clone()),
            (AF_INET,  SOCK_RAW)    => InetSocket::new_raw4_in(spec.protocol as u8, net_namespace.clone()),
            (AF_INET6, SOCK_DGRAM)  => InetSocket::new_udp6_in(net_namespace.clone()),
            (AF_INET6, SOCK_STREAM) => InetSocket::new_tcp6_in(net_namespace.clone()),
            (AF_INET6, SOCK_RAW)    => InetSocket::new_raw6_in(spec.protocol as u8, net_namespace.clone()),
            (AF_UNIX, SOCK_STREAM) => InetSocket::new_unix_in(net_namespace.clone()),
            (AF_UNIX, SOCK_RAW) => inet_with_so_type(
                InetSocket::new_unix_dgram_in(net_namespace.clone()), SOCK_RAW),
            (AF_UNIX, SOCK_DGRAM) => InetSocket::new_unix_dgram_in(net_namespace.clone()),
            // systemd uses path-bound AF_UNIX SOCK_SEQPACKET control sockets.
            // The existing Unix listener path is byte-stream internally, but
            // accepting the type is enough for bind/listen/epoll readiness.
            (AF_UNIX, SOCK_SEQPACKET) => {
                // SOCK_SEQPACKET is byte-ring-backed internally, but it MUST
                // report SO_TYPE=SOCK_SEQPACKET: systemd-udevd's listen_fds()
                // does sd_is_socket(fd, AF_UNIX, SOCK_SEQPACKET) on its
                // inherited control socket and returns -EINVAL on mismatch.
                let s = InetSocket::new_unix_in(net_namespace.clone());
                s.opts.so_type.store(SOCK_SEQPACKET as u8, core::sync::atomic::Ordering::Release);
                s
            }
            (AF_PACKET, _) => {
                // F131: proto is htons(ETH_P_*); store host-order.
                let proto_be = (proto & 0xFFFF) as u16;
                InetSocket::new_packet_in(proto_be.swap_bytes(), spec.typ as u8,
                    net_namespace.clone())
            }
            (AF_INET, _) | (AF_INET6, _) | (AF_UNIX, _) => return -(Errno::Esocktnosupport.as_i32() as i64),
            _ => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        let inet = Arc::new(inet);
        if spec.family == AF_PACKET { net::sock::register_packet(&inet); }
        net::sock::make_inet_socket_inode(inet)
    };
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = vfs::dcache::d_alloc_pseudo("socket", Arc::clone(&inode), &crate::anon_dname::SOCKET_OPS);
    // F198: sockets are RW by spec — File::write needs O_RDWR.
    let mut fl = OpenFlags::O_RDWR;
    if spec.nonblock { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    if let Some(sock) = crate::net_common::inode_as_inet_socket(file.inode()) {
        net::bind_file(&file, &sock);
    }
    match crate::socket_fd::install(&fdt, file, cur.nofile_soft(), spec.cloexec) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

fn netlink_protocol_registered(protocol: u32) -> bool {
    let Ok(p) = u16::try_from(protocol) else { return false; };
    matches!(p,
        ::netlink::proto::NETLINK_ROUTE
        | ::netlink::proto::NETLINK_USERSOCK
        | ::netlink::proto::NETLINK_SOCK_DIAG
        | ::netlink::proto::NETLINK_AUDIT
        | ::netlink::proto::NETLINK_NETFILTER
        | ::netlink::proto::NETLINK_KOBJECT_UEVENT
        | ::netlink::proto::NETLINK_GENERIC
    )
}

fn inet_with_so_type(sock: InetSocket, typ: u32) -> InetSocket {
    sock.opts.so_type.store(typ as u8, core::sync::atomic::Ordering::Release);
    sock
}
