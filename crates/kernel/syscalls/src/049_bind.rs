// 049 bind — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::{
    AF_INET, AF_INET6, fd_file, socket_from_file, vsock_from_file,
};
use crate::net_errno::errno_from_neterr;

struct UnixSockNode {
    parent: vfs::VfsPath,
    name: alloc::string::String,
    addr: net::UnixAddr,
}

fn create_unix_sock_node_bytes(path: &[u8]) -> Result<Option<UnixSockNode>, i64> {
    if net::unix_path_is_abstract(path) { return Ok(None); }
    let decoded = vfs::path_from_bytes(path);
    let (parent, name) = crate::namei_common::resolve_create_parent_at(crate::pathresolve::AT_FDCWD, &decoded)?;
    if crate::namei_common::parent_mount_readonly(&parent) {
        return Err(-(Errno::Erofs.as_i32() as i64));
    }
    let cred = crate::pathresolve::current_cred();
    let ctx = vfs::CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0 };
    let r = {
        let _g = parent.inode.inode_lock();
        parent.inode.mknod_child(&name, vfs::S_IFSOCK as u16, 0, &ctx)
    };
    match r {
        Ok(()) => {
            let inode = match parent.inode.lookup(&name) {
                Ok(i) => i,
                Err(e) => return Err(crate::namei_common::errno_from_vfs(e)),
            };
            let addr = net::UnixAddr::from_inode_bytes(path.to_vec(), &inode);
            vfs::file::iput(inode);
            crate::namei_common::drop_child_cache(&parent, &name);
            vfs::fire_dirent_create(&parent.inode, &name, false);
            Ok(Some(UnixSockNode { parent, name, addr }))
        }
        Err(vfs::VfsError::Eexist) => Err(-(Errno::Eaddrinuse.as_i32() as i64)),
        Err(e) => Err(crate::namei_common::errno_from_vfs(e)),
    }
}

fn remove_unix_sock_node(n: &UnixSockNode) {
    let _ = {
        let _g = n.parent.inode.inode_lock();
        n.parent.inode.unlink_child(&n.name)
    };
    crate::namei_common::drop_child_cache(&n.parent, &n.name);
    vfs::fire_dirent_delete(&n.parent.inode, &n.name, false);
}

fn copy_sockaddr(addr_p: u64, len: usize) -> Result<net::SockaddrStorage, i64> {
    let mut bytes = [0u8; net::sockaddr::SOCKADDR_STORAGE_LEN];
    if uaccess::copy_from_user(&mut bytes[..len], addr_p).is_err() {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    net::SockaddrStorage::from_bytes(&bytes[..len])
        .ok_or(-(Errno::Einval.as_i32() as i64))
}

fn run_bind_hook(sock: &net::sock::InetSocket, storage: &mut net::SockaddrStorage,
                 op: net::cgroup_bpf::SockAddrOp) -> Result<bool, i64> {
    let fields = match op {
        net::cgroup_bpf::SockAddrOp::Bind4 => storage.bpf_fields_v4(),
        net::cgroup_bpf::SockAddrOp::Bind6 => storage.bpf_fields_v6(),
        _ => None,
    };
    let Some((user_ip4, user_ip6, user_port)) = fields
        else { return Err(-(Errno::Einval.as_i32() as i64)); };
    let mut context = net::cgroup_bpf::SockAddr {
        user_family: storage.family().unwrap_or_default() as u32,
        user_ip4, user_ip6, user_port,
    };
    let verdict = net::cgroup_bpf::run_sock_addr(sock, op, &mut context)
        .map_err(|error| -(error as i64))?;
    match op {
        net::cgroup_bpf::SockAddrOp::Bind4 =>
            storage.apply_bpf_fields_v4(context.user_ip4, context.user_port),
        net::cgroup_bpf::SockAddrOp::Bind6 =>
            storage.apply_bpf_fields_v6(context.user_ip6, context.user_port),
        _ => {}
    }
    Ok(verdict)
}

/// Linux privileged-port admission for explicit INET binds. # C: O(1)
fn privileged_inet_port_denied(sock: &net::sock::InetSocket, port: u16) -> bool {
    let net_ns = &sock.net_namespace;
    let Some(floor) = net::ephemeral::unprivileged_start_in(net_ns.id().as_u64()) else { return true; };
    if port == 0 || port >= floor { return false; }
    let transport = matches!(*sock.kind.lock(),
        net::sock::SockKind::Udp | net::sock::SockKind::TcpInit);
    if !transport { return false; }
    !sched::live::current()
        .is_some_and(|cur| nscg::has_net_bind_service_for(cur, net_ns))
}

/// `bind(fd, addr, addrlen)` slot 49.
/// # C: O(1)
pub fn sys_bind(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let addrlen = args.a2;
    let file = match fd_file(fd) {
        Some(file) => file,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    enum Target {
        Netlink(crate::netlink_fd::NetlinkFileRef),
        Vsock(crate::net_common::VsockFileRef),
        Inet(crate::net_common::SocketFileRef),
    }
    let target = if let Some(target) = crate::netlink_fd::from_file(file.clone()) {
        Target::Netlink(target)
    } else if let Some(target) = vsock_from_file(file.clone()) {
        Target::Vsock(target)
    } else if let Some(target) = socket_from_file(file) {
        Target::Inet(target)
    } else {
        trace_enotsock_at(fd, b"bind");
        return -(Errno::Enotsock.as_i32() as i64);
    };
    let copied_len = match move_sockaddr_to_kernel_shape(addr_p, addrlen) {
        Ok(n) => n,
        Err(error) => return error,
    };
    let mut storage = match copy_sockaddr(addr_p, copied_len) {
        Ok(storage) => storage,
        Err(error) => return error,
    };
    // The generic bind security decision, above the family branch and above
    // every address-shape screen: the hook reads the socket's namespace and
    // family, never the address, so a malformed `sockaddr` must not outrank a
    // denial. One token, whatever the family answers with.
    let (namespace, sock_family) = match &target {
        Target::Netlink(target) => (net::net_ns::namespace_id(&target.socket().net_ns),
            net::socket_args::AF_NETLINK_WIRE),
        Target::Vsock(vs) => (vs.net_ns(), net::socket_args::AF_VSOCK as u16),
        Target::Inet(sock) => (sock.net_ns(),
            sock.family.load(core::sync::atomic::Ordering::Acquire)),
    };
    let admission = match net::sock_admit::admit_bind_in(namespace, sock_family) {
        Ok(admission) => admission,
        Err(error) => return errno_from_neterr(error),
    };
    if let Target::Netlink(target) = &target {
        return crate::netlink_fd::bind(target, &storage, admission);
    }
    // D3.3: AF_VSOCK bind — record the local CID/port; listen() registers
    // the owner-keyed listener in the table.
    if let Target::Vsock(vs) = &target {
        if let Err(e) = require_sockaddr_vm(copied_len) { return e; }
        let (family, port, cid) = match storage.vsock() {
            Some(t) => t, None => return -(Errno::Einval.as_i32() as i64),
        };
        return match vs.bind(family, port, cid, admission) {
            Ok(()) => 0,
            Err(e) => errno_from_neterr(e),
        };
    }
    let sock = match &target {
        Target::Inet(sock) => sock,
        _ => unreachable!(),
    };
    let sock_fam = sock_family;
    if sock_fam == AF_INET as u16 {
        if let Err(error) = require_sockaddr_in(copied_len) { return error; }
    } else if sock_fam == AF_INET6 as u16 {
        if let Err(error) = require_sockaddr_in6(copied_len) { return error; }
    } else if copied_len < core::mem::size_of::<u16>() {
        return -(Errno::Einval.as_i32() as i64);
    }
    let family = match storage.family() {
        Some(family) => family,
        None => return -(Errno::Einval.as_i32() as i64),
    };
    let hook = net::cgroup_bpf::bind_op(sock_fam, family);
    if hook == Some(net::cgroup_bpf::SockAddrOp::Bind4) {
        if let Err(error) = require_sockaddr_in(copied_len) { return error; }
    } else if hook == Some(net::cgroup_bpf::SockAddrOp::Bind6) {
        if let Err(error) = require_sockaddr_in6(copied_len) { return error; }
    }
    let bypass_cap = if let Some(op) = hook {
        match run_bind_hook(&sock, &mut storage, op) {
            Ok(value) => value,
            Err(error) => return error,
        }
    } else {
        false
    };
    if sock_fam == AF_INET as u16
        && family != AF_INET as u16 && family != net::socket_args::AF_UNSPEC as u16
    {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if sock_fam == AF_INET6 as u16 && family != AF_INET6 as u16 {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    // Port rules for the local endpoint, after the family checks so a
    // malformed address reports its own error rather than a denial.
    if let Err(rv) = crate::landlock::check_socket(
        crate::landlock::sock_proto(&sock), ::landlock::netcheck::Op::Bind, storage.as_bytes(), sock_fam)
    { return rv; }
    // Parse the user sockaddr into the typed BoundAddr enum.
    let mut unix_node: Option<UnixSockNode> = None;
    let addr = if family == net::sock::AF_UNIX {
        if let Err(error) = net::sockaddr::validate_unix_addr(family, copied_len) {
            return -(error.as_i32() as i64);
        }
        let path = match storage.unix_path() {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        // If the socket is already SOCK_DGRAM, pass its queue along.
        let node = match create_unix_sock_node_bytes(&path) {
            Ok(n) => n,
            Err(rv) => return rv,
        };
        let addr = node.as_ref()
            .map(|n| n.addr.clone())
            .unwrap_or_else(|| net::UnixAddr::from_sockaddr_path(path.clone()));
        unix_node = node;
        match &*sock.kind.lock() {
            net::sock::SockKind::UnixDgram(q) =>
                net::sock::BoundAddr::UnixDgram { addr, queue: q.clone() },
            _ => net::sock::BoundAddr::UnixListener(addr),
        }
    } else if family == AF_INET as u16 {
        // Linux `__inet_bind`: the sockaddr_in minimum-length check precedes
        // the family comparison, and a sufficient-length family mismatch is
        // EAFNOSUPPORT (not EINVAL).
        if let Err(e) = require_sockaddr_in(copied_len) { return e; }
        if family != sock_fam { return -(Errno::Eafnosupport.as_i32() as i64); }
        let (ip, port) = match storage.inet4() {
            Some(value) => value, None => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        if !bypass_cap && privileged_inet_port_denied(&sock, port) {
            return -(Errno::Eacces.as_i32() as i64);
        }
        net::sock::BoundAddr::Inet { ip, port }
    } else if family == AF_INET6 as u16 {
        // F180a: AF_INET6 bind via v6 path with the 16-byte address. Linux
        // `inet6_bind` requires SIN6_LEN_RFC2133 (24) before the family check,
        // and a sufficient-length mismatch is EAFNOSUPPORT.
        if let Err(e) = require_sockaddr_in6(copied_len) { return e; }
        if family != sock_fam { return -(Errno::Eafnosupport.as_i32() as i64); }
        let (ip, port, scope_id) = match storage.inet6() {
            Some(value) => value, None => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        if !bypass_cap && privileged_inet_port_denied(&sock, port) {
            return -(Errno::Eacces.as_i32() as i64);
        }
        net::sock::BoundAddr::Inet6 { ip, port, scope_id }
    } else if family == net::socket_args::AF_UNSPEC as u16 {
        // Linux `__inet_bind` compatibility: AF_UNSPEC is accepted as an
        // AF_INET bind only for a v4 socket whose address is INADDR_ANY; a v6
        // socket (`inet6_bind`) has no such exception.
        if let Err(e) = require_sockaddr_in(copied_len) { return e; }
        if sock_fam != AF_INET as u16 { return -(Errno::Eafnosupport.as_i32() as i64); }
        let (ip, port) = match storage.inet4() {
            Some(value) => value, None => return -(Errno::Efault.as_i32() as i64),
        };
        if ip != net::Ipv4Addr::ANY {
            return -(Errno::Eafnosupport.as_i32() as i64);
        }
        if !bypass_cap && privileged_inet_port_denied(&sock, port) {
            return -(Errno::Eacces.as_i32() as i64);
        }
        net::sock::BoundAddr::Inet { ip: net::Ipv4Addr::ANY, port }
    } else if family == net::sock::AF_PACKET {
        // F131: sockaddr_ll = u16 family + u16 proto_be + i32 ifindex + tail.
        // SAFETY: addr_p validated < USER_VA_END above; sockaddr_ll spans +0..+20.
        let (proto_be, ifindex) = match storage.packet() {
            Some(value) => value, None => return -(Errno::Einval.as_i32() as i64),
        };
        if ifindex < 0 { return -(Errno::Enodev.as_i32() as i64); }
        if ifindex != 0 {
            let net_ns = sock.net_ns();
            let iface = net::NetIfaceId::from_raw(ifindex as u32);
            if net::sock::stack().ifaces.lookup_in_ns(iface, net_ns).is_none() {
                return -(Errno::Enodev.as_i32() as i64);
            }
        }
        return match sock.bind_packet_admitted(ifindex as u32, proto_be.swap_bytes(), admission) {
            Ok(()) => 0,
            Err(error) => errno_from_neterr(error),
        };
    } else {
        return -(Errno::Eafnosupport.as_i32() as i64);
    };
    let rv = match net::sock::bind_admitted(&sock, addr, admission) {
        Ok(()) => 0, Err(e) => errno_from_neterr(e),
    };
    if rv != 0 {
        if let Some(n) = unix_node.as_ref() { remove_unix_sock_node(n); }
    }
    rv
}
