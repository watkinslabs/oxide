// 049 bind — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::{
    AF_INET, AF_INET6, errno_from_neterr, fd_file, socket_from_file, vsock_from_file,
};

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
            vfs::fire_dirent_create(&parent.inode, &name);
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
    vfs::fire_dirent_delete(&n.parent.inode, &n.name);
}

/// Linux privileged-port admission for explicit INET binds. # C: O(1)
fn privileged_inet_port_denied(sock: &net::sock::InetSocket, port: u16) -> bool {
    let net_ns = sock.net_ns();
    let Some(floor) = net::ephemeral::unprivileged_start_in(net_ns) else { return true; };
    if port == 0 || port >= floor { return false; }
    let transport = matches!(*sock.kind.lock(),
        net::sock::SockKind::Udp | net::sock::SockKind::TcpInit);
    if !transport { return false; }
    !sched::live::current()
        .is_some_and(|cur| nscg::has_net_bind_service_for(cur, &net_ns))
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
    if let Err(error) = move_sockaddr_to_kernel_shape(addr_p, addrlen) { return error; }
    if let Some(target) = crate::netlink_fd::from_file(file.clone()) {
        return crate::netlink_fd::bind(&target, addr_p, addrlen as usize);
    }
    // D3.3: AF_VSOCK bind — record the local CID/port; listen() registers
    // the owner-keyed listener in the table.
    if let Some(vs) = vsock_from_file(file.clone()) {
        if let Err(e) = require_sockaddr_vm(addrlen as usize) { return e; }
        let (family, port, cid) = match read_sockaddr_vm(addr_p) {
            Some(t) => t, None => return -(Errno::Efault.as_i32() as i64),
        };
        return match vs.bind(family, port, cid) {
            Ok(()) => 0,
            Err(e) => errno_from_neterr(e),
        };
    }
    let sock   = match socket_from_file(file) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"bind"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    let family = match read_sa_family(addr_p) {
        Some(f) => f, None => return -(Errno::Efault.as_i32() as i64),
    };
    let admission = match net::sock::admit_bind(&sock) {
        Ok(admission) => admission,
        Err(error) => return errno_from_neterr(error),
    };
    // Parse the user sockaddr into the typed BoundAddr enum.
    let mut unix_node: Option<UnixSockNode> = None;
    let addr = if family == net::sock::AF_UNIX {
        let path = match read_sockaddr_un_path_len(addr_p, addrlen) {
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
        let sock_fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
        if family != sock_fam { return -(Errno::Einval.as_i32() as i64); }
        let (_fam, ip, port) = match read_sockaddr_any(addr_p) {
            Some(t) => t, None => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        if privileged_inet_port_denied(&sock, port) {
            return -(Errno::Eacces.as_i32() as i64);
        }
        net::sock::BoundAddr::Inet { ip, port }
    } else if family == AF_INET6 as u16 {
        // F180a: AF_INET6 bind via v6 path with the 16-byte address.
        let sock_fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
        if family != sock_fam { return -(Errno::Einval.as_i32() as i64); }
        let (_fam, port, bytes, scope_id) = match read_sockaddr_in6(addr_p) {
            Some(t) => t, None => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        if privileged_inet_port_denied(&sock, port) {
            return -(Errno::Eacces.as_i32() as i64);
        }
        net::sock::BoundAddr::Inet6 { ip: net::Ipv6Addr(bytes), port, scope_id }
    } else if family == net::sock::AF_PACKET {
        // F131: sockaddr_ll = u16 family + u16 proto_be + i32 ifindex + tail.
        // SAFETY: addr_p validated < USER_VA_END above; sockaddr_ll spans +0..+20.
        let (proto_be, ifindex) = unsafe {
            let p = core::ptr::read_volatile((addr_p + 2) as *const u16);
            let i = core::ptr::read_volatile((addr_p + 4) as *const i32);
            (p, i)
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
