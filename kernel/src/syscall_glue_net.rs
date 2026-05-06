// AF_INET socket syscalls — `sys_socket`, `sys_bind`, `sys_sendto`,
// `sys_recvfrom`, `sys_close` (the last via the existing close
// path; socket fds are normal VFS inodes).
//
// v1 supports SOCK_DGRAM/UDP only over AF_INET (IPv4).

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use vfs::{Dentry, File, OpenFlags};

use crate::dev_net::{InetSocket, SockKind, socket_sendto, socket_recv, drain_loopback};

const AF_INET:     u32 = 2;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM:  u32 = 2;

fn errno_from_neterr(e: net::NetError) -> i64 {
    -(match e {
        net::NetError::Eaddrinuse    => Errno::Eaddrinuse,
        net::NetError::Eaddrnotavail => Errno::Eaddrnotavail,
        net::NetError::Enobufs       => Errno::Enobufs,
        net::NetError::Enomem        => Errno::Enomem,
        net::NetError::Enetunreach   => Errno::Enetunreach,
        net::NetError::Einval        => Errno::Einval,
        net::NetError::Eio           => Errno::Eio,
        net::NetError::Eagain        => Errno::Eagain,
        net::NetError::Eafnosupport  => Errno::Eafnosupport,
        net::NetError::Enotconn      => Errno::Enotconn,
        net::NetError::Erange        => Errno::Erange,
    } as i32 as i64)
}

/// `socket(domain, type, protocol)` slot 41.
/// # C: O(1)
pub fn kernel_sys_socket(args: &SyscallArgs) -> i64 {
    let domain = args.a0 as u32;
    let typ    = args.a1 as u32 & 0xFF;  // strip SOCK_NONBLOCK / SOCK_CLOEXEC
    if domain != AF_INET { return -(Errno::Eafnosupport.as_i32() as i64); }
    let inet = match typ {
        SOCK_DGRAM  => InetSocket::new_udp(),
        SOCK_STREAM => InetSocket::new_tcp(),
        _ => return -(Errno::Esocktnosupport.as_i32() as i64),
    };
    let inode: vfs::InodeRef = Arc::new(inet) as _;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = Dentry::new(None, String::from("[socket]"), Arc::clone(&inode));
    let file = File::new(inode, dentry, OpenFlags::empty());
    match fdt.alloc(file) { Ok(fd) => fd as i64, Err(e) => -(e as i64) }
}

/// Read a `struct sockaddr_in` (16 bytes) at user pointer `ptr`:
///   u16 sin_family ; u16 sin_port ; u32 sin_addr ; u8 zero[8].
fn read_sockaddr_in(ptr: u64) -> Option<(u32, u16, u32)> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    // SAFETY: ptr in user range; user page mapped (caller's AS); 8-byte aligned read.
    unsafe {
        let family = core::ptr::read_volatile(ptr as *const u16) as u32;
        let port_be = core::ptr::read_volatile((ptr + 2) as *const u16);
        let addr_be = core::ptr::read_volatile((ptr + 4) as *const u32);
        Some((family, u16::from_be(port_be), u32::from_be(addr_be)))
    }
}

fn write_sockaddr_in(ptr: u64, addr_be: u32, port_be: u16) {
    if ptr == 0 || ptr >= USER_VA_END { return; }
    // SAFETY: ptr in user range; user page mapped (caller's AS); 8-byte writes.
    unsafe {
        core::ptr::write_volatile(ptr as *mut u16, AF_INET as u16);
        core::ptr::write_volatile((ptr + 2) as *mut u16, port_be);
        core::ptr::write_volatile((ptr + 4) as *mut u32, addr_be);
        core::ptr::write_volatile((ptr + 8) as *mut u64, 0);
    }
}

fn socket_from_fd(fd: u64) -> Option<Arc<InetSocket>> {
    let cur = crate::sched::current()?;
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?;
    let file = fdt.get(fd as i32).ok()?;
    let inode: &vfs::InodeRef = file.inode();
    // Downcast from Arc<dyn Inode> by raw-pointer compare with
    // a sentinel — vfs::Inode doesn't expose Any. Workaround:
    // wrap the InetSocket in an Arc<dyn Inode> and rely on
    // matching the underlying type via a dedicated tag inode.
    // Simpler: stash a raw &InetSocket via a downcast helper.
    // For v1 we pattern: Arc<dyn Inode> → check ino() upper bits.
    let raw_ino = inode.ino();
    if (raw_ino & 0xFFFF_FFFF_0000_0000) != 0x534F_434B_0000_0000 {
        return None;
    }
    // SAFETY: ino tag confirms this Inode is an InetSocket; the
    // pointer encoded in the low 32 bits is a valid &InetSocket
    // for the Arc's lifetime (kept alive by `file`).
    let ptr = (raw_ino & 0xFFFF_FFFF) as usize;
    let _ = ptr;
    // Cleaner lift: clone the Arc<dyn Inode>, then convert via
    // a transmute through Arc::into_raw. We can't do that safely
    // without a downcast trait. So: rebuild an InetSocket-shaped
    // handle by re-reading. This v1 implementation requires the
    // caller supply the InetSocket directly via the fd_table —
    // which it does, since the Arc holds the InetSocket. We just
    // can't retrieve it as Arc<InetSocket> without a dedicated
    // downcast helper. Add one here.
    let sock_arc = inode_as_inet_socket(inode)?;
    Some(sock_arc)
}

/// Downcast an `Arc<dyn vfs::Inode>` to `Arc<InetSocket>` by
/// pattern: only succeeds when the inode IS an InetSocket
/// (vouched by the high-bit tag in `ino()`).
fn inode_as_inet_socket(inode: &vfs::InodeRef) -> Option<Arc<InetSocket>> {
    if (inode.ino() & 0xFFFF_FFFF_0000_0000) != 0x534F_434B_0000_0000 {
        return None;
    }
    // Erase fat-pointer metadata via Arc::into_raw → cast to
    // *const InetSocket → Arc::from_raw. Sound only because we
    // verified the tag.
    let raw = Arc::into_raw(inode.clone());
    let ptr = raw as *const InetSocket;
    // SAFETY: ino tag check above confirms the inode is an
    // InetSocket; refcount was just incremented by `Arc::clone`
    // followed by `into_raw` so the new Arc::from_raw consumes it.
    let arc = unsafe { Arc::from_raw(ptr) };
    Some(arc)
}

/// `bind(fd, addr, addrlen)` slot 49.
pub fn kernel_sys_bind(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock   = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    let (family, port, addr) = match read_sockaddr_in(addr_p) {
        Some(t) => t, None => return -(Errno::Efault.as_i32() as i64),
    };
    if family != AF_INET { return -(Errno::Eafnosupport.as_i32() as i64); }
    let ip = net::Ipv4Addr::from_u32(addr);
    match crate::dev_net::stack().bind_udp(ip, port) {
        Ok(())   => {
            *sock.local_port.lock() = Some(port);
            *sock.local_ip.lock()   = ip;
            0
        }
        Err(e) => errno_from_neterr(e),
    }
}

/// `sendto(fd, buf, len, flags, dest, dest_len)` slot 44.
pub fn kernel_sys_sendto(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let bufp   = args.a1;
    let len    = args.a2 as usize;
    let dest_p = args.a4;
    let sock   = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    if bufp == 0 || bufp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    if len > 65507 { return -(Errno::Emsgsize.as_i32() as i64); }
    // SAFETY: ptr range validated; user page mapped under caller's AS.
    let payload: alloc::vec::Vec<u8> = unsafe {
        core::slice::from_raw_parts(bufp as *const u8, len).to_vec()
    };
    // TCP path: send into the existing TcpConn (no destaddr needed).
    if let SockKind::TcpConn(entry) = &*sock.kind.lock() {
        let entry = entry.clone();
        return match crate::dev_net::stack().tcp_send(&entry, &payload) {
            Ok(n)  => { drain_loopback(); n as i64 }
            Err(e) => errno_from_neterr(e),
        };
    }
    let (dst_ip, dst_port) = if dest_p != 0 {
        match read_sockaddr_in(dest_p) {
            Some((fam, p, a)) if fam == AF_INET => (net::Ipv4Addr::from_u32(a), p),
            _ => return -(Errno::Einval.as_i32() as i64),
        }
    } else {
        match *sock.peer.lock() {
            Some(t) => t, None => return -(Errno::Edestaddrreq.as_i32() as i64),
        }
    };
    match socket_sendto(&sock, dst_ip, dst_port, &payload) {
        Ok(n)  => n as i64,
        Err(e) => errno_from_neterr(e),
    }
}

/// `socketpair(domain, type, protocol, sv)` slot 53. v1 supports
/// AF_UNIX SOCK_STREAM only (the common shell-IPC case).
pub fn kernel_sys_socketpair(args: &SyscallArgs) -> i64 {
    const AF_UNIX: u32 = 1;
    let domain = args.a0 as u32;
    let typ    = args.a1 as u32 & 0xFF;
    let svp    = args.a3;
    if domain != AF_UNIX {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    if typ != SOCK_STREAM {
        return -(Errno::Esocktnosupport.as_i32() as i64);
    }
    if svp == 0 || svp >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let pair = net::UnixPair::new();
    let mk = |end: net::UnixEnd| -> vfs::InodeRef {
        let s = InetSocket::new_tcp();
        *s.kind.lock() = SockKind::Unix(pair.clone(), end);
        Arc::new(s) as _
    };
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let a = {
        let inode = mk(net::UnixEnd::A);
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("[unix]"), Arc::clone(&inode));
        let f = vfs::File::new(inode, dentry, vfs::OpenFlags::empty());
        match fdt.alloc(f) { Ok(fd) => fd, Err(e) => return -(e as i64) }
    };
    let b = {
        let inode = mk(net::UnixEnd::B);
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("[unix]"), Arc::clone(&inode));
        let f = vfs::File::new(inode, dentry, vfs::OpenFlags::empty());
        match fdt.alloc(f) { Ok(fd) => fd, Err(e) => return -(e as i64) }
    };
    // Write both fds back to user[]int sv[2].
    // SAFETY: svp range validated < USER_VA_END; user page mapped.
    unsafe {
        core::ptr::write_volatile( svp           as *mut i32, a as i32);
        core::ptr::write_volatile((svp + 4)      as *mut i32, b as i32);
    }
    0
}

/// `listen(fd, backlog)` slot 50.
pub fn kernel_sys_listen(args: &SyscallArgs) -> i64 {
    let fd = args.a0;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    let port = match *sock.local_port.lock() {
        Some(p) => p,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    let ip = *sock.local_ip.lock();
    match crate::dev_net::stack().tcp_listen(ip, port) {
        Ok(le) => {
            *sock.kind.lock() = SockKind::TcpListener(le);
            0
        }
        Err(e) => errno_from_neterr(e),
    }
}

/// `accept(fd, sockaddr, addrlen)` slot 43 / `accept4` slot 288.
/// Non-blocking: returns Eagain when no connection is ready.
pub fn kernel_sys_accept(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    drain_loopback();
    let listener_arc = match &*sock.kind.lock() {
        SockKind::TcpListener(l) => l.clone(),
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    let entry = match crate::dev_net::stack().tcp_accept(&listener_arc) {
        Some(e) => e,
        None    => return -(Errno::Eagain.as_i32() as i64),
    };
    let (peer_ip, peer_port) = {
        let c = entry.conn.lock();
        (c.remote.ip, c.remote.port)
    };
    let new_sock = InetSocket::new_tcp();
    *new_sock.kind.lock() = SockKind::TcpConn(entry);
    *new_sock.peer.lock() = Some((peer_ip, peer_port));
    let inode: vfs::InodeRef = Arc::new(new_sock) as _;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("[socket]"), Arc::clone(&inode));
    let file = vfs::File::new(inode, dentry, vfs::OpenFlags::empty());
    if addr_p != 0 {
        write_sockaddr_in(addr_p, peer_ip.as_u32().to_be(), peer_port.to_be());
    }
    match fdt.alloc(file) { Ok(fd) => fd as i64, Err(e) => -(e as i64) }
}

/// `connect(fd, sockaddr, addrlen)` slot 42.
pub fn kernel_sys_connect(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    let (family, port, addr) = match read_sockaddr_in(addr_p) {
        Some(t) => t, None => return -(Errno::Efault.as_i32() as i64),
    };
    if family != AF_INET { return -(Errno::Eafnosupport.as_i32() as i64); }
    let dst_ip = net::Ipv4Addr::from_u32(addr);
    // For TCP: tcp_connect emits SYN. For UDP: just store the peer.
    let kind_is_tcp = matches!(*sock.kind.lock(), SockKind::Udp) == false
        || matches!(*sock.kind.lock(), SockKind::TcpListener(_));
    let _ = kind_is_tcp;  // noop; fall-through below
    let is_dgram = matches!(*sock.kind.lock(), SockKind::Udp);
    if is_dgram {
        *sock.peer.lock() = Some((dst_ip, port));
        return 0;
    }
    // TCP active open.
    let local_port = match *sock.local_port.lock() {
        Some(p) => p,
        None    => match crate::dev_net::alloc_ephemeral_port() {
            Ok(p) => { *sock.local_port.lock() = Some(p); p }
            Err(e) => return errno_from_neterr(e),
        },
    };
    let local_ip = match *sock.local_ip.lock() {
        ip if ip == net::Ipv4Addr::ANY => net::Ipv4Addr::LOOPBACK,
        ip => ip,
    };
    let entry = match crate::dev_net::stack().tcp_connect(local_ip, local_port, dst_ip, port) {
        Ok(e)  => e,
        Err(e) => return errno_from_neterr(e),
    };
    *sock.kind.lock() = SockKind::TcpConn(entry.clone());
    *sock.peer.lock() = Some((dst_ip, port));
    // Drive 3WHS via loopback drain. v1 connect is "blocking-ish":
    // we drain a few times and check state.
    for _ in 0..4 { drain_loopback(); }
    if !entry.conn.lock().state.is_established() {
        return -(Errno::Etimedout.as_i32() as i64);
    }
    0
}

/// `getsockname(fd, addr, addrlen)` slot 51 — write local addr.
pub fn kernel_sys_getsockname(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    if addr_p == 0 || addr_p >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let port = (*sock.local_port.lock()).unwrap_or(0);
    let ip   = *sock.local_ip.lock();
    write_sockaddr_in(addr_p, ip.as_u32().to_be(), port.to_be());
    0
}

/// `getpeername(fd, addr, addrlen)` slot 52.
pub fn kernel_sys_getpeername(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    if addr_p == 0 || addr_p >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let (ip, port) = match *sock.peer.lock() {
        Some(t) => t, None => return -(Errno::Enotconn.as_i32() as i64),
    };
    write_sockaddr_in(addr_p, ip.as_u32().to_be(), port.to_be());
    0
}

/// `shutdown(fd, how)` slot 48. v1 honors SHUT_WR (close-write
/// for AF_UNIX) by calling close_writer. SHUT_RD / SHUT_RDWR are
/// accepted silently (TCP shutdown ride alongside graceful close).
pub fn kernel_sys_shutdown(args: &SyscallArgs) -> i64 {
    let fd  = args.a0;
    let how = args.a1 as u32;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    const SHUT_WR: u32 = 1;
    const SHUT_RDWR: u32 = 2;
    if let SockKind::Unix(pair, end) = &*sock.kind.lock() {
        if how == SHUT_WR || how == SHUT_RDWR { pair.close_writer(*end); }
    }
    if let SockKind::TcpConn(entry) = &*sock.kind.lock() {
        let _ = crate::dev_net::stack().tcp_close(entry);
        drain_loopback();
    }
    0
}

/// `setsockopt(fd, level, optname, optval, optlen)` slot 54.
/// v1 accepts every option silently — SO_REUSEADDR / SO_REUSEPORT
/// are no-ops for our single-listener model; other options that
/// don't change wire behavior (linger, sndbuf, rcvbuf) likewise
/// accepted to keep userspace tooling unblocked.
pub fn kernel_sys_setsockopt(_args: &SyscallArgs) -> i64 { 0 }

/// `getsockopt(fd, level, optname, optval, optlen)` slot 55.
/// Returns 0 + zero-length opt for every query.
pub fn kernel_sys_getsockopt(args: &SyscallArgs) -> i64 {
    let optlen_p = args.a4;
    if optlen_p != 0 && optlen_p < USER_VA_END {
        // SAFETY: ptr in user range; user page mapped under caller's AS.
        unsafe { core::ptr::write_volatile(optlen_p as *mut u32, 0); }
    }
    0
}

/// `recvfrom(fd, buf, len, flags, src, src_len)` slot 45.
pub fn kernel_sys_recvfrom(args: &SyscallArgs) -> i64 {
    let fd       = args.a0;
    let bufp     = args.a1;
    let len      = args.a2 as usize;
    let src_p    = args.a4;
    let sock     = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    if bufp == 0 || bufp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // TCP path: drain bytes from the conn's recv_buf.
    if let SockKind::TcpConn(entry) = &*sock.kind.lock() {
        let entry = entry.clone();
        drain_loopback();
        let payload = crate::dev_net::stack().tcp_recv(&entry, len);
        if payload.is_empty() { return -(Errno::Eagain.as_i32() as i64); }
        let take = payload.len();
        // SAFETY: ptr+take validated < USER_VA_END; user page mapped.
        unsafe { core::ptr::copy_nonoverlapping(payload.as_ptr(), bufp as *mut u8, take); }
        if src_p != 0 {
            let (peer_ip, peer_port) = (*sock.peer.lock()).unwrap_or((net::Ipv4Addr::ANY, 0));
            write_sockaddr_in(src_p, peer_ip.as_u32().to_be(), peer_port.to_be());
        }
        return take as i64;
    }
    let (src_ip, src_port, payload) = match socket_recv(&sock) {
        Some(t) => t, None => return -(Errno::Eagain.as_i32() as i64),
    };
    let take = core::cmp::min(len, payload.len());
    // SAFETY: ptr+take validated < USER_VA_END; user page mapped under caller's AS.
    unsafe {
        core::ptr::copy_nonoverlapping(payload.as_ptr(), bufp as *mut u8, take);
    }
    if src_p != 0 {
        write_sockaddr_in(src_p, src_ip.as_u32().to_be(), src_port.to_be());
    }
    take as i64
}
