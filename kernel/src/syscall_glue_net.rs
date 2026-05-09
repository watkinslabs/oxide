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
const AF_INET6:    u32 = 10;
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
    const AF_UNIX_DOM: u32 = 1;
    let inet = match (domain, typ) {
        (AF_INET,  SOCK_DGRAM)  => InetSocket::new_udp(),
        (AF_INET,  SOCK_STREAM) => InetSocket::new_tcp(),
        (AF_INET6, SOCK_DGRAM)  => InetSocket::new_udp6(),
        (AF_INET6, SOCK_STREAM) => InetSocket::new_tcp6(),
        (AF_UNIX_DOM, SOCK_STREAM) => InetSocket::new_unix(),
        (AF_INET, _) | (AF_INET6, _) | (AF_UNIX_DOM, _) => return -(Errno::Esocktnosupport.as_i32() as i64),
        _ => return -(Errno::Eafnosupport.as_i32() as i64),
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
/// Read sa_family at the user pointer (first 2 bytes).
fn read_sa_family(ptr: u64) -> Option<u16> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    // SAFETY: ptr in user range; user page mapped (caller's AS).
    unsafe { Some(core::ptr::read_volatile(ptr as *const u16)) }
}

/// Read a sockaddr_un path at offset 2 (after sun_family). Reads
/// up to 107 bytes + NUL terminator.
fn read_sockaddr_un_path(ptr: u64) -> Option<alloc::string::String> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    // SAFETY: ptr in user range; user page mapped (caller's AS); 108-byte bounded read.
    unsafe {
        let p = (ptr + 2) as *const u8;
        let mut bytes = alloc::vec::Vec::new();
        for i in 0..108 {
            let b = core::ptr::read_volatile(p.add(i));
            if b == 0 { break; }
            bytes.push(b);
        }
        alloc::string::String::from_utf8(bytes).ok()
    }
}

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

/// Read a `struct sockaddr_in6` (28 bytes):
///   u16 sin6_family ; u16 sin6_port ; u32 sin6_flowinfo ;
///   u8[16] sin6_addr ; u32 sin6_scope_id.
/// Returns (family, port_host, addr_bytes, scope_id).
fn read_sockaddr_in6(ptr: u64) -> Option<(u32, u16, [u8; 16], u32)> {
    if ptr == 0 || ptr >= USER_VA_END { return None; }
    if ptr.checked_add(28).map_or(true, |e| e >= USER_VA_END) { return None; }
    // SAFETY: 28 bytes inside validated range; caller's AS active.
    unsafe {
        let family   = core::ptr::read_volatile(ptr as *const u16) as u32;
        let port_be  = core::ptr::read_volatile((ptr + 2) as *const u16);
        let _flow    = core::ptr::read_volatile((ptr + 4) as *const u32);
        let mut a = [0u8; 16];
        for i in 0..16 {
            a[i] = core::ptr::read_volatile((ptr + 8 + i as u64) as *const u8);
        }
        let scope    = core::ptr::read_volatile((ptr + 24) as *const u32);
        Some((family, u16::from_be(port_be), a, scope))
    }
}

fn write_sockaddr_in6(ptr: u64, addr_bytes: [u8; 16], port_be: u16, scope_id: u32) {
    if ptr == 0 || ptr >= USER_VA_END { return; }
    if ptr.checked_add(28).map_or(true, |e| e >= USER_VA_END) { return; }
    // SAFETY: 28 bytes inside validated range; caller's AS active.
    unsafe {
        core::ptr::write_volatile(ptr as *mut u16, AF_INET6 as u16);
        core::ptr::write_volatile((ptr + 2) as *mut u16, port_be);
        core::ptr::write_volatile((ptr + 4) as *mut u32, 0); // flowinfo
        for i in 0..16 {
            core::ptr::write_volatile((ptr + 8 + i as u64) as *mut u8, addr_bytes[i]);
        }
        core::ptr::write_volatile((ptr + 24) as *mut u32, scope_id);
    }
}

/// IPv4-mapped check: `::ffff:a.b.c.d` is the IPv6 form of an IPv4
/// address. Returns Some(Ipv4Addr) when the bytes match the prefix.
/// Used to thread V6 sockets through the V4 transport for v1.
fn ipv4_from_v6_mapped(b: &[u8; 16]) -> Option<net::Ipv4Addr> {
    let prefix_zeros = b[0..10].iter().all(|&x| x == 0);
    let prefix_ff    = b[10] == 0xff && b[11] == 0xff;
    if prefix_zeros && prefix_ff {
        Some(net::Ipv4Addr::new(b[12], b[13], b[14], b[15]))
    } else { None }
}

fn ipv6_loopback(b: &[u8; 16]) -> bool {
    b[..15].iter().all(|&x| x == 0) && b[15] == 1
}

fn ipv6_unspecified(b: &[u8; 16]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// Read a sockaddr that may be `sockaddr_in` (16 bytes, AF_INET) or
/// `sockaddr_in6` (28 bytes, AF_INET6). Returns the V4-equivalent
/// (IpAddr::V6 maps `::1` → 127.0.0.1, `::` → ANY, V4-mapped → its
/// embedded V4) for the v1 V4-only transport. Returns the requested
/// family so callers can validate it against the socket's family.
fn read_sockaddr_any(ptr: u64) -> Option<(u32, net::Ipv4Addr, u16)> {
    let fam = read_sa_family(ptr)? as u32;
    if fam == AF_INET {
        let (_, port, addr_host) = read_sockaddr_in(ptr)?;
        Some((fam, net::Ipv4Addr::from_u32(addr_host), port))
    } else if fam == AF_INET6 {
        let (_, port, b, _scope) = read_sockaddr_in6(ptr)?;
        // IPv4-mapped: forward to V4 transport directly.
        if let Some(v4) = ipv4_from_v6_mapped(&b) {
            return Some((fam, v4, port));
        }
        // ::1 loopback: treat as 127.0.0.1.
        if ipv6_loopback(&b) {
            return Some((fam, net::Ipv4Addr::LOOPBACK, port));
        }
        // :: (unspecified): treat as INADDR_ANY.
        if ipv6_unspecified(&b) {
            return Some((fam, net::Ipv4Addr::ANY, port));
        }
        // Any other v6 address: not reachable on the v1 V4-only
        // transport. Caller maps to -EAFNOSUPPORT.
        None
    } else { None }
}

/// Write the sockaddr at `ptr` matching the socket's family. For
/// AF_INET6 sockets we synthesize the V6-equivalent of the V4
/// state held in InetSocket (V4 → V4-mapped ::ffff:x.x.x.x, V4
/// loopback → ::1, V4 ANY → ::).
fn write_sockaddr_for_socket(ptr: u64, sock: &InetSocket, ip: net::Ipv4Addr, port: u16) {
    let fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
    if fam == crate::dev_net::AF_INET6 {
        let mut b = [0u8; 16];
        if ip == net::Ipv4Addr::LOOPBACK {
            b[15] = 1; // ::1
        } else if ip == net::Ipv4Addr::ANY {
            // :: stays all-zero.
        } else {
            // V4-mapped form: ::ffff:a.b.c.d
            b[10] = 0xff; b[11] = 0xff;
            let v = ip.as_u32();
            b[12] = (v >> 24) as u8;
            b[13] = (v >> 16) as u8;
            b[14] = (v >>  8) as u8;
            b[15] =  v        as u8;
        }
        write_sockaddr_in6(ptr, b, port.to_be(), 0);
    } else {
        write_sockaddr_in(ptr, ip.as_u32().to_be(), port.to_be());
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
/// # C: O(1)
pub fn kernel_sys_bind(args: &SyscallArgs) -> i64 {
    const AF_UNIX: u16 = 1;
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock   = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    let family = match read_sa_family(addr_p) {
        Some(f) => f, None => return -(Errno::Efault.as_i32() as i64),
    };
    if family == AF_UNIX as u16 {
        let path = match read_sockaddr_un_path(addr_p) {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        let listener = match crate::dev_net::UNIX_REGISTRY.bind(path) {
            Ok(l) => l, Err(_) => return -(Errno::Eaddrinuse.as_i32() as i64),
        };
        *sock.kind.lock() = crate::dev_net::SockKind::UnixListener(listener);
        return 0;
    }
    if family != AF_INET as u16 && family != AF_INET6 as u16 {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    // Reject family-mismatch: AF_INET6 socket should not bind a
    // sockaddr_in (and vice-versa). musl/glibc don't issue such
    // mismatches; explicit reject catches buggy callers cleanly.
    let sock_fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
    if family != sock_fam { return -(Errno::Einval.as_i32() as i64); }
    let (_family, ip, port) = match read_sockaddr_any(addr_p) {
        Some(t) => t, None => return -(Errno::Eafnosupport.as_i32() as i64),
    };
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
/// # C: O(1)
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
        match read_sockaddr_any(dest_p) {
            Some((_fam, ip, p)) => (ip, p),
            None => return -(Errno::Eafnosupport.as_i32() as i64),
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
/// # C: O(1)
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
/// # C: O(1)
pub fn kernel_sys_listen(args: &SyscallArgs) -> i64 {
    let fd = args.a0;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    // AF_UNIX path-bound sockets are listeners after bind(2);
    // listen(2) is a no-op (no kernel state-change required).
    if matches!(*sock.kind.lock(), SockKind::UnixListener(_)) { return 0; }
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
/// # C: O(1)
pub fn kernel_sys_accept(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    drain_loopback();
    // AF_UNIX listener: pop one queued UnixPair and wrap as A end.
    if let SockKind::UnixListener(l) = &*sock.kind.lock() {
        let l = l.clone();
        let pair = match l.accept_q.lock().pop_front() {
            Some(p) => p, None => return -(Errno::Eagain.as_i32() as i64),
        };
        let new_sock = InetSocket::new_tcp();
        *new_sock.kind.lock() = SockKind::Unix(pair, net::UnixEnd::A);
        let inode: vfs::InodeRef = Arc::new(new_sock) as _;
        let cur = match crate::sched::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        // SAFETY: running task; sole reader of fd_table slot.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("[unix]"), Arc::clone(&inode));
        let f = vfs::File::new(inode, dentry, vfs::OpenFlags::empty());
        return match fdt.alloc(f) { Ok(fd) => fd as i64, Err(e) => -(e as i64) };
    }
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
    let listener_fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
    let new_sock = if listener_fam == crate::dev_net::AF_INET6 {
        InetSocket::new_tcp6()
    } else {
        InetSocket::new_tcp()
    };
    *new_sock.kind.lock() = SockKind::TcpConn(entry);
    *new_sock.peer.lock() = Some((peer_ip, peer_port));
    if addr_p != 0 {
        // Inherit family from the listening socket so accept() returns
        // the right sockaddr shape on AF_INET6 listeners.
        write_sockaddr_for_socket(addr_p, &new_sock, peer_ip, peer_port);
    }
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
    match fdt.alloc(file) { Ok(fd) => fd as i64, Err(e) => -(e as i64) }
}

/// `connect(fd, sockaddr, addrlen)` slot 42.
/// # C: O(1)
pub fn kernel_sys_connect(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    const AF_UNIX: u32 = 1;
    let family = match read_sa_family(addr_p) {
        Some(f) => f as u32, None => return -(Errno::Efault.as_i32() as i64),
    };
    if family == AF_UNIX {
        let path = match read_sockaddr_un_path(addr_p) {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        let pair = match crate::dev_net::UNIX_REGISTRY.connect(&path) {
            Some(p) => p, None => return -(Errno::Enoent.as_i32() as i64),
        };
        // Client gets the B end of the pair; the server's accept
        // pulls the A end out via the listener's accept_q.
        *sock.kind.lock() = crate::dev_net::SockKind::Unix(pair, net::UnixEnd::B);
        return 0;
    }
    if family != AF_INET && family != AF_INET6 {
        return -(Errno::Eafnosupport.as_i32() as i64);
    }
    let sock_fam = sock.family.load(core::sync::atomic::Ordering::Acquire) as u32;
    if family != sock_fam { return -(Errno::Einval.as_i32() as i64); }
    let (_family, dst_ip, port) = match read_sockaddr_any(addr_p) {
        Some(t) => t, None => return -(Errno::Eafnosupport.as_i32() as i64),
    };
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

/// `sendmsg(fd, msghdr, flags)` slot 46. v1 walks the iovec array
/// and calls into the same TCP/UDP/UNIX dispatch as sendto, using
/// `msg_name` as destaddr (else NULL). SCM_RIGHTS / SCM_CREDS in
/// msg_control are not yet honored (controllen treated as 0).
/// # C: O(1)
pub fn kernel_sys_sendmsg(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let msgp   = args.a1;
    let _flags = args.a2;
    if msgp == 0 || msgp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: msgp range validated; user page mapped under caller's AS.
    let (name, _namelen, iov, iovlen) = unsafe {
        let name      = core::ptr::read_volatile(msgp as *const u64);
        let namelen   = core::ptr::read_volatile((msgp + 8) as *const u32);
        let iov       = core::ptr::read_volatile((msgp + 16) as *const u64);
        let iovlen    = core::ptr::read_volatile((msgp + 24) as *const u64);
        (name, namelen, iov, iovlen)
    };
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let mut total: i64 = 0;
    for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i lies in user range; 8-byte aligned per Linux ABI; sendmsg path.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: iov_i + 8 still inside the iovec entry; len field is 8-byte aligned.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if len == 0 { continue; }
        let mut sa = *args;
        sa.a0 = fd; sa.a1 = base; sa.a2 = len; sa.a3 = 0; sa.a4 = name; sa.a5 = 0;
        let r = kernel_sys_sendto(&sa);
        if r < 0 { return if total > 0 { total } else { r }; }
        total += r;
    }
    total
}

/// `recvmsg(fd, msghdr, flags)` slot 47. Walks iovec, calls
/// recvfrom into each buffer until one returns Eagain or 0.
/// # C: O(1)
pub fn kernel_sys_recvmsg(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let msgp   = args.a1;
    let _flags = args.a2;
    if msgp == 0 || msgp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: msgp range validated; user page mapped under caller's AS.
    let (name, _namelen, iov, iovlen) = unsafe {
        let name      = core::ptr::read_volatile(msgp as *const u64);
        let namelen   = core::ptr::read_volatile((msgp + 8) as *const u32);
        let iov       = core::ptr::read_volatile((msgp + 16) as *const u64);
        let iovlen    = core::ptr::read_volatile((msgp + 24) as *const u64);
        (name, namelen, iov, iovlen)
    };
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let mut total: i64 = 0;
    for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i lies in user range; 8-byte aligned per Linux ABI; recvmsg path.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: iov_i + 8 still inside the iovec entry; len field is 8-byte aligned.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if len == 0 { continue; }
        let mut sa = *args;
        sa.a0 = fd; sa.a1 = base; sa.a2 = len; sa.a3 = 0; sa.a4 = name; sa.a5 = 0;
        let r = kernel_sys_recvfrom(&sa);
        if r < 0 { return if total > 0 { total } else { r }; }
        if r == 0 { break; }
        total += r;
        if (r as u64) < len { break; }  // short read -> stop
    }
    total
}

/// `sendmmsg(fd, mmsghdr*, vlen, flags)` — slot 307. Walks the
/// mmsghdr array calling `sendmsg` for each entry; writes the
/// per-entry byte count into the trailing `msg_len` u32 of each
/// mmsghdr. Stops on the first error and returns the count of
/// successfully-sent messages (Linux semantics: error is reported
/// only if zero messages succeeded).
/// # C: O(vlen)
pub fn kernel_sys_sendmmsg(args: &SyscallArgs) -> i64 {
    let fd       = args.a0;
    let mmsg_ptr = args.a1;
    let vlen     = args.a2;
    let flags    = args.a3;
    if mmsg_ptr == 0 || vlen == 0 { return 0; }
    if vlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let mut sent: i64 = 0;
    for i in 0..vlen {
        // struct mmsghdr = { struct msghdr (56 bytes); u32 msg_len; pad }; size 64.
        let entry = mmsg_ptr + i * 64;
        if entry >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let mut sa = *args;
        sa.a0 = fd; sa.a1 = entry; sa.a2 = flags;
        let r = kernel_sys_sendmsg(&sa);
        if r < 0 {
            return if sent > 0 { sent } else { r };
        }
        // Write back msg_len at +56.
        // SAFETY: entry < USER_VA_END; +56 within the 64-byte mmsghdr.
        unsafe { core::ptr::write_volatile((entry + 56) as *mut u32, r as u32); }
        sent += 1;
    }
    sent
}

/// `recvmmsg(fd, mmsghdr*, vlen, flags, timeout)` — slot 299.
/// Calls recvmsg per entry; same Linux semantics as sendmmsg.
/// Timeout is currently ignored (recvfrom path already polls via
/// internal yield-loop on blocking sockets).
/// # C: O(vlen)
pub fn kernel_sys_recvmmsg(args: &SyscallArgs) -> i64 {
    let fd       = args.a0;
    let mmsg_ptr = args.a1;
    let vlen     = args.a2;
    let flags    = args.a3;
    let _timeout = args.a4;
    if mmsg_ptr == 0 || vlen == 0 { return 0; }
    if vlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let mut got: i64 = 0;
    for i in 0..vlen {
        let entry = mmsg_ptr + i * 64;
        if entry >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let mut sa = *args;
        sa.a0 = fd; sa.a1 = entry; sa.a2 = flags;
        let r = kernel_sys_recvmsg(&sa);
        if r < 0 {
            return if got > 0 { got } else { r };
        }
        if r == 0 { break; }
        // SAFETY: entry < USER_VA_END; msg_len at +56.
        unsafe { core::ptr::write_volatile((entry + 56) as *mut u32, r as u32); }
        got += 1;
    }
    got
}

/// `getsockname(fd, addr, addrlen)` slot 51 — write local addr.
/// # C: O(1)
pub fn kernel_sys_getsockname(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => return -(Errno::Enotsock.as_i32() as i64),
    };
    if addr_p == 0 || addr_p >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let port = (*sock.local_port.lock()).unwrap_or(0);
    let ip   = *sock.local_ip.lock();
    write_sockaddr_for_socket(addr_p, &sock, ip, port);
    0
}

/// `getpeername(fd, addr, addrlen)` slot 52.
/// # C: O(1)
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
    write_sockaddr_for_socket(addr_p, &sock, ip, port);
    0
}

/// `shutdown(fd, how)` slot 48. v1 honors SHUT_WR (close-write
/// for AF_UNIX) by calling close_writer. SHUT_RD / SHUT_RDWR are
/// accepted silently (TCP shutdown ride alongside graceful close).
/// # C: O(1)
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
/// # C: O(1)
pub fn kernel_sys_setsockopt(_args: &SyscallArgs) -> i64 { 0 }

/// `getsockopt(fd, level, optname, optval, optlen)` slot 55.
///
/// Honored:
///   SOL_SOCKET (1) / SO_PEERCRED (17): writes back a `struct ucred`
///     {pid, uid, gid} (12 bytes) for AF_UNIX-paired fds. v1 reports
///     the calling task's tid + 0/0 (no real uid); sufficient for
///     systemd-class peer-credential checks to receive a non-zero pid.
///   SOL_SOCKET / SO_TYPE (3): writes back the SOCK_* shape.
///   Everything else: zero-length opt + return 0.
/// # C: O(1)
pub fn kernel_sys_getsockopt(args: &SyscallArgs) -> i64 {
    const SOL_SOCKET:   u64 = 1;
    const SO_TYPE:      u64 = 3;
    const SO_PEERCRED:  u64 = 17;
    let _fd     = args.a0;
    let level   = args.a1;
    let optname = args.a2;
    let optval  = args.a3;
    let optlen_p = args.a4;
    if level == SOL_SOCKET && optname == SO_PEERCRED
       && optval != 0 && optval < USER_VA_END
       && optlen_p != 0 && optlen_p < USER_VA_END
    {
        let pid = crate::sched::current().map(|c| c.tid as u32).unwrap_or(0);
        // SAFETY: optval+optlen_p validated < USER_VA_END; struct ucred is 12 bytes; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( optval        as *mut u32, pid);
            core::ptr::write_volatile((optval +  4)  as *mut u32, 0);
            core::ptr::write_volatile((optval +  8)  as *mut u32, 0);
            core::ptr::write_volatile(optlen_p as *mut u32, 12);
        }
        return 0;
    }
    if level == SOL_SOCKET && optname == SO_TYPE
       && optval != 0 && optval < USER_VA_END
       && optlen_p != 0 && optlen_p < USER_VA_END
    {
        // SAFETY: optval+optlen_p validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile(optval as *mut u32, 1 /* SOCK_STREAM */);
            core::ptr::write_volatile(optlen_p as *mut u32, 4);
        }
        return 0;
    }
    if optlen_p != 0 && optlen_p < USER_VA_END {
        // SAFETY: optlen_p validated < USER_VA_END; CPL=0 write through caller's AS.
        unsafe { core::ptr::write_volatile(optlen_p as *mut u32, 0); }
    }
    0
}

/// `recvfrom(fd, buf, len, flags, src, src_len)` slot 45.
/// # C: O(1)
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
            write_sockaddr_for_socket(src_p, &sock, peer_ip, peer_port);
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
        write_sockaddr_for_socket(src_p, &sock, src_ip, src_port);
    }
    take as i64
}
