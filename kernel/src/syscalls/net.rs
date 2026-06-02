// AF_INET socket syscalls. v1: SOCK_DGRAM/UDP on AF_INET (IPv4).
use alloc::string::String;
use alloc::sync::Arc;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;
use vfs::{Dentry, File, OpenFlags};
use net::sock::{InetSocket, SockKind, socket_sendto, socket_recv, drain_loopback};
use crate::syscalls::net_trace::trace_enotsock_at;
use crate::syscalls::net_sockaddr::*;

const AF_INET:     u32 = 2;
const AF_INET6:    u32 = 10;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM:  u32 = 2;

/// Map net::NetError → Linux errno (negated, ABI-ready). # C: O(1)
pub(crate) fn errno_from_neterr(e: net::NetError) -> i64 {
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
        net::NetError::Econnrefused  => Errno::Econnrefused,
        net::NetError::Enoent        => Errno::Enoent,
        net::NetError::Eintr         => Errno::Eintr,
    } as i32 as i64)
}

/// `socket(domain, type, protocol)` slot 41. # C: O(1)
pub fn sys_socket(args: &SyscallArgs) -> i64 {
    const SOCK_CLOEXEC:  u32 = 0o2_000_000;
    const SOCK_NONBLOCK: u32 = 0o0_004_000;
    const SOCK_RAW:      u32 = 3;
    let domain = args.a0 as u32;
    let raw    = args.a1 as u32;
    let typ    = raw & 0xFF;
    let proto  = args.a2 as u32;
    let cloexec  = (raw & SOCK_CLOEXEC)  != 0;
    let nonblock = (raw & SOCK_NONBLOCK) != 0;
    const AF_UNIX_DOM: u32 = 1;
    const AF_NETLINK_DOM: u32 = ::netlink::AF_NETLINK as u32;
    const AF_PACKET_DOM: u32 = 17;
    let inode: vfs::InodeRef = if domain == AF_NETLINK_DOM {
        // Linux accepts SOCK_DGRAM and SOCK_RAW for netlink (Linux's
        // own libnl uses SOCK_RAW). Other types → EPROTOTYPE.
        if typ != SOCK_DGRAM && typ != SOCK_RAW {
            return -(Errno::Esocktnosupport.as_i32() as i64);
        }
        let sock = Arc::new(::netlink::NetlinkSocket::new(proto as u16));
        // udev/systemd-udevd: a NETLINK_KOBJECT_UEVENT socket subscribes
        // to broadcast device uevents.
        if (proto as u16) == ::netlink::proto::NETLINK_KOBJECT_UEVENT {
            ::netlink::register_uevent_listener(&sock);
        }
        sock as _
    } else {
        let inet = match (domain, typ) {
            (AF_INET,  SOCK_DGRAM)  => InetSocket::new_udp(),
            (AF_INET,  SOCK_STREAM) => InetSocket::new_tcp(),
            // F142: AF_INET+SOCK_RAW admitted as UDP shell. udhcpc /
            // libc getifaddrs use RAW sockets as ioctl handles only.
            (AF_INET,  SOCK_RAW)    => InetSocket::new_udp(),
            (AF_INET6, SOCK_DGRAM)  => InetSocket::new_udp6(),
            (AF_INET6, SOCK_STREAM) => InetSocket::new_tcp6(),
            (AF_INET6, SOCK_RAW)    => InetSocket::new_udp6(),
            (AF_UNIX_DOM, SOCK_STREAM) => InetSocket::new_unix(),
            (AF_UNIX_DOM, SOCK_DGRAM)  => InetSocket::new_unix_dgram(),
            (AF_PACKET_DOM, _) => {
                // F131: proto is htons(ETH_P_*); store host-order.
                let proto_be = (proto & 0xFFFF) as u16;
                InetSocket::new_packet(proto_be.swap_bytes(), typ as u8)
            }
            (AF_INET, _) | (AF_INET6, _) | (AF_UNIX_DOM, _) => return -(Errno::Esocktnosupport.as_i32() as i64),
            _ => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        Arc::new(inet) as _
    };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = Dentry::new(None, String::from("[socket]"), Arc::clone(&inode));
    // F198: sockets are RW by spec — File::write needs O_RDWR.
    let mut fl = OpenFlags::O_RDWR;
    if nonblock { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    match fdt.alloc(file) {
        Ok(fd) => { if cloexec { let _ = fdt.set_cloexec(fd, true); } fd as i64 }
        Err(e) => -(e as i64),
    }
}


/// True iff the fd's vfs::File has `O_NONBLOCK` set.
/// # C: O(1)
pub(crate) fn file_is_nonblock(fd: u64) -> bool {
    let Some(cur) = sched::live::current() else { return false };
    // SAFETY: running task; sole reader of fd_table slot per `13§5`.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return false };
    let Ok(file) = fdt.get(fd as i32) else { return false };
    file.flags().contains(vfs::OpenFlags::O_NONBLOCK)
}

/// Resolve an fd to its InetSocket Arc. None when fd is closed
/// or refers to a non-socket inode.
/// # C: O(1)
pub(crate) fn socket_from_fd(fd: u64) -> Option<Arc<InetSocket>> {
    let cur = sched::live::current()?;
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
/// `SO_PEERCRED` source: resolve `fd` → its AF_UNIX socket → the peer
/// end's `{pid,uid,gid}`. `None` for non-unix / unconnected fds.
/// # C: O(1)
fn peercred_for_fd(fd: i32) -> Option<(u32, u32, u32)> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    let file = fdt.get(fd).ok()?;
    let sock = inode_as_inet_socket(&file.inode())?;
    let kind = sock.kind.lock();
    match &*kind {
        SockKind::Unix(pair, end) => Some(pair.peer_cred(*end)),
        _ => None,
    }
}

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
pub fn sys_bind(args: &SyscallArgs) -> i64 {
    const AF_UNIX: u16 = 1;
    let fd     = args.a0;
    let addr_p = args.a1;
    if crate::syscalls::netlink_fd::is_netlink(fd) {
        return crate::syscalls::netlink_fd::bind();
    }
    let sock   = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"bind"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    let family = match read_sa_family(addr_p) {
        Some(f) => f, None => return -(Errno::Efault.as_i32() as i64),
    };
    // Parse the user sockaddr into the typed BoundAddr enum.
    let addr = if family == AF_UNIX as u16 {
        let path = match read_sockaddr_un_path(addr_p) {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        // If the socket is already SOCK_DGRAM, pass its queue along.
        match &*sock.kind.lock() {
            net::sock::SockKind::UnixDgram(q) =>
                net::sock::BoundAddr::UnixDgram { path, queue: q.clone() },
            _ => net::sock::BoundAddr::UnixListener(path),
        }
    } else if family == AF_INET as u16 {
        let sock_fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
        if family != sock_fam { return -(Errno::Einval.as_i32() as i64); }
        let (_fam, ip, port) = match read_sockaddr_any(addr_p) {
            Some(t) => t, None => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        net::sock::BoundAddr::Inet { ip, port }
    } else if family == AF_INET6 as u16 {
        // F180a: AF_INET6 bind via v6 path with the 16-byte address.
        let sock_fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
        if family != sock_fam { return -(Errno::Einval.as_i32() as i64); }
        let (_fam, port, bytes, _scope) = match read_sockaddr_in6(addr_p) {
            Some(t) => t, None => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        net::sock::BoundAddr::Inet6 { ip: net::Ipv6Addr(bytes), port }
    } else if family == 17 /* AF_PACKET */ {
        // F131: sockaddr_ll = u16 family + u16 proto_be + i32 ifindex + tail.
        // SAFETY: addr_p validated < USER_VA_END above; sockaddr_ll spans +0..+20.
        let (proto_be, ifindex) = unsafe {
            let p = core::ptr::read_volatile((addr_p + 2) as *const u16);
            let i = core::ptr::read_volatile((addr_p + 4) as *const i32);
            (p, i)
        };
        let registered = {
            let k = sock.kind.lock();
            if let net::sock::SockKind::Packet { ifindex: ifi, protocol, .. } = &*k {
                ifi.store(ifindex as u32, core::sync::atomic::Ordering::Release);
                protocol.store(proto_be.swap_bytes(), core::sync::atomic::Ordering::Release);
                true
            } else { false }
        };
        if registered {
            // F137: register for rx delivery (e.g. DHCPOFFER frames).
            net::sock::register_packet(&sock);
            return 0;
        }
        return -(Errno::Einval.as_i32() as i64);
    } else {
        return -(Errno::Eafnosupport.as_i32() as i64);
    };
    // F153: also materialise an AF_UNIX path as a tmpfs sock inode
    // so stat(path) returns S_IFSOCK + chmod/unlink flow through VFS.
    let unix_path = match &addr {
        net::sock::BoundAddr::UnixListener(p) => Some(p.clone()),
        net::sock::BoundAddr::UnixDgram { path, .. } => Some(path.clone()),
        _ => None,
    };
    let rv = match net::sock::bind(&sock, addr) {
        Ok(()) => 0, Err(e) => errno_from_neterr(e),
    };
    if rv == 0 {
        if let Some(p) = unix_path {
            fs::tmpfs::register(p, fs::tmpfs::TmpfsSockInode::new() as vfs::InodeRef);
        }
    }
    rv
}

/// `sendto(fd, buf, len, flags, dest, dest_len)` slot 44.
/// # C: O(payload bytes)
pub fn sys_sendto(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use core::sync::atomic::Ordering;
    const MSG_DONTWAIT: u64 = 0x40;
    let fd     = args.a0;
    let bufp   = args.a1;
    let len    = args.a2 as usize;
    let flags  = args.a3;
    let dest_p = args.a4;
    // F132: netlink fd routing must happen BEFORE socket_from_fd,
    // which only knows InetSocket — netlink would otherwise hit
    // the ENOTSOCK branch despite is_netlink() recognizing it.
    if crate::syscalls::netlink_fd::is_netlink(fd) {
        if bufp == 0 || bufp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        if len > 65507 { return -(Errno::Emsgsize.as_i32() as i64); }
        return crate::syscalls::netlink_fd::sendto(fd, bufp, len);
    }
    let sock   = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"sendto"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    if bufp == 0 || bufp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    if len > 65507 { return -(Errno::Emsgsize.as_i32() as i64); }
    // F131/F146: AF_PACKET fast path lives in af_packet.rs.
    if let Some(rv) = crate::syscalls::af_packet::sendto(&sock, bufp, len, dest_p) {
        return rv;
    }
    let nonblock = (flags & MSG_DONTWAIT) != 0 || file_is_nonblock(fd);
    let timeo = sock.opts.sndtimeo_ns.load(Ordering::Acquire);
    #[cfg(target_arch = "x86_64")]
    let now = || hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = || hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let deadline = if timeo > 0 { Some(now().saturating_add(timeo as u64)) } else { None };
    // SAFETY: ptr range validated; user page mapped under caller's AS.
    let payload: alloc::vec::Vec<u8> = unsafe {
        core::slice::from_raw_parts(bufp as *const u8, len).to_vec()
    };
    // Parse optional destination based on socket family.
    let dest = if dest_p == 0 {
        None
    } else if matches!(*sock.kind.lock(), SockKind::UnixDgram(_)) {
        match read_sockaddr_un_path(dest_p) {
            Some(p) => Some(net::sock::RemoteAddr::UnixPath(p)),
            None    => return -(Errno::Einval.as_i32() as i64),
        }
    } else if read_sa_family(dest_p) == Some(AF_INET6 as u16) {
        // AF_INET6 destination: parse the 28-byte sockaddr_in6 and
        // route through the v6 send path. Reading it as sockaddr_in
        // (the v4 branch below) would mis-read the address as
        // 0.0.0.0 and silently send a v4 datagram into the void.
        match read_sockaddr_in6(dest_p) {
            Some((_fam, port, bytes, _scope)) =>
                Some(net::sock::RemoteAddr::Inet6 { ip: net::Ipv6Addr(bytes), port }),
            None => return -(Errno::Eafnosupport.as_i32() as i64),
        }
    } else {
        match read_sockaddr_any(dest_p) {
            Some((_fam, ip, port)) => Some(net::sock::RemoteAddr::Inet { ip, port }),
            None => return -(Errno::Eafnosupport.as_i32() as i64),
        }
    };
    // Fetch sender creds for AF_UNIX SCM.
    let creds = match sched::live::current() {
        Some(t) => net::sock::SenderCreds {
            pid: t.tgid.load(core::sync::atomic::Ordering::Acquire),
            uid: t.creds.euid.load(core::sync::atomic::Ordering::Acquire),
            gid: t.creds.egid.load(core::sync::atomic::Ordering::Acquire),
        },
        None => net::sock::SenderCreds::default(),
    };
    loop {
        match net::sock::sendto(&sock, &payload, dest.clone(), creds) {
            Ok(n)  => return n as i64,
            Err(net::NetError::Eagain) => {
                if nonblock { return -(Errno::Eagain.as_i32() as i64); }
                if let Some(dl) = deadline { if now() >= dl { return -(Errno::Eagain.as_i32() as i64); } }
                // SAFETY: process ctx; runqueue installed; preempt-off; tick_yield reschedules.
                unsafe { sched::live::tick_yield(); }
            }
            Err(e) => return errno_from_neterr(e),
        }
    }
}

/// `socketpair` slot 53. AF_UNIX STREAM / SEQPACKET / DGRAM (F125).
/// # C: O(1)
pub fn sys_socketpair(args: &SyscallArgs) -> i64 {
    const AF_UNIX: u32 = 1;
    const SOCK_TYPE_MASK: u32 = 0xF;
    const SOCK_SEQPACKET: u32 = 5;
    let domain = args.a0 as u32;
    let typ    = args.a1 as u32 & SOCK_TYPE_MASK;
    let svp    = args.a3;
    if domain != AF_UNIX { return -(Errno::Eafnosupport.as_i32() as i64); }
    if typ != SOCK_STREAM && typ != SOCK_SEQPACKET && typ != SOCK_DGRAM {
        return -(Errno::Esocktnosupport.as_i32() as i64);
    }
    if svp == 0 || svp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let stream = if typ == SOCK_STREAM { Some(net::UnixPair::new()) } else { None };
    let msg    = if typ != SOCK_STREAM { Some(net::UnixMsgPair::new()) } else { None };
    let mk = |end: net::UnixEnd| -> vfs::InodeRef {
        let s = InetSocket::new_tcp();
        if let Some(p) = &stream {
            *s.kind.lock() = SockKind::Unix(p.clone(), end);
            // F181a: tell the pair which subscribers wake on
            // peer-end writes/close.
            p.register_end_subs(end, &s.poll_subs);
        } else if let Some(p) = &msg {
            *s.kind.lock() = SockKind::UnixMsgPair(p.clone(), end);
            p.register_end_subs(end, &s.poll_subs);
        }
        Arc::new(s) as _
    };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SO_PEERCRED: both ends of a socketpair belong to the caller.
    if let Some(p) = &stream {
        use core::sync::atomic::Ordering;
        let (pid, uid, gid) = (cur.tgid.load(Ordering::Relaxed),
            cur.creds.euid.load(Ordering::Relaxed), cur.creds.egid.load(Ordering::Relaxed));
        p.set_end_cred(net::UnixEnd::A, pid, uid, gid);
        p.set_end_cred(net::UnixEnd::B, pid, uid, gid);
    }
    let a = {
        let inode = mk(net::UnixEnd::A);
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("[unix]"), Arc::clone(&inode));
        let f = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);
        match fdt.alloc(f) { Ok(fd) => fd, Err(e) => return -(e as i64) }
    };
    let b = {
        let inode = mk(net::UnixEnd::B);
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("[unix]"), Arc::clone(&inode));
        let f = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);
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
/// `listen(fd, backlog)` slot 50. Tier-3 shim per `docs/53§4`.
/// # C: O(1)
pub fn sys_listen(args: &SyscallArgs) -> i64 {
    let fd      = args.a0;
    let backlog = args.a1 as i32;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"listen"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    match net::sock::listen(&sock, backlog) {
        Ok(())  => 0,
        Err(e)  => errno_from_neterr(e),
    }
}

/// `accept(fd, sockaddr, addrlen)` slot 43 / `accept4` slot 288.
/// Blocking unless fd has O_NONBLOCK (then Eagain on empty backlog);
/// honors SO_RCVTIMEO. Tier-3 shim per `docs/53§4`.
/// # C: O(1)
pub fn sys_accept(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use core::sync::atomic::Ordering;
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"accept"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    let nonblock = file_is_nonblock(fd);
    let timeo = sock.opts.rcvtimeo_ns.load(Ordering::Acquire);
    #[cfg(target_arch = "x86_64")]
    let now = || hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = || hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let deadline = if timeo > 0 { Some(now().saturating_add(timeo as u64)) } else { None };
    let accepted = loop {
        match net::sock::accept(&sock) {
            Ok(a)  => break a,
            Err(net::NetError::Eagain) => {
                if nonblock { return -(Errno::Eagain.as_i32() as i64); }
                if let Some(dl) = deadline { if now() >= dl { return -(Errno::Eagain.as_i32() as i64); } }
                // F160/F170: per-listener waitq park — TCP or AF_UNIX.
                enum LW { Tcp(Arc<net::stack::TcpListenEntry>), Unix(Arc<net::UnixListener>), None }
                let lw = match &*sock.kind.lock() {
                    net::sock::SockKind::TcpListener(l)  => LW::Tcp(l.clone()),
                    net::sock::SockKind::UnixListener(l) => LW::Unix(l.clone()),
                    _                                     => LW::None,
                };
                let dl = deadline.unwrap_or(0);
                match lw {
                    LW::Tcp(l)  => {
                        // SAFETY: process ctx (sys_accept TCP); deliver_tcp wakes on accept_q push; timer scanner wakes on deadline.
                        unsafe { l.accept_waiters.park_with_deadline(dl); sched::live::schedule::schedule(); }
                    }
                    LW::Unix(l) => {
                        // SAFETY: process ctx (sys_accept AF_UNIX); UnixRegistry::connect wakes accept_waiters after push.
                        unsafe { l.accept_waiters.park_with_deadline(dl); sched::live::schedule::schedule(); }
                    }
                    LW::None    => {
                        // SAFETY: process ctx; runqueue installed; preempt-off; tick_yield reschedules.
                        unsafe { sched::live::tick_yield(); }
                    }
                }
                continue;
            }
            Err(e) => return errno_from_neterr(e),
        }
    };
    if let (Some((ip, port)), true) = (accepted.peer, addr_p != 0) {
        write_sockaddr_for_socket(addr_p, &accepted.new_sock, ip, port);
    }
    let label = if accepted.peer.is_some() { "[socket]" } else { "[unix]" };
    let inode: vfs::InodeRef = accepted.new_sock as _;
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let dentry = vfs::Dentry::new(None, alloc::string::String::from(label), Arc::clone(&inode));
    const SOCK_CLOEXEC:  u64 = 0o2_000_000;
    const SOCK_NONBLOCK: u64 = 0o0_004_000;
    let flags = args.a3;
    let mut fl = vfs::OpenFlags::O_RDWR;
    if (flags & SOCK_NONBLOCK) != 0 { fl |= vfs::OpenFlags::O_NONBLOCK; }
    let file = vfs::File::new(inode, dentry, fl);
    match fdt.alloc(file) {
        Ok(fd) => {
            if (flags & SOCK_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// `connect(fd, sockaddr, addrlen)` slot 42. Parses user sockaddr →
/// `net::sock::RemoteAddr` then calls `net::sock::connect`.
/// # C: O(1) UDP/UNIX, O(SYN-ACK RTT) TCP.
pub fn sys_connect(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"connect"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    const AF_UNIX: u32 = 1;
    let family = match read_sa_family(addr_p) {
        Some(f) => f as u32, None => return -(Errno::Efault.as_i32() as i64),
    };
    let addr = if family == AF_UNIX {
        let path = match read_sockaddr_un_path(addr_p) {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        net::sock::RemoteAddr::UnixPath(path)
    } else if family == AF_INET || family == AF_INET6 {
        let sock_fam = sock.family.load(core::sync::atomic::Ordering::Acquire) as u32;
        if family != sock_fam { return -(Errno::Einval.as_i32() as i64); }
        // F180b: native v6 dst routes through connect_v6 (UDP stashes
        // the v6 peer, TCP runs tcp_connect_ip). Only the v4-mapped
        // form (::ffff:a.b.c.d) falls through to the v4 path for
        // dual-stack semantics — ::1 / :: / global are genuine v6 and
        // must NOT be mis-stashed as a v4 peer.
        if family == AF_INET6 {
            if let Some((_, port, bytes, _)) = read_sockaddr_in6(addr_p) {
                let v4_mapped = ipv4_from_v6_mapped(&bytes).is_some();
                if !v4_mapped {
                    return match net::sock::connect(&sock, net::sock::RemoteAddr::Inet6 { ip: net::Ipv6Addr(bytes), port }) {
                        Ok(()) => 0,
                        Err(net::NetError::Eio) => -(Errno::Etimedout.as_i32() as i64),
                        Err(e) => errno_from_neterr(e),
                    };
                }
            }
        }
        let (_fam, ip, port) = match read_sockaddr_any(addr_p) {
            Some(t) => t, None => return -(Errno::Eafnosupport.as_i32() as i64),
        };
        net::sock::RemoteAddr::Inet { ip, port }
    } else {
        return -(Errno::Eafnosupport.as_i32() as i64);
    };
    match net::sock::connect(&sock, addr) {
        Ok(()) => 0,
        Err(net::NetError::Eio) => -(Errno::Etimedout.as_i32() as i64),
        Err(e) => errno_from_neterr(e),
    }
}

/// `sendmsg(fd, msghdr, flags)` slot 46. F189 honors SCM_RIGHTS
/// when the dest is an AF_UNIX SOCK_DGRAM (captures Arc<File> from
/// current fd_table; receiver dup's via recvmsg_unix_dgram).
/// # C: O(iov + nfds)
pub fn sys_sendmsg(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let msgp   = args.a1;
    let _flags = args.a2;
    if msgp == 0 || msgp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: msgp range validated; user page mapped under caller's AS.
    let (name, _namelen, iov, iovlen, control, controllen) = unsafe {
        let name      = core::ptr::read_volatile(msgp as *const u64);
        let namelen   = core::ptr::read_volatile((msgp + 8) as *const u32);
        let iov       = core::ptr::read_volatile((msgp + 16) as *const u64);
        let iovlen    = core::ptr::read_volatile((msgp + 24) as *const u64);
        let control   = core::ptr::read_volatile((msgp + 32) as *const u64);
        let controllen= core::ptr::read_volatile((msgp + 40) as *const u64);
        (name, namelen, iov, iovlen, control, controllen)
    };
    // F189: SCM_RIGHTS short-circuit for AF_UNIX SOCK_DGRAM.
    if let Some(r) = crate::syscalls::cmsg_parse::try_sendmsg_with_fds(
        fd, name, iov, iovlen, control, controllen,
    ) { return r; }
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
        let r = sys_sendto(&sa);
        if r < 0 { return if total > 0 { total } else { r }; }
        total += r;
    }
    total
}

/// `recvmsg(fd, msghdr, flags)` slot 47. # C: O(iov)
pub fn sys_recvmsg(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let msgp   = args.a1;
    let _flags = args.a2;
    // netlink: real netlink_recvmsg (fills the returned msghdr) — explicit,
    // not relying on the recvfrom fall-through which left msghdr unset.
    // MSG_PEEK (a2) must be honoured: sd-netlink peeks to size its buffer
    // before the consuming read.
    if crate::syscalls::netlink_fd::is_netlink(fd) {
        return crate::syscalls::netlink_fd::recvmsg(fd, msgp, args.a2 as u32);
    }
    if msgp == 0 || msgp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // F122/F213: route to DGRAM/STREAM cmsg handlers (lock dropped before recurse).
    let sock = socket_from_fd(fd);
    if let Some(s) = &sock {
        if matches!(*s.kind.lock(), SockKind::UnixDgram(_)) { return net::unix_cmsg::recvmsg_unix_dgram(s, msgp); }
        if matches!(*s.kind.lock(), SockKind::Unix(_, _))   { return crate::syscalls::cmsg_parse::recvmsg_unix_stream(s, msgp); }
    }
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
        let r = crate::syscalls::net_recv::sys_recvfrom(&sa);
        if r < 0 { return if total > 0 { total } else { r }; }
        if r == 0 { break; }
        total += r;
        if (r as u64) < len { break; }  // short read -> stop
    }
    total
}

pub use crate::syscalls::mmsg::{sys_sendmmsg, sys_recvmmsg};

/// `getsockname(fd, addr, addrlen)` slot 51 — write local addr.
/// # C: O(1)
pub fn sys_getsockname(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    if addr_p == 0 || addr_p >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    if crate::syscalls::netlink_fd::is_netlink(fd) {
        return crate::syscalls::netlink_fd::getsockname(addr_p);
    }
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"getsockname"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    let port = (*sock.local_port.lock()).unwrap_or(0);
    let ip   = *sock.local_ip.lock();
    write_sockaddr_for_socket(addr_p, &sock, ip, port);
    0
}

fn fd_file(fd: u64) -> Option<Arc<vfs::File>> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    fdt.get(fd as i32).ok()
}

/// `getpeername(fd, addr, addrlen)` slot 52.
/// # C: O(1)
pub fn sys_getpeername(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let addr_p = args.a1;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"getpeername"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    if addr_p == 0 || addr_p >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let (ip, port) = match *sock.peer.lock() {
        Some(t) => t, None => return -(Errno::Enotconn.as_i32() as i64),
    };
    write_sockaddr_for_socket(addr_p, &sock, ip, port);
    0
}

/// `shutdown(fd, how)` slot 48. POSIX semantics:
///   SHUT_RD   (0) — disable read side; future read()/recv* return EOF
///   SHUT_WR   (1) — disable write side; send FIN to peer
///   SHUT_RDWR (2) — both
/// AF_UNIX SHUT_WR maps to UnixPair::close_writer; TCP SHUT_WR maps
/// to tcp_close (sends FIN). SHUT_RD sets the per-socket read_shut
/// flag honored by Inode::read / read_nonblock.
/// # C: O(1)
pub fn sys_shutdown(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let fd  = args.a0;
    let how = args.a1 as u32;
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"shutdown"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    const SHUT_RD:   u32 = 0;
    const SHUT_WR:   u32 = 1;
    const SHUT_RDWR: u32 = 2;
    let do_rd = matches!(how, SHUT_RD | SHUT_RDWR);
    let do_wr = matches!(how, SHUT_WR | SHUT_RDWR);
    if do_rd { sock.read_shut.store(true, Ordering::Release); }
    if do_wr {
        match &*sock.kind.lock() {
            SockKind::Unix(p, e)        => p.close_writer(*e),
            SockKind::UnixMsgPair(p, e) => p.close_writer(*e),
            SockKind::TcpConn(entry)    => {
                let _ = net::sock::stack().tcp_close(entry);
                drain_loopback();
            }
            _ => {}
        }
    }
    0
}

/// `setsockopt(fd, level, optname, optval, optlen)` slot 54. # C: O(1)
pub fn sys_setsockopt(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    const SOL_SOCKET: u64  = 1;
    const IPPROTO_TCP: u64 = 6;
    let fd       = args.a0;
    let level    = args.a1;
    let optname  = args.a2;
    let optval   = args.a3;
    let optlen   = args.a4 as u32;
    if crate::syscalls::netlink_fd::is_netlink(fd) {
        return crate::syscalls::netlink_fd::setsockopt();
    }
    let sock = match socket_from_fd(fd) {
        Some(s) => s, None => { trace_enotsock_at(fd, b"setsockopt"); return -(Errno::Enotsock.as_i32() as i64); }
    };
    if optval == 0 || optval >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    let read_i32 = |o: u64| -> Option<i32> {
        if optlen < 4 || o + 4 > USER_VA_END { return None; }
        // SAFETY: o validated user range; 4-byte aligned int read per Linux ABI.
        Some(unsafe { core::ptr::read_volatile(o as *const i32) })
    };
    match (level, optname) {
        (SOL_SOCKET, 2)  => if let Some(v) = read_i32(optval) { sock.opts.reuseaddr.store(v, Ordering::Release); },
        (SOL_SOCKET, 15) => if let Some(v) = read_i32(optval) { sock.opts.reuseport.store(v, Ordering::Release); },
        (SOL_SOCKET, 9)  => if let Some(v) = read_i32(optval) {
            sock.opts.keepalive.store(v, Ordering::Release);
            if let net::sock::SockKind::TcpConn(entry) = &*sock.kind.lock() {
                entry.conn.lock().ka_enabled = v != 0;
            }
        },
        (SOL_SOCKET, 6)  => if let Some(v) = read_i32(optval) { sock.opts.broadcast.store(v, Ordering::Release); },
        (SOL_SOCKET, 7)  => if let Some(v) = read_i32(optval) { sock.opts.sndbuf.store(v, Ordering::Release); },
        (SOL_SOCKET, 8)  => if let Some(v) = read_i32(optval) { sock.opts.rcvbuf.store(v, Ordering::Release); },
        (SOL_SOCKET, 16) => if let Some(v) = read_i32(optval) { sock.opts.passcred.store(v, Ordering::Release); }, // SO_PASSCRED
        (SOL_SOCKET, 12) => priority_store(&sock, read_i32(optval)),
        (SOL_SOCKET, 36) => mark_store(&sock, read_i32(optval)),
        (SOL_SOCKET, 13) => {
            // struct linger { int l_onoff; int l_linger; } = 8 bytes
            if optlen >= 8 && optval + 8 <= USER_VA_END {
                // SAFETY: optval+8 validated; reading two i32 ints per linger ABI.
                // SAFETY: optval+8 validated above; struct linger has int l_onoff/l_linger.
                let on = unsafe { core::ptr::read_volatile(optval as *const i32) };
                // SAFETY: optval+8 validated above; second linger int at offset +4.
                let sec = unsafe { core::ptr::read_volatile((optval + 4) as *const i32) };
                sock.opts.linger_on.store(on, Ordering::Release);
                sock.opts.linger_s.store(sec, Ordering::Release);
            }
        }
        (SOL_SOCKET, 21) | (SOL_SOCKET, 20) => {
            // SO_RCVTIMEO_OLD(20) / SO_SNDTIMEO_OLD(21) — struct timeval (16B)
            if optlen >= 16 && optval + 16 <= USER_VA_END {
                // SAFETY: optval+16 validated; struct timeval { i64 sec; i64 usec; } read.
                // SAFETY: optval+16 validated above; struct timeval tv_sec is i64 at +0.
                let s = unsafe { core::ptr::read_volatile(optval as *const i64) };
                // SAFETY: optval+16 validated above; struct timeval tv_usec is i64 at +8.
                let u = unsafe { core::ptr::read_volatile((optval + 8) as *const i64) };
                let ns = (s.max(0) as i64) * 1_000_000_000 + (u.max(0) as i64) * 1_000;
                let slot = if optname == 21 { &sock.opts.sndtimeo_ns } else { &sock.opts.rcvtimeo_ns };
                slot.store(ns, Ordering::Release);
            }
        }
        (IPPROTO_TCP, 1) => if let Some(v) = read_i32(optval) { sock.opts.tcp_nodelay.store(v, Ordering::Release); },
        _ => {}
    }
    0
}

fn priority_store(s: &alloc::sync::Arc<net::sock::InetSocket>, v: Option<i32>) {
    if let Some(v) = v { s.opts.priority.store(v, core::sync::atomic::Ordering::Release); }
}
fn mark_store(s: &alloc::sync::Arc<net::sock::InetSocket>, v: Option<i32>) {
    if let Some(v) = v { s.opts.mark.store(v, core::sync::atomic::Ordering::Release); }
}

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
pub fn sys_getsockopt(args: &SyscallArgs) -> i64 {
    const SOL_SOCKET:   u64 = 1;
    const SO_TYPE:      u64 = 3;
    const SO_PEERCRED:  u64 = 17;
    let _fd     = args.a0;
    let level   = args.a1;
    let optname = args.a2;
    let optval  = args.a3;
    let optlen_p = args.a4;
    if crate::syscalls::netlink_fd::is_netlink(_fd) {
        return crate::syscalls::netlink_fd::getsockopt(_fd, level, optname, optval, optlen_p);
    }
    if level == SOL_SOCKET && optname == SO_PEERCRED
       && optval != 0 && optval < USER_VA_END
       && optlen_p != 0 && optlen_p < USER_VA_END
    {
        // Real peer creds for a connected AF_UNIX fd (snapshotted at
        // socketpair/connect/accept); falls back to the caller's own
        // {pid,euid,egid} for non-unix/unconnected sockets.
        let (pid, uid, gid) = peercred_for_fd(args.a0 as i32).unwrap_or_else(|| {
            use core::sync::atomic::Ordering;
            sched::live::current()
                .map(|c| (c.tgid.load(Ordering::Relaxed),
                          c.creds.euid.load(Ordering::Relaxed),
                          c.creds.egid.load(Ordering::Relaxed)))
                .unwrap_or((0, 0, 0))
        });
        // SAFETY: optval+optlen_p validated < USER_VA_END; struct ucred is 12 bytes; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile( optval        as *mut u32, pid);
            core::ptr::write_volatile((optval +  4)  as *mut u32, uid);
            core::ptr::write_volatile((optval +  8)  as *mut u32, gid);
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
    // Read-back of options stored via setsockopt.
    use core::sync::atomic::Ordering;
    const IPPROTO_TCP: u64 = 6;
    let fd = args.a0;
    let sock = socket_from_fd(fd);
    let i32_back = |val: i32| -> i64 {
        if optval == 0 || optval >= USER_VA_END
            || optlen_p == 0 || optlen_p >= USER_VA_END { return 0; }
        // SAFETY: optval+4 within user range; optlen_p validated; 4-byte aligned int writeback.
        unsafe {
            core::ptr::write_volatile(optval as *mut i32, val);
            core::ptr::write_volatile(optlen_p as *mut u32, 4);
        }
        0
    };
    if let Some(s) = sock {
        match (level, optname) {
            (SOL_SOCKET, 2)  => return i32_back(s.opts.reuseaddr.load(Ordering::Acquire)),
            (SOL_SOCKET, 15) => return i32_back(s.opts.reuseport.load(Ordering::Acquire)),
            (SOL_SOCKET, 9)  => return i32_back(s.opts.keepalive.load(Ordering::Acquire)),
            (SOL_SOCKET, 6)  => return i32_back(s.opts.broadcast.load(Ordering::Acquire)),
            (SOL_SOCKET, 7)  => return i32_back(s.opts.sndbuf.load(Ordering::Acquire)),
            (SOL_SOCKET, 8)  => return i32_back(s.opts.rcvbuf.load(Ordering::Acquire)),
            (SOL_SOCKET, 12) => return i32_back(s.opts.priority.load(Ordering::Acquire)),
            (SOL_SOCKET, 36) => return i32_back(s.opts.mark.load(Ordering::Acquire)),
            (IPPROTO_TCP, 1) => return i32_back(s.opts.tcp_nodelay.load(Ordering::Acquire)),
            // F188: TCP_INFO returns the Linux tcp_info struct.
            (IPPROTO_TCP, 11) => return crate::syscalls::tcp_info::write_tcp_info(&s, optval, optlen_p),
            (SOL_SOCKET, 4)  => {
                // F163/F174: SO_ERROR — read+clear per-conn (TCP) or
                // per-port (UDP, ICMP-unreach surface) error.
                let e = match &*s.kind.lock() {
                    SockKind::TcpConn(entry) => {
                        let mut c = entry.conn.lock();
                        let v = c.error_eno;
                        c.error_eno = 0;
                        v
                    }
                    SockKind::Udp => {
                        if let Some(p) = *s.local_port.lock() {
                            net::sock::stack().udp_queue_arc(p)
                                .map(|q| q.take_error()).unwrap_or(0)
                        } else { 0 }
                    }
                    _ => 0,
                };
                return i32_back(e);
            }
            _ => {}
        }
    }
    if optlen_p != 0 && optlen_p < USER_VA_END {
        // SAFETY: optlen_p validated < USER_VA_END; CPL=0 write through caller's AS.
        unsafe { core::ptr::write_volatile(optlen_p as *mut u32, 0); }
    }
    0
}

// F162: sys_recvfrom moved to net_recv.rs to stay under the
// 1000-line spec-lint cap. Re-exported via the syscalls module.
