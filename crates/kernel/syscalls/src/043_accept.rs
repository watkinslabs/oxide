// 043 accept — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use alloc::sync::Arc;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_trace::trace_enotsock_at;
use crate::net_sockaddr::*;
use crate::net_common::{errno_from_neterr, file_is_nonblock, socket_from_fd};

/// `accept(fd, sockaddr, addrlen)` slot 43 / `accept4` slot 288.
/// Blocking unless fd has O_NONBLOCK (then Eagain on empty backlog);
/// honors SO_RCVTIMEO. ABI shim per `docs/53§4`.
/// # C: O(1)
pub fn sys_accept(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use core::sync::atomic::Ordering;
    let fd     = args.a0;
    let addr_p = args.a1;
    // D3.3: AF_VSOCK accept — pop a queued peer from the listener's
    // backlog (deliver_rx already replied OP_RESPONSE + inserted the
    // conn), wrap it in a new VsockSocket fd.
    if let Some(vs) = crate::net_common::vsock_from_fd(fd) {
        return vsock_accept(&vs, addr_p, file_is_nonblock(fd), args.a3);
    }
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
    let inode: vfs::InodeRef = net::sock::make_inet_socket_inode(accepted.new_sock);
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let dentry = vfs::dcache::d_alloc_pseudo("socket", Arc::clone(&inode), &crate::anon_dname::SOCKET_OPS);
    const SOCK_CLOEXEC:  u64 = 0o2_000_000;
    const SOCK_NONBLOCK: u64 = 0o0_004_000;
    let flags = args.a3;
    let mut fl = vfs::OpenFlags::O_RDWR;
    if (flags & SOCK_NONBLOCK) != 0 { fl |= vfs::OpenFlags::O_NONBLOCK; }
    let file = vfs::File::new(inode, dentry, fl);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (flags & SOCK_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// D3.3: AF_VSOCK accept. Pops one pending peer key from the listener's
/// backlog (blocking unless O_NONBLOCK), looks up the connection
/// deliver_rx already created, and installs it on a fresh VsockSocket fd.
/// # C: O(1) per accept
fn vsock_accept(vs: &Arc<net::vsock_socket::VsockSocket>, addr_p: u64,
                nonblock: bool, flags: u64) -> i64 {
    let port = match &*vs.kind.lock() {
        net::vsock_socket::VsockKind::Listener(p) => *p,
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    let key = loop {
        if let Some(k) = net::vsock::TABLE.pop_accept(port) { break k; }
        if nonblock { return -(Errno::Eagain.as_i32() as i64); }
        // SAFETY: process ctx (sys_accept AF_VSOCK); runqueue installed;
        // preempt-off owned by the syscall stub; deliver_rx queues the
        // peer + tick_yield reschedules so we re-poll the backlog.
        unsafe { sched::live::tick_yield(); }
    };
    let conn = match net::vsock::TABLE.find(key) {
        Some(c) => c, None => return -(Errno::Econnreset.as_i32() as i64),
    };
    if addr_p != 0 {
        write_sockaddr_vm(addr_p, key.peer_port, key.peer_cid);
    }
    let new_sock = Arc::new(net::vsock_socket::VsockSocket::new());
    *new_sock.kind.lock() = net::vsock_socket::VsockKind::Conn(conn);
    let inode: vfs::InodeRef = net::vsock_socket::make_vsock_socket_inode(new_sock);
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let dentry = vfs::dcache::d_alloc_pseudo("socket", Arc::clone(&inode), &crate::anon_dname::SOCKET_OPS);
    const SOCK_CLOEXEC:  u64 = 0o2_000_000;
    const SOCK_NONBLOCK: u64 = 0o0_004_000;
    let mut fl = vfs::OpenFlags::O_RDWR;
    if (flags & SOCK_NONBLOCK) != 0 { fl |= vfs::OpenFlags::O_NONBLOCK; }
    let file = vfs::File::new(inode, dentry, fl);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => { if (flags & SOCK_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); } fd as i64 }
        Err(e) => -(e as i64),
    }
}
