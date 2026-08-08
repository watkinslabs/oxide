// 043 accept — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use alloc::sync::Arc;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::net_sockaddr::*;
use crate::net_common::{classify, Routed};
use crate::net_errno::errno_from_neterr;
use crate::sock_route::ControlOp;
use net::socket_args::{AcceptFlags, parse_accept_flags};

/// `accept(fd, sockaddr, addrlen)` slot 43 / `accept4` slot 288.
/// Blocking unless fd has O_NONBLOCK (then Eagain on empty backlog);
/// honors SO_RCVTIMEO. ABI shim per `docs/53§4`.
/// # C: O(1)
pub fn sys_accept(args: &SyscallArgs) -> i64 {
    accept_common(args, 0)
}

/// `accept4(fd, sockaddr, addrlen, flags)` slot 288. # C: O(1)
pub fn sys_accept4(args: &SyscallArgs) -> i64 {
    accept_common(args, args.a3)
}

fn accept_common(args: &SyscallArgs, flags: u64) -> i64 {
    use hal::TimerOps;
    use core::sync::atomic::Ordering;
    let fd     = args.a0;
    let addr_p = args.a1;
    let len_p  = args.a2;
    // An fd that names no open file is EBADF before the flag word is even
    // read; a bad flag word is EINVAL before the file's protocol gets a say.
    // Both, and netlink's "no accept operation" EOPNOTSUPP, come from the one
    // ladder in `sock_route`.
    let parsed = parse_accept_flags(flags);
    let target = match classify(fd, ControlOp::Accept, parsed.as_ref().err().copied()) {
        Ok(target) => target,
        Err(error) => return -(error.as_i32() as i64),
    };
    let acc_flags = match parsed {
        Ok(f) => f, Err(e) => return -(e.as_i32() as i64),
    };
    let (file, sock) = match target {
        // `route` refuses a netlink accept before classification returns.
        Routed::Netlink(_) => return -(Errno::Eopnotsupp.as_i32() as i64),
        Routed::Vsock(vs) => {
            let nonblock = vs.is_nonblock();
            return vsock_accept(&vs, addr_p, len_p, nonblock, acc_flags);
        }
        Routed::Inet(file, sock) => (file, sock),
    };
    let nonblock = file.flags().contains(vfs::OpenFlags::O_NONBLOCK);
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
                // Linux `inet_csk_wait_for_connect`
                // and, for AF_UNIX,
                // `unix_accept` -> `skb_recv_datagram` ->
                // `__skb_wait_for_more_packets`:
                // `err = sock_intr_errno(timeo)` off `sock_rcvtimeo`.
                let wait = net::sock_intr::accept_wait_verdict(nonblock,
                    sched::live::deliverable_signals_self() != 0,
                    deadline.is_some_and(|dl| now() >= dl),
                    deadline.unwrap_or(net::sock_intr::NO_TIMEOUT));
                match wait {
                    net::sock_intr::AcceptWaitVerdict::Eagain => return -(Errno::Eagain.as_i32() as i64),
                    net::sock_intr::AcceptWaitVerdict::Interrupted(_) =>
                        return crate::net_errno::sock_intr_errno(deadline.unwrap_or(net::sock_intr::NO_TIMEOUT)),
                    net::sock_intr::AcceptWaitVerdict::Park => {}
                }
                // F160/F170: per-listener waitq park — TCP or AF_UNIX.
                enum LW { Tcp(Arc<net::stack::TcpListenEntry>), Unix(Arc<net::UnixListener>), None }
                let lw = match &*sock.kind.lock() {
                    net::sock::SockKind::TcpListener(l)  => LW::Tcp(l.clone()),
                    net::sock::SockKind::UnixListener(l) => LW::Unix(l.clone()),
                    _                                     => LW::None,
                };
                let park_dl = deadline.unwrap_or(0);
                match lw {
                    LW::Tcp(l)  => match l.arm_accept_wait(park_dl) {
                        net::stack::TcpAcceptWait::Ready => {}
                        net::stack::TcpAcceptWait::Closed => {
                            return -(Errno::Einval.as_i32() as i64);
                        }
                        net::stack::TcpAcceptWait::Parked => {
                            // SAFETY: arm_accept_wait registered current under the
                            // accept queue lock; enqueue, close, signal, and timeout wake it.
                            unsafe { sched::live::schedule::schedule(); }
                            l.accept_waiters.remove_current();
                        }
                    }
                    LW::Unix(l) => {
                        // Race-free: arm on accept_waiters UNDER the accept_q lock
                        // (re-checks emptiness there) so connect()'s push+wake_all
                        // cannot be lost. Only schedule() if we actually parked;
                        // a connection that arrived in the window skips the park
                        // and the loop retries accept() immediately.
                        // SAFETY: process ctx; park armed under listener state;
                        // connect, signal, and timeout wake the task.
                        if l.arm_accept_wait(park_dl) {
                            // SAFETY: process context holding no lock (the park
                            // was armed under the accept_q lock, which
                            // `arm_accept_wait` released), which is `schedule`'s
                            // sleepable-context contract.
                            unsafe { sched::live::schedule::schedule(); }
                            l.accept_waiters.remove_current();
                        }
                    }
                    LW::None    => return -(Errno::Einval.as_i32() as i64),
                }
                continue;
            }
            Err(e) => return errno_from_neterr(e),
        }
    };
    let accepted = if addr_p != 0 {
        match net::sock::complete_accepted(accepted, |socket| {
            let sa = accepted_peer_sockaddr(socket);
            let rv = copy_sockaddr_to_user(addr_p, len_p, &sa);
            if rv < 0 { Err(rv) } else { Ok(()) }
        }, |accepted| accepted.new_sock.release_file()) {
            Ok(accepted) => accepted,
            Err(error) => return error,
        }
    } else { accepted };
    let unix_gc_pin = accepted.unix_gc_pin;
    let inode: vfs::InodeRef = net::sock::make_inet_socket_inode(accepted.new_sock);
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let dentry = vfs::dcache::d_alloc_pseudo("socket", Arc::clone(&inode), &crate::anon_dname::SOCKET_OPS);
    let mut fl = vfs::OpenFlags::O_RDWR;
    if acc_flags.nonblock { fl |= vfs::OpenFlags::O_NONBLOCK; }
    let file_cred = match crate::pathresolve::file_cred_for(&cur) {
        Some(cred) => cred, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let file = vfs::File::new_at(inode, dentry, fl, 0, file_cred);
    if let Some(sock) = crate::net_common::inode_as_inet_socket(file.inode()) {
        net::bind_file(&file, &sock);
    }
    drop(unix_gc_pin);
    match crate::socket_fd::install(&fdt, file, cur.nofile_soft(), acc_flags.cloexec) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

fn accepted_peer_sockaddr(sock: &net::sock::InetSocket) -> EncodedSockaddr {
    let fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
    if fam == net::sock::AF_UNIX {
        let path = net::sock::unix_peer_path(sock).flatten();
        return encoded_sockaddr_un_path(path.as_deref());
    }
    if fam == net::sock::AF_INET6 {
        if let Some((ip, port)) = *sock.peer6.lock() {
            return encoded_sockaddr_in6_peer(ip, port);
        }
    }
    let (ip, port) = (*sock.peer.lock()).unwrap_or((net::Ipv4Addr::ANY, 0));
    encoded_sockaddr_for_socket(sock, ip, port)
}

/// D3.3: AF_VSOCK accept. Pops one pending peer key from the listener's
/// backlog (blocking unless O_NONBLOCK), looks up the connection
/// deliver_rx already created, and installs it on a fresh VsockSocket fd.
/// # C: O(1) per accept
fn vsock_accept(vs: &Arc<net::vsock_socket::VsockSocket>, addr_p: u64, len_p: u64,
                nonblock: bool, acc_flags: AcceptFlags) -> i64 {
    let listener = match vs.listener_for_accept() {
        Ok(listener) => listener,
        Err(error) => return crate::net_errno::errno_from_neterr(error),
    };
    let conn = loop {
        if let Some(c) = net::vsock::TABLE.pop_accept_exact(&listener) { break c; }
        match net::sock_intr::accept_wait_verdict(nonblock,
            sched::live::deliverable_signals_self() != 0, false, vs.recv_deadline_ns()) {
            net::sock_intr::AcceptWaitVerdict::Eagain => return -(Errno::Eagain.as_i32() as i64),
            net::sock_intr::AcceptWaitVerdict::Interrupted(_) =>
                return crate::net_errno::sock_intr_errno(vs.recv_deadline_ns()),
            net::sock_intr::AcceptWaitVerdict::Park => {}
        }
        match net::vsock::TABLE.arm_accept_wait_exact(&listener, 0) {
            net::vsock::AcceptWait::Ready => continue,
            net::vsock::AcceptWait::Removed => return -(Errno::Einval.as_i32() as i64),
            net::vsock::AcceptWait::Armed => {
                // SAFETY: owner wait gate registered current under listener locks.
                unsafe { sched::live::schedule::schedule(); }
                listener.accept_waiters.remove_current();
            }
        }
    };
    if addr_p != 0 {
        let sa = encoded_sockaddr_vm(conn.peer_port, conn.peer_cid);
        let rv = copy_sockaddr_to_user(addr_p, len_p, &sa);
        if rv < 0 {
            net::vsock::close(&conn);
            return rv;
        }
    }
    let new_sock = Arc::new(net::vsock_socket::VsockSocket::new_accepted_with_filter(
        vs, conn.bpf_filter.clone()));
    *new_sock.kind.lock() = net::vsock_socket::VsockKind::Conn(conn);
    let inode: vfs::InodeRef = net::vsock_socket::make_vsock_socket_inode(new_sock);
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let dentry = vfs::dcache::d_alloc_pseudo("socket", Arc::clone(&inode), &crate::anon_dname::SOCKET_OPS);
    let mut fl = vfs::OpenFlags::O_RDWR;
    if acc_flags.nonblock { fl |= vfs::OpenFlags::O_NONBLOCK; }
    let file = vfs::File::new(inode, dentry, fl);
    match crate::socket_fd::install(&fdt, file, cur.nofile_soft(), acc_flags.cloexec) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}
