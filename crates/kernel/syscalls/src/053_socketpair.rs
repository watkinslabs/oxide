// 053 socketpair — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use alloc::sync::Arc;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use net::sock::{InetSocket, SockKind};
use net::socket_args::{parse_socket_args, AF_UNIX, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_NONBLOCK, SOCK_RAW, SOCK_SEQPACKET, SOCK_STREAM, SOCK_TYPE_MASK};
use crate::userbuf::write_user_i32;

/// `socketpair` slot 53. AF_UNIX STREAM / SEQPACKET / DGRAM (F125).
/// # C: O(1)
pub fn sys_socketpair(args: &SyscallArgs) -> i64 {
    let domain = args.a0 as u32;
    let raw_type = args.a1 as u32;
    let protocol = args.a2 as u32;
    let svp    = args.a3;
    let extra = raw_type & !SOCK_TYPE_MASK;
    if extra & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let net_namespace = match cur.network_namespace_snapshot() {
        Some(namespace) => namespace,
        None => return -(Errno::Esrch.as_i32() as i64),
    };
    let reserve_flags = if extra & SOCK_CLOEXEC != 0 { vfs::OpenFlags::O_CLOEXEC } else { vfs::OpenFlags::empty() };
    crate::fd_pair::install_fd_pair(&fdt, cur.nofile_soft(), reserve_flags,
        |index, fd| write_user_i32(svp + index as u64 * 4, fd),
        || create_files(domain, raw_type, protocol, cur, net_namespace))
}

fn create_files(domain: u32, raw_type: u32, protocol: u32, cur: &sched::Task,
                net_namespace: network_namespace::NetworkNamespaceRef)
    -> Result<(Arc<vfs::File>, Arc<vfs::File>), i64>
{
    let spec = parse_socket_args(domain, raw_type, protocol, true).map_err(|e| -(e.as_i32() as i64))?;
    if spec.family != AF_UNIX { return Err(-(Errno::Eopnotsupp.as_i32() as i64)); }
    // Linux unix_create maps AF_UNIX SOCK_RAW onto SOCK_DGRAM before its
    // socketpair operation. Preserve that one protocol personality for both
    // transport construction and the observable SO_TYPE value.
    let socket_type = if spec.typ == SOCK_RAW { SOCK_DGRAM } else { spec.typ };
    net::sock_opts::check_socketpair(net_namespace.id().as_u64(), spec.family as u16,
        socket_type, spec.protocol).map_err(|e| -(crate::net_common::errno_from_neterr(e) as i64))?;
    let stream = if socket_type == SOCK_STREAM { Some(net::UnixPair::new()) } else { None };
    let msg = match socket_type {
        SOCK_DGRAM => Some(net::UnixMsgPair::new_datagram()),
        SOCK_SEQPACKET => Some(net::UnixMsgPair::new()),
        _ => None,
    };
    if let Some(p) = &stream {
        use core::sync::atomic::Ordering;
        let (pid, uid, gid) = (cur.visible_pid(),
            cur.creds.euid.load(Ordering::Relaxed), cur.creds.egid.load(Ordering::Relaxed));
        p.set_end_cred(net::UnixEnd::A, pid, uid, gid);
        p.set_end_cred(net::UnixEnd::B, pid, uid, gid);
    }
    if let Some(p) = &msg {
        use core::sync::atomic::Ordering;
        let (pid, uid, gid) = (cur.visible_pid(),
            cur.creds.euid.load(Ordering::Relaxed), cur.creds.egid.load(Ordering::Relaxed));
        p.set_end_cred(net::UnixEnd::A, pid, uid, gid);
        p.set_end_cred(net::UnixEnd::B, pid, uid, gid);
    }
    let make_file = |end: net::UnixEnd| {
        let error = if let Some(p) = &stream { p.end_error(end) }
            else if let Some(p) = &msg { p.end_error(end) }
            else { Arc::new(net::SocketError::new()) };
        let mut s = if let Some(p) = &stream {
            InetSocket::new_unix_pair_end_in(net_namespace.clone(), p.clone(), end)
        } else { InetSocket::new_unix_dgram_in(net_namespace.clone()) };
        s.error = error;
        s.opts.so_type.store(socket_type as u8, core::sync::atomic::Ordering::Release);
        if let Some(p) = &stream {
            p.attach_end_error(end, &s.error);
        } else if let Some(p) = &msg {
            *s.kind.lock() = SockKind::UnixMsgPair(p.clone(), end);
            p.register_end_subs(end, &s.poll_subs);
            p.attach_end_filter(end, &s.bpf_filter);
        }
        let inode = net::sock::make_inet_socket_inode(Arc::new(s));
        let dentry = vfs::dcache::d_alloc_pseudo("socket", Arc::clone(&inode), &crate::anon_dname::SOCKET_OPS);
        let mut flags = vfs::OpenFlags::O_RDWR;
        if spec.nonblock { flags |= vfs::OpenFlags::O_NONBLOCK; }
        let f = vfs::File::new(inode, dentry, flags);
        let sock = crate::net_common::inode_as_inet_socket(f.inode()).expect("socketpair inode");
        net::bind_file(&f, &sock);
        f
    };
    Ok((make_file(net::UnixEnd::A), make_file(net::UnixEnd::B)))
}
