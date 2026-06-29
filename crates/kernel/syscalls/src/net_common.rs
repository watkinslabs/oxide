// net_common — shared net-syscall helpers + consts (docs/53 §0).
// Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use alloc::sync::Arc;
use syscall::errno::Errno;
use net::sock::{InetSocket, SockKind};

pub(crate) const AF_INET:     u32 = 2;
pub(crate) const AF_INET6:    u32 = 10;
pub(crate) const SOCK_STREAM: u32 = 1;
pub(crate) const SOCK_DGRAM:  u32 = 2;
pub(crate) const SOCK_SEQPACKET: u32 = 5;

/// Map net::NetError → Linux errno (negated, ABI-ready). # C: O(1)
pub(crate) fn errno_from_neterr(e: net::NetError) -> i64 {
    -(match e {
        net::NetError::Eaddrinuse    => Errno::Eaddrinuse,
        net::NetError::Eaddrnotavail => Errno::Eaddrnotavail,
        net::NetError::Enobufs       => Errno::Enobufs,
        net::NetError::Enomem        => Errno::Enomem,
        net::NetError::Enetunreach   => Errno::Enetunreach,
        net::NetError::Enodev        => Errno::Enodev,
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
    // Post-KEYSTONE: the socket is the inode's `i_private`; `Arc::downcast`
    // (in `inode_as_inet_socket`) recovers the typed `Arc<InetSocket>`.
    inode_as_inet_socket(file.inode())
}

/// `SO_PEERCRED` source: resolve `fd` → its AF_UNIX socket → the peer
/// end's `{pid,uid,gid}`. `None` for non-unix / unconnected fds.
/// # C: O(1)
pub(crate) fn peercred_for_fd(fd: i32) -> Option<(u32, u32, u32)> {
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

/// Downcast an `Arc<dyn vfs::Inode>` to `Arc<InetSocket>` by
/// pattern: only succeeds when the inode IS an InetSocket
/// (vouched by the high-bit tag in `ino()`).
/// # C: O(1)
pub(crate) fn inode_as_inet_socket(inode: &vfs::InodeRef) -> Option<Arc<InetSocket>> {
    // Post-KEYSTONE: the socket lives in the concrete inode's `i_private`
    // (`Arc<dyn Any + Send + Sync>`); recover the typed `Arc<InetSocket>` via
    // `Arc::downcast` (the ino tag is no longer needed — the downcast IS the
    // type check).
    inode.i_private().clone().downcast::<InetSocket>().ok()
}

/// D3.3: resolve an fd to its AF_VSOCK socket Arc, or None for a
/// closed fd / non-vsock inode. Mirrors `inode_as_inet_socket` but
/// keys on the VSOCK_INO_TAG. # C: O(1)
pub(crate) fn vsock_from_fd(fd: u64) -> Option<Arc<net::vsock_socket::VsockSocket>> {
    let cur = sched::live::current()?;
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?;
    let file = fdt.get(fd as i32).ok()?;
    let inode: &vfs::InodeRef = file.inode();
    // Post-KEYSTONE: the vsock socket lives in `i_private`; recover the typed
    // `Arc<VsockSocket>` via `Arc::downcast`.
    inode.i_private().clone().downcast::<net::vsock_socket::VsockSocket>().ok()
}

/// Resolve an fd to its vfs::File Arc (running task's fd table).
/// # C: O(1)
pub(crate) fn fd_file(fd: u64) -> Option<Arc<vfs::File>> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    fdt.get(fd as i32).ok()
}
