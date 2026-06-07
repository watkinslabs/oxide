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

/// Resolve an fd to its vfs::File Arc (running task's fd table).
/// # C: O(1)
pub(crate) fn fd_file(fd: u64) -> Option<Arc<vfs::File>> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    fdt.get(fd as i32).ok()
}
