// net_common — shared net-syscall helpers + consts (docs/53 §0).
// Moved verbatim from net.rs.
use alloc::sync::Arc;
use net::sock::InetSocket;
#[cfg(target_os = "oxide-kernel")]
use net::sock::SockKind;

pub(crate) use crate::net_errno::errno_from_neterr;

/// Socket plus the `fget`-style file pin held for the syscall duration.
pub(crate) struct SocketFileRef {
    _file: Arc<vfs::File>,
    socket: Arc<InetSocket>,
}

/// AF_VSOCK socket plus the `fget`-style file pin held for the syscall duration.
pub(crate) struct VsockFileRef {
    file: Arc<vfs::File>,
    socket: Arc<net::vsock_socket::VsockSocket>,
}

impl VsockFileRef {
    /// Snapshot `O_NONBLOCK` from the pinned open file description. # C: O(1)
    pub(crate) fn is_nonblock(&self) -> bool {
        self.file.flags().contains(vfs::OpenFlags::O_NONBLOCK)
    }
}

impl core::ops::Deref for VsockFileRef {
    type Target = Arc<net::vsock_socket::VsockSocket>;
    fn deref(&self) -> &Self::Target { &self.socket }
}

impl core::ops::Deref for SocketFileRef {
    type Target = Arc<InetSocket>;
    fn deref(&self) -> &Self::Target { &self.socket }
}

pub(crate) const AF_INET:     u32 = 2;
pub(crate) const AF_INET6:    u32 = 10;
pub(crate) const SOCK_STREAM: u32 = 1;
pub(crate) const SOCK_DGRAM:  u32 = 2;
pub(crate) const SOCK_SEQPACKET: u32 = 5;

#[cfg(target_os = "oxide-kernel")]
/// True iff the fd's vfs::File has `O_NONBLOCK` set.
/// # C: O(1)
pub(crate) fn file_is_nonblock(fd: u64) -> bool {
    let Some(cur) = sched::live::current() else { return false };
    // SAFETY: running task; sole reader of fd_table slot per `13§5`.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return false };
    let Ok(file) = fdt.get(fd as i32) else { return false };
    file.flags().contains(vfs::OpenFlags::O_NONBLOCK)
}

#[cfg(target_os = "oxide-kernel")]
/// Resolve an fd to its InetSocket Arc. None when fd is closed
/// or refers to a non-socket inode.
/// # C: O(1)
pub(crate) fn socket_from_fd(fd: u64) -> Option<SocketFileRef> {
    let cur = sched::live::current()?;
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?;
    let file = fdt.get(fd as i32).ok()?;
    // Post-KEYSTONE: the socket is the inode's `i_private`; `Arc::downcast`
    // (in `inode_as_inet_socket`) recovers the typed `Arc<InetSocket>`.
    let socket = inode_as_inet_socket(file.inode())?;
    Some(SocketFileRef { _file: file, socket })
}

#[cfg(target_os = "oxide-kernel")]
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
        SockKind::UnixMsgPair(pair, end) => Some(pair.peer_cred(*end)),
        SockKind::UnixListener(listener) => Some(listener.owner_cred()),
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

/// Downcast an inode to the concrete AF_VSOCK socket. # C: O(1)
pub(crate) fn inode_as_vsock(inode: &vfs::InodeRef) -> Option<Arc<net::vsock_socket::VsockSocket>> {
    inode.i_private().clone().downcast::<net::vsock_socket::VsockSocket>().ok()
}

/// Classify an already-pinned file as AF_VSOCK while retaining its file pin.
/// # C: O(1)
pub(crate) fn vsock_from_file(file: Arc<vfs::File>) -> Option<VsockFileRef> {
    let socket = inode_as_vsock(file.inode())?;
    Some(VsockFileRef { file, socket })
}

/// Resolve an fd to AF_VSOCK with a Linux `fget`-style file pin. The pin delays
/// final `fput` and endpoint release until the complete syscall operation ends.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn vsock_from_fd(fd: u64) -> Option<VsockFileRef> {
    let cur = sched::live::current()?;
    // SAFETY: running task; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?;
    let file = fdt.get(fd as i32).ok()?;
    vsock_from_file(file)
}

#[cfg(target_os = "oxide-kernel")]
/// Resolve an fd to its vfs::File Arc (running task's fd table).
/// # C: O(1)
pub(crate) fn fd_file(fd: u64) -> Option<Arc<vfs::File>> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    fdt.get(fd as i32).ok()
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod tests {
    use super::*;

    #[test]
    fn vsock_ref_delays_final_file_release_until_operation_ends() {
        let socket = Arc::new(net::vsock_socket::VsockSocket::new());
        let inode = net::vsock_socket::make_vsock_socket_inode(socket.clone());
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
        let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);
        let socket_file = vsock_from_file(file.clone()).expect("AF_VSOCK file");

        drop(file);
        assert!(!matches!(*socket.kind.lock(), net::vsock_socket::VsockKind::Released));

        drop(socket_file);
        assert!(matches!(*socket.kind.lock(), net::vsock_socket::VsockKind::Released));
    }

    #[test]
    fn read_uses_its_original_file_instead_of_reresolving_vsock_fd() {
        let read = include_str!("000_read.rs");
        assert!(!read.contains("vsock_from_fd"));
        assert!(read.contains("file.read(slice)"));
    }
}
