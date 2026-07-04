use super::*;

/// `ino()` high tag identifying an AF_INET/AF_UNIX/AF_PACKET socket inode (so
/// its inode numbers don't collide with fs inode space). # C: O(1)
pub const INET_INO_TAG: u64 = 0x534F_434B_0000_0000;

/// Build the `Arc<Inode>` wrapping an AF_INET-family socket fd. The socket
/// lives in `i_private` (recover it with [`inet_from_inode`]); `ino()` carries
/// [`INET_INO_TAG`] OR'd with the socket pointer's low bits.
///
/// NOTE (kp2 follow-up): the socket's own `poll_subs` (`Arc<PollSubscribers>`,
/// referenced by the TCP/UDP stack entries for targeted epoll wakes) is NOT
/// shared into the built inode, because `InodeBuilder` only accepts a
/// by-value `PollSubscribers`. Until vfs grows `InodeBuilder::poll_subs_arc(
/// Arc<PollSubscribers>)`, `inode.poll_subscribers()` is `None` and epoll on a
/// socket fd falls back to the global broadcast. # C: O(1)
pub fn make_inet_socket_inode(sock: Arc<InetSocket>) -> vfs::InodeRef {
    let ino = INET_INO_TAG | (Arc::as_ptr(&sock) as u64 & 0xFFFF_FFFF);
    // Share the socket's OWN poll_subs into the inode so `inode.poll_subscribers()`
    // (what epoll_ctl(ADD) subscribes to) is the SAME list the socket's write/recv
    // paths notify (`wake_peer_subs`, stack targeted wakes). Without this the inode
    // had no subscriber list, so a notify() on a socket write never reached an
    // epoll_wait-blocked reader — dbus-broker's post-AUTH epoll on an accepted
    // AF_UNIX connection never woke for the client's binary messages, so it timed
    // out and closed every connection (every Type=dbus unit then timed out).
    let subs = sock.poll_subs.clone();
    // S_IFSOCK so fstat()/sd_is_socket() see a socket — systemd-udevd's
    // listen_fds() rejects an inherited fd whose mode isn't S_ISSOCK
    // (returns -EINVAL → "Failed to listen on fds"). Linux socket fds
    // are always S_IFSOCK.
    vfs::InodeBuilder::new(ino, vfs::mk_mode(vfs::FileType::Socket, 0o600),
        vfs::default_inode_ops(), Arc::new(InetFileOps))
        .private(sock)
        .poll_subs_arc(subs)
        .build()
}

/// Recover the `&InetSocket` stored in a socket inode's `i_private`. # C: O(1)
pub fn inet_from_inode(inode: &vfs::Inode) -> Option<&InetSocket> {
    inode.private::<InetSocket>()
}

/// Local AF_UNIX address (sun_path) this socket is bound to, if any —
/// used by `getsockname` to report the bound path. A bound stream/seqpacket
/// listener carries its path on the `UnixListener`; a bound dgram queue
/// carries it on the queue. Unbound/connected sockets return `None`.
/// # C: O(1)
pub fn unix_local_path(sock: &InetSocket) -> Option<alloc::string::String> {
    match &*sock.kind.lock() {
        SockKind::UnixListener(l) => Some(l.path.clone()),
        // Dgram queues don't retain their bound path (the registry owns
        // it); the bare AF_UNIX family is enough for getsockname's callers.
        _ => None,
    }
}

/// Recover an owning `Arc<InetSocket>` from a socket inode. # C: O(1)
pub fn inet_arc_from_inode(inode: &vfs::InodeRef) -> Option<Arc<InetSocket>> {
    inode.i_private().clone().downcast::<InetSocket>().ok()
}

/// `file_operations` for an AF_INET-family socket inode — delegates the data
/// path to the `InetSocket` in `i_private`.
struct InetFileOps;

impl vfs::FileOps for InetFileOps {
    fn read(&self, inode: &vfs::Inode, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        match inode.private::<InetSocket>() { Some(s) => s.read(off, buf), None => Err(vfs::VfsError::Einval) }
    }
    fn write(&self, inode: &vfs::Inode, off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        match inode.private::<InetSocket>() { Some(s) => s.write(off, buf), None => Err(vfs::VfsError::Einval) }
    }
    fn read_nonblock(&self, inode: &vfs::Inode, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        match inode.private::<InetSocket>() { Some(s) => s.read_nonblock(off, buf), None => Err(vfs::VfsError::Einval) }
    }
    fn write_nonblock(&self, inode: &vfs::Inode, off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        match inode.private::<InetSocket>() { Some(s) => s.write_nonblock(off, buf), None => Err(vfs::VfsError::Einval) }
    }
    fn poll(&self, inode: &vfs::Inode) -> u32 {
        inode.private::<InetSocket>().map(|s| s.poll()).unwrap_or(vfs::POLL_OUT)
    }
}
