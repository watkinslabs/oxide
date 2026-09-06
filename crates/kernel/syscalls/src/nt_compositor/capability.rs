use alloc::sync::{Arc, Weak};
use sched::thread_group::ThreadGroup;
use super::TransportError;

/// Transport identity is a canonical ThreadGroup pointer and a pinned open file.
pub(super) struct Capability {
    pub group: Weak<ThreadGroup>,
    pub _file: Arc<vfs::File>,
    pub socket: Arc<net::sock::InetSocket>,
    pub pair: Arc<net::UnixPair>,
    pub end: net::UnixEnd,
}

impl Capability {
    /// Classify the already-pinned file exactly once. # C: O(1)
    pub(super) fn pin(group: &Arc<ThreadGroup>, file: Arc<vfs::File>) -> Result<Self, TransportError> {
        let socket = crate::net_common::inode_as_inet_socket(file.inode()).ok_or(TransportError::Invalid)?;
        let (pair, end) = match &*socket.kind.lock() {
            net::sock::SockKind::Unix(pair, end) => (pair.clone(), *end),
            _ => return Err(TransportError::Invalid),
        };
        if pair.peer_gone(end) || pair.is_eof(end) { return Err(TransportError::Disconnected); }
        net::sock_opts::check_send(&socket).map_err(|_| TransportError::Invalid)?;
        net::sock_opts::check_receive(&socket).map_err(|_| TransportError::Invalid)?;
        Ok(Self { group: Arc::downgrade(group), _file: file, socket, pair, end })
    }
    /// Numeric PID reuse never grants the old connection. # C: O(1)
    pub(super) fn belongs_to(&self, group: &Arc<ThreadGroup>) -> bool { self.group.ptr_eq(&Arc::downgrade(group)) }
    /// Canonical group-exit latch ends transport even while zombies retain the group. # C: O(1)
    pub(super) fn owner_live(&self) -> bool {
        self.group.upgrade().is_some_and(|g| g.live_count() != 0 && g.group_exit_status().is_none())
    }
    /// # C: O(bytes)
    pub(super) fn write_bounded(&self, bytes: &[u8]) -> Result<usize, TransportError> {
        match self.pair.write_bounded(self.end, bytes, syscall::nt_compositor::SOCKET_CAP) {
            Ok(n) => Ok(n),
            Err(net::unix_sock::UnixStreamSendError::PeerClosed) => Err(TransportError::Disconnected),
            Err(net::unix_sock::UnixStreamSendError::WouldBlock) => Err(TransportError::Full),
        }
    }
    /// Owned endpoint teardown wakes readers and writers without acquiring GUI locks.
    /// # C: O(waiters)
    pub(super) fn shutdown(&self) { self.pair.shutdown_reader(self.end); self.pair.close_writer(self.end); }
}
