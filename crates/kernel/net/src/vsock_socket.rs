// AF_VSOCK per-fd socket object — a vfs::Inode like InetSocket, but
// backed by the vsock connection table in `crate::vsock`. Its ino()
// upper bits carry a distinct tag (0x56534F43 = "VSOC") so the syscall
// layer's `vsock_from_fd` can recognize it without an Any downcast,
// mirroring InetSocket's 0x534F434B ("SOCK") tag.

use alloc::sync::Arc;
use sync::{Spinlock, Socket as SockLockClass};
use crate::vsock::{self, VsockConn, VsockState};

/// ino() high-word tag identifying an AF_VSOCK socket inode. # C: O(1)
pub const VSOCK_INO_TAG: u64 = 0x5653_4F43_0000_0000;
pub const VSOCK_INO_ID_MASK: u64 = 0xFFFF_FFFF;

/// vsock socket role across its lifetime. # C: O(1)
pub enum VsockKind {
    /// `socket()` done, no connect/bind yet.
    Init,
    /// `bind()` done, not listening yet. None means VMADDR_CID_ANY.
    Bound { port: u32, owner: Option<vsock::VsockOwner> },
    /// `connect()` succeeded or `accept()` produced this — live stream.
    Conn(Arc<VsockConn>),
    /// `bind()`+`listen()` — concrete table record and accept backlog.
    Listener(Arc<vsock::Listener>),
    /// Final file release detached the endpoint; no later publication is valid.
    Released,
}

enum VsockBinding {
    None,
    Explicit(Arc<vsock::BindReservation>),
    Auto(Arc<vsock::BindReservation>),
}

/// AF_VSOCK socket VFS state. # C: O(1)
pub struct VsockSocket {
    pub net_namespace: network_namespace::NetworkNamespaceRef,
    pub kind: Spinlock<VsockKind, SockLockClass>,
    binding: Spinlock<VsockBinding, SockLockClass>,
    released: core::sync::atomic::AtomicBool,
    pub so_type: core::sync::atomic::AtomicU8,
    /// AF_VSOCK transport buffer policy, in bytes. These are socket-owned
    /// Linux SOL_VSOCK values; the transport consumes them when attached.
    pub buffer_size: core::sync::atomic::AtomicU32,
    pub buffer_min_size: core::sync::atomic::AtomicU32,
    pub buffer_max_size: core::sync::atomic::AtomicU32,
    /// Canonical Linux `sk_err`.
    pub error: crate::SocketError,
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    /// SHUT_RD latch → read returns EOF.
    pub read_shut: core::sync::atomic::AtomicBool,
    #[cfg(test)]
    read_retry_hook: Spinlock<Option<fn(&Self)>, SockLockClass>,
    #[cfg(test)]
    write_retry_hook: Spinlock<Option<fn(&Self)>, SockLockClass>,
    #[cfg(test)]
    connect_wait_hook: Spinlock<Option<fn(&Self)>, SockLockClass>,
    pub poll_subs: Arc<vfs::PollSubscribers>,
}

impl VsockSocket {
    /// `socket(AF_VSOCK, SOCK_STREAM, 0)`. # C: O(1)
    pub fn new() -> Self {
        Self::new_type(crate::socket_args::SOCK_STREAM)
    }

    /// `socket(AF_VSOCK, type, protocol)`. # C: O(1)
    pub fn new_type(typ: u32) -> Self {
        Self::new_type_in(typ, crate::net_ns::current_namespace())
    }

    /// Build a socket retaining an explicit namespace owner. # C: O(1)
    pub fn new_type_in(typ: u32, net_namespace: network_namespace::NetworkNamespaceRef) -> Self {
        VsockSocket {
            net_namespace,
            kind: Spinlock::new(VsockKind::Init),
            binding: Spinlock::new(VsockBinding::None),
            released: core::sync::atomic::AtomicBool::new(false),
            so_type: core::sync::atomic::AtomicU8::new(typ as u8),
            buffer_size: core::sync::atomic::AtomicU32::new(256 * 1024),
            buffer_min_size: core::sync::atomic::AtomicU32::new(128),
            buffer_max_size: core::sync::atomic::AtomicU32::new(256 * 1024),
            error: crate::SocketError::new(),
            bpf_filter: Arc::new(crate::bpf_filter::SocketFilter::new()),
            read_shut: core::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            read_retry_hook: Spinlock::new(None),
            #[cfg(test)]
            write_retry_hook: Spinlock::new(None),
            #[cfg(test)]
            connect_wait_hook: Spinlock::new(None),
            poll_subs: Arc::new(vfs::PollSubscribers::new()),
        }
    }

    /// Build an accepted socket by cloning the listener's owner. # C: O(1)
    pub fn new_accepted(listener: &Self) -> Self {
        Self::new_accepted_with_filter(listener,
            Arc::new(crate::bpf_filter::SocketFilter::inherited(&listener.bpf_filter)))
    }

    /// Build an accepted socket sharing its exact pending connection filter. # C: O(1)
    pub fn new_accepted_with_filter(listener: &Self,
                                    bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> Self {
        let mut child = Self::new_type_in(
            listener.so_type.load(core::sync::atomic::Ordering::Acquire) as u32,
            listener.net_namespace.clone());
        child.bpf_filter = bpf_filter;
        child
    }

    /// Consume one exact listener backlog child and build its accepted socket. # C: O(N)
    pub fn accept(&self) -> Result<Arc<Self>, crate::NetError> {
        let listener = match &*self.kind.lock() {
            VsockKind::Listener(listener) => listener.clone(),
            _ => return Err(crate::NetError::Einval),
        };
        let conn = vsock::TABLE.pop_accept_exact(&listener).ok_or(crate::NetError::Eagain)?;
        conn.set_local_buf_alloc(self.buffer_size.load(core::sync::atomic::Ordering::Acquire));
        let child = Arc::new(Self::new_accepted_with_filter(self, conn.bpf_filter.clone()));
        *child.kind.lock() = VsockKind::Conn(conn);
        Ok(child)
    }

    /// Derive the short-lived namespace table key. # C: O(1)
    pub fn net_ns(&self) -> u64 { crate::net_ns::namespace_id(&self.net_namespace) }

    /// Check the retained namespace before consuming VSOCK receive state. # C: O(1)
    pub fn check_receive(&self) -> Result<(), crate::NetError> {
        crate::security_admission::check(
            self.net_ns(), crate::socket_args::AF_VSOCK as u16,
            security::network::Operation::Receive,
        )
    }

    /// Check the retained namespace before transmitting VSOCK payload. # C: O(1)
    pub fn check_send(&self) -> Result<(), crate::NetError> {
        crate::security_admission::check(
            self.net_ns(), crate::socket_args::AF_VSOCK as u16,
            security::network::Operation::Send,
        )
    }

    /// Snapshot the live connection Arc if this socket is connected.
    /// # C: O(1)
    pub fn conn(&self) -> Option<Arc<VsockConn>> {
        match &*self.kind.lock() {
            VsockKind::Conn(c) => Some(c.clone()),
            _ => None,
        }
    }

    fn attach_poll_source(&self) {
        match &*self.kind.lock() {
            VsockKind::Conn(conn) => conn.register_poll_subs(&self.poll_subs),
            VsockKind::Listener(listener) => listener.register_poll_subs(&self.poll_subs),
            _ => {}
        }
    }

    /// Record the latest positive Linux receive errno until it is consumed. # C: O(1)
    pub fn set_pending_recv_error(&self, errno: i32) -> bool {
        let conn = self.conn();
        let st = conn.as_ref().map(|c| c.st.lock());
        let changed = self.error.set(errno);
        drop(st);
        if changed {
            #[cfg(target_os = "oxide-kernel")]
            if let Some(c) = conn.as_ref() {
                c.waiters.wake_all();
            }
            self.poll_subs.notify_mask(vfs::POLL_ERR);
        }
        changed
    }

    /// Consume the pending positive Linux receive errno, or zero. # C: O(1)
    pub fn take_pending_recv_error(&self) -> i32 {
        self.error.take()
    }

    /// Observe whether a receive error is pending without consuming it. # C: O(1)
    pub fn has_pending_recv_error(&self) -> bool {
        self.error.has()
    }

    /// Snapshot the local sockaddr_vm port and CID. # C: O(1)
    pub fn local_addr(&self) -> Result<(u32, u64), crate::NetError> {
        const VMADDR_PORT_ANY: u32 = u32::MAX;
        Ok(match &*self.kind.lock() {
            VsockKind::Init => (VMADDR_PORT_ANY, vsock::VMADDR_CID_ANY),
            VsockKind::Bound { port, owner } =>
                (*port, owner.map(vsock::guest_cid_for).unwrap_or(vsock::VMADDR_CID_ANY)),
            VsockKind::Conn(conn) => (conn.local_port, conn.local_cid),
            VsockKind::Listener(listener) => (listener.local_port,
                listener.owner.map(vsock::guest_cid_for).unwrap_or(vsock::VMADDR_CID_ANY)),
            VsockKind::Released => return Err(crate::NetError::Einval),
        })
    }

    /// Snapshot the connected peer sockaddr_vm port and CID. # C: O(1)
    pub fn peer_addr(&self) -> Result<(u32, u64), crate::NetError> {
        let conn = self.conn().ok_or(crate::NetError::Enotconn)?;
        if matches!(*conn.st.lock(), VsockState::Connecting | VsockState::Closed) {
            return Err(crate::NetError::Enotconn);
        }
        Ok((conn.peer_port, conn.peer_cid))
    }

}

mod lifecycle;
mod shutdown;

impl Default for VsockSocket { fn default() -> Self { Self::new() } }

impl Drop for VsockSocket {
    fn drop(&mut self) { self.release_file(); }
}

/// Build the `Arc<Inode>` wrapping an AF_VSOCK socket fd. The socket lives in
/// `i_private` (recover it with [`vsock_from_inode`]); `ino()` carries
/// [`VSOCK_INO_TAG`] OR'd with the socket pointer's low bits. # C: O(1)
pub fn make_vsock_socket_inode(sock: Arc<VsockSocket>) -> vfs::InodeRef {
    let ino = VSOCK_INO_TAG | (Arc::as_ptr(&sock) as u64 & VSOCK_INO_ID_MASK);
    let subs = sock.poll_subs.clone();
    vfs::InodeBuilder::new(ino, vfs::mk_mode(vfs::FileType::Socket, 0o600),
        vfs::default_inode_ops(), Arc::new(VsockFileOps))
        .private(sock)
        .poll_subs_arc(subs)
        .build()
}

/// Recover the `&VsockSocket` stored in a vsock inode's `i_private`. # C: O(1)
pub fn vsock_from_inode(inode: &vfs::Inode) -> Option<&VsockSocket> {
    inode.private::<VsockSocket>()
}

/// Recover an owning `Arc<VsockSocket>` from a vsock inode. # C: O(1)
pub fn vsock_arc_from_inode(inode: &vfs::InodeRef) -> Option<Arc<VsockSocket>> {
    inode.i_private().clone().downcast::<VsockSocket>().ok()
}

/// `file_operations` for an AF_VSOCK socket inode — delegates the data path to
/// the `VsockSocket` in `i_private`.
struct VsockFileOps;

impl vfs::FileOps for VsockFileOps {
    fn read(&self, inode: &vfs::Inode, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        match inode.private::<VsockSocket>() { Some(s) => s.read(off, buf), None => Err(vfs::VfsError::Einval) }
    }
    fn write(&self, inode: &vfs::Inode, off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        match inode.private::<VsockSocket>() { Some(s) => s.write(off, buf), None => Err(vfs::VfsError::Einval) }
    }
    fn read_nonblock(&self, inode: &vfs::Inode, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        match inode.private::<VsockSocket>() { Some(s) => s.read_nonblock(off, buf), None => Err(vfs::VfsError::Einval) }
    }
    fn write_nonblock(&self, inode: &vfs::Inode, off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        match inode.private::<VsockSocket>() { Some(s) => s.write_nonblock(off, buf), None => Err(vfs::VfsError::Einval) }
    }
    fn poll(&self, inode: &vfs::Inode) -> u32 {
        inode.private::<VsockSocket>().map(|s| s.poll()).unwrap_or(vfs::POLL_OUT)
    }
    fn poll_subscribers(&self, file: &vfs::File) -> Option<Arc<vfs::PollSubscribers>> {
        let sock = file.inode().private::<VsockSocket>()?;
        sock.attach_poll_source();
        Some(sock.poll_subs.clone())
    }
    fn ioctl_int(&self, file: &vfs::File, cmd: vfs::IoctlIntCmd) -> vfs::KResult<u32> {
        let Some(s) = file.inode().private::<VsockSocket>() else { return Err(vfs::VfsError::Einval); };
        crate::security_admission::check(
            s.net_ns(), crate::socket_args::AF_VSOCK as u16,
            security::network::Operation::Ioctl,
        )
            .map_err(|_| vfs::VfsError::Eacces)?;
        Ok(match cmd {
            vfs::IoctlIntCmd::Fionread => s.conn().map(|c| c.rx.lock().len() as u32).unwrap_or(0),
            vfs::IoctlIntCmd::Siocoutq => s.conn().map(|c| { let tx = c.tx.lock(); tx.credit.tx_cnt.wrapping_sub(tx.credit.peer_fwd_cnt) }).unwrap_or(0),
            vfs::IoctlIntCmd::Siocatmark => return Err(vfs::VfsError::Enotty),
        })
    }
    fn fasync_file(&self, _fd: i32, file: &Arc<vfs::File>, on: bool) -> vfs::KResult<()> {
        file.set_fasync_state(on);
        Ok(())
    }
    fn on_release_file(&self, file: &vfs::File) {
        if let Some(sock) = file.inode().private::<VsockSocket>() { sock.release_file(); }
    }
}

#[cfg(test)]
#[path = "vsock_socket_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "vsock_socket_linux_tests.rs"]
mod linux_tests;

#[cfg(test)]
#[path = "vsock_socket/interleaving_tests.rs"]
mod interleaving_tests;

#[cfg(test)]
#[path = "vsock_socket/lifecycle_tests.rs"]
mod lifecycle_tests;

impl VsockSocket {
    /// Blocking stream read: drain buffered RX, park on the conn's
    /// waiters when empty + still live. EOF (Ok(0)) on peer shutdown.
    /// # C: backend-dependent
    pub fn read(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        self.check_receive().map_err(|_| vfs::VfsError::Eacces)?;
        if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
        let Some(c) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        loop {
            if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
            #[cfg(target_os = "oxide-kernel")]
            let _ = vsock::poll_rx_for(c.owner);
            match vsock::recv(&c, buf) {
                Ok(n)  => return Ok(n),
                Err(crate::NetError::Eagain) => {
                    let eno = self.take_pending_recv_error();
                    if eno != 0 { return Err(vsock_vfs_error(eno)); }
                    #[cfg(test)]
                    if let Some(hook) = self.read_retry_hook.lock().take() { hook(self); }
                    if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
                    {
                        let st = c.st.lock();
                        let rx = c.rx.lock();
                        if rx.is_empty()
                            && matches!(*st, VsockState::RcvShutdown | VsockState::Closed)
                        { return Ok(0); }
                    }
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        if sched::live::deliverable_signals_self() != 0 {
                            return Err(vfs::VfsError::Eintr);
                        }
                        let st = c.st.lock();
                        let rx = c.rx.lock();
                        if !rx.is_empty() || matches!(*st,
                            VsockState::RcvShutdown | VsockState::Closed)
                            || self.has_pending_recv_error()
                            || self.read_shut.load(core::sync::atomic::Ordering::Acquire)
                        { continue; }
                        // SAFETY: process ctx (VsockSocket::read); runqueue
                        // installed; preempt-off owned by the read syscall stub;
                        // RX lock closes data/error publication before park.
                        unsafe { c.waiters.park(); }
                        drop(rx);
                        drop(st);
                        // SAFETY: current is parked on this connection's wait list.
                        unsafe { sched::live::schedule::schedule(); }
                    }
                    #[cfg(not(target_os = "oxide-kernel"))]
                    return Err(vfs::VfsError::Eagain);
                }
                Err(_) => return Err(vfs::VfsError::Eio),
            }
        }
    }

    /// Read one immediately available VSOCK stream prefix. # C: O(buf len)
    pub fn read_nonblock(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        self.check_receive().map_err(|_| vfs::VfsError::Eacces)?;
        if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
        let Some(c) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        match vsock::recv(&c, buf) {
            Ok(n)  => Ok(n),
            Err(crate::NetError::Eagain) => {
                let eno = self.take_pending_recv_error();
                if eno != 0 { Err(vsock_vfs_error(eno)) } else { Err(vfs::VfsError::Eagain) }
            }
            Err(_) => Err(vfs::VfsError::Eio),
        }
    }

    /// Blocking stream write: OP_RW respecting peer credit; park on the
    /// conn's waiters until credit reopens (a peer CREDIT_UPDATE wakes us). # C: O(buf len) + waits
    pub fn write(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        self.check_send().map_err(|_| vfs::VfsError::Eacces)?;
        let Some(c) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        let mut sent = 0usize;
        while sent < buf.len() {
            #[cfg(target_os = "oxide-kernel")]
            let _ = vsock::poll_rx_for(c.owner);
            match vsock::send(&c, &buf[sent..]) {
                Ok(0)  => break,
                Ok(n)  => sent += n,
                Err(crate::NetError::Eagain) => {
                    if sent > 0 { break; }
                    #[cfg(test)]
                    if let Some(hook) = self.write_retry_hook.lock().take() { hook(self); }
                    if c.tx.lock().shut() { return Err(vfs::VfsError::Epipe); }
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        if sched::live::deliverable_signals_self() != 0 {
                            return Err(vfs::VfsError::Eintr);
                        }
                        let tx = c.tx.lock();
                        if tx.shut() { return Err(vfs::VfsError::Epipe); }
                        if tx.credit.peer_credit() > 0 { continue; }
                        // SAFETY: process ctx (VsockSocket::write); runqueue
                        // installed; preempt-off owned by the write syscall stub;
                        // a peer OP_CREDIT_UPDATE wakes c.waiters via deliver_rx.
                        unsafe { c.waiters.park(); }
                        drop(tx);
                        // SAFETY: current is parked on this connection's wait list.
                        unsafe { sched::live::schedule::schedule(); }
                    }
                    #[cfg(not(target_os = "oxide-kernel"))]
                    return Err(vfs::VfsError::Eagain);
                }
                Err(crate::NetError::Enotconn) => return Err(vfs::VfsError::Epipe),
                Err(crate::NetError::Epipe) => return Err(vfs::VfsError::Epipe),
                Err(_) => return Err(vfs::VfsError::Eio),
            }
        }
        Ok(sent)
    }

    /// Write one immediately admitted VSOCK stream prefix. # C: O(buf len)
    pub fn write_nonblock(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        self.check_send().map_err(|_| vfs::VfsError::Eacces)?;
        let Some(c) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        match vsock::send(&c, buf) {
            Ok(n)  => Ok(n),
            Err(crate::NetError::Eagain)  => Err(vfs::VfsError::Eagain),
            Err(crate::NetError::Enotconn) => Err(vfs::VfsError::Epipe),
            Err(crate::NetError::Epipe) => Err(vfs::VfsError::Epipe),
            Err(_) => Err(vfs::VfsError::Eio),
        }
    }

    /// Snapshot VSOCK readiness from canonical endpoint state. # C: O(1)
    pub fn poll(&self) -> u32 {
        use core::sync::atomic::Ordering::Acquire;
        use vfs::{POLL_ERR, POLL_IN, POLL_OUT, POLL_HUP, POLL_RDHUP};
        let read_shut = self.read_shut.load(Acquire);
        self.attach_poll_source();
        let kind = self.kind.lock();
        let pending = if self.has_pending_recv_error() { POLL_ERR } else { 0 };
        match &*kind {
            VsockKind::Conn(c) => {
                let mut mask = 0;
                let tx = c.tx.lock();
                let send_shut = tx.shut();
                let local_write_shut = tx.local_shut;
                let peer_credit = tx.credit.peer_credit();
                drop(tx);
                if !c.rx.lock().is_empty() || read_shut { mask |= POLL_IN; }
                match *c.st.lock() {
                    VsockState::Connected => {
                        if !send_shut && peer_credit > 0 { mask |= POLL_OUT; }
                    }
                    VsockState::RcvShutdown => {
                        mask |= POLL_IN | POLL_RDHUP;
                        if !send_shut && peer_credit > 0 { mask |= POLL_OUT; }
                        if local_write_shut { mask |= POLL_HUP; }
                    }
                    VsockState::Closed => { mask |= POLL_HUP; }
                    VsockState::Connecting => {}
                }
                if read_shut { mask |= POLL_RDHUP; }
                if read_shut && local_write_shut { mask |= POLL_HUP; }
                mask | pending
            }
            VsockKind::Listener(listener) => {
                (if !listener.backlog.lock().is_empty() { POLL_IN } else { 0 }) | pending
            }
            VsockKind::Init | VsockKind::Bound { .. } => POLL_OUT | pending,
            VsockKind::Released => POLL_HUP | pending,
        }
    }
}

fn vsock_vfs_error(errno: i32) -> vfs::VfsError {
    if errno == syscall::errno::Errno::Econnreset as i32 { vfs::VfsError::Econnreset }
    else if errno == syscall::errno::Errno::Econnrefused as i32 { vfs::VfsError::Econnrefused }
    else { vfs::VfsError::Eio }
}
