// Module manifest: lifecycle owns bind/connect/teardown, io owns payload I/O,
// and file_ops owns inode and VFS adaptation.
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

/// Immutable AF_VSOCK protocol personality selected by `socket(2)`.
/// This is distinct from [`VsockKind`]: the latter is a mutable lifecycle
/// state, while the socket type never changes after creation. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VsockSocketType {
    Datagram,
    Stream,
    Seqpacket,
}

impl VsockSocketType {
    /// Decode one already UAPI-validated `SOCK_*` value. # C: O(1)
    fn from_uapi(typ: u32) -> Self {
        match typ {
            crate::socket_args::SOCK_DGRAM => Self::Datagram,
            crate::socket_args::SOCK_STREAM => Self::Stream,
            crate::socket_args::SOCK_SEQPACKET => Self::Seqpacket,
            _ => unreachable!("AF_VSOCK constructor received an unvalidated socket type"),
        }
    }

    /// Connection-oriented VSOCK types share stream-style lifecycle ownership.
    /// # C: O(1)
    pub const fn is_connectible(self) -> bool {
        matches!(self, Self::Stream | Self::Seqpacket)
    }

    /// Virtio connection personality, if this type has a connection transport.
    /// # C: O(1)
    pub const fn connection_transport(self) -> Option<vsock::VsockTransportType> {
        match self {
            Self::Datagram => None,
            Self::Stream => Some(vsock::VsockTransportType::Stream),
            Self::Seqpacket => Some(vsock::VsockTransportType::Seqpacket),
        }
    }
}

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
    socket_type: VsockSocketType,
    pub kind: Spinlock<VsockKind, SockLockClass>,
    binding: Spinlock<VsockBinding, SockLockClass>,
    released: core::sync::atomic::AtomicBool,
    pub so_type: core::sync::atomic::AtomicU8,
    /// AF_VSOCK transport buffer policy, in bytes. These are socket-owned
    /// Linux SOL_VSOCK values; the transport consumes them when attached.
    pub buffer_size: core::sync::atomic::AtomicU64,
    pub buffer_min_size: core::sync::atomic::AtomicU64,
    pub buffer_max_size: core::sync::atomic::AtomicU64,
    /// Linux SOL_VSOCK connect timeout in nanoseconds.
    pub connect_timeout_ns: core::sync::atomic::AtomicU64,
    /// Canonical Linux `sk_err`.
    pub error: crate::SocketError,
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    /// SHUT_RD latch → read returns EOF.
    pub read_shut: core::sync::atomic::AtomicBool,
    /// AF_VSOCK SOCK_DGRAM local `SHUT_WR` latch. Connectible sockets retain
    /// their send-shutdown state in the connection's canonical TX owner.
    dgram_write_shut: core::sync::atomic::AtomicBool,
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
            socket_type: VsockSocketType::from_uapi(typ),
            kind: Spinlock::new(VsockKind::Init),
            binding: Spinlock::new(VsockBinding::None),
            released: core::sync::atomic::AtomicBool::new(false),
            so_type: core::sync::atomic::AtomicU8::new(typ as u8),
            buffer_size: core::sync::atomic::AtomicU64::new(crate::uapi::VSOCK_DEFAULT_BUFFER_SIZE),
            buffer_min_size: core::sync::atomic::AtomicU64::new(crate::uapi::VSOCK_DEFAULT_BUFFER_MIN_SIZE),
            buffer_max_size: core::sync::atomic::AtomicU64::new(crate::uapi::VSOCK_DEFAULT_BUFFER_MAX_SIZE),
            connect_timeout_ns: core::sync::atomic::AtomicU64::new(vsock::VSOCK_CONNECT_TIMEOUT_NS),
            error: crate::SocketError::new(),
            bpf_filter: Arc::new(crate::bpf_filter::SocketFilter::new()),
            read_shut: core::sync::atomic::AtomicBool::new(false),
            dgram_write_shut: core::sync::atomic::AtomicBool::new(false),
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
        child.buffer_size.store(listener.buffer_size.load(core::sync::atomic::Ordering::Acquire),
            core::sync::atomic::Ordering::Release);
        child.buffer_min_size.store(listener.buffer_min_size.load(core::sync::atomic::Ordering::Acquire),
            core::sync::atomic::Ordering::Release);
        child.buffer_max_size.store(listener.buffer_max_size.load(core::sync::atomic::Ordering::Acquire),
            core::sync::atomic::Ordering::Release);
        child.connect_timeout_ns.store(listener.connect_timeout_ns.load(core::sync::atomic::Ordering::Acquire),
            core::sync::atomic::Ordering::Release);
        child
    }

    /// Admit an accept and snapshot its exact listener owner. # C: O(1)
    pub fn listener_for_accept(&self) -> Result<Arc<vsock::Listener>, crate::NetError> {
        crate::security_admission::check(self.net_ns(), crate::socket_args::AF_VSOCK as u16,
            security::network::Operation::Accept)?;
        match &*self.kind.lock() {
            VsockKind::Listener(listener) => Ok(listener.clone()),
            _ => return Err(crate::NetError::Einval),
        }
    }

    /// Consume one exact listener backlog child and build its accepted socket. # C: O(N)
    pub fn accept(&self) -> Result<Arc<Self>, crate::NetError> {
        let listener = self.listener_for_accept()?;
        let conn = vsock::TABLE.pop_accept_exact(&listener).ok_or(crate::NetError::Eagain)?;
        conn.set_local_buf_alloc(self.advertised_buffer_size());
        let child = Arc::new(Self::new_accepted_with_filter(self, conn.bpf_filter.clone()));
        *child.kind.lock() = VsockKind::Conn(conn);
        Ok(child)
    }

    /// Derive the short-lived namespace table key. # C: O(1)
    pub fn net_ns(&self) -> u64 { crate::net_ns::namespace_id(&self.net_namespace) }

    /// Socket protocol personality retained from `socket(2)`. # C: O(1)
    pub const fn socket_type(&self) -> VsockSocketType { self.socket_type }

    /// True only for the independently-owned datagram transport. # C: O(1)
    pub const fn is_datagram(&self) -> bool { matches!(self.socket_type, VsockSocketType::Datagram) }

    /// Reduce the socket's UAPI-sized policy to the u32 virtio wire field.
    /// Linux virtio-vsock performs the same transport-specific clamp. # C: O(1)
    pub(crate) fn advertised_buffer_size(&self) -> u32 {
        self.buffer_size.load(core::sync::atomic::Ordering::Acquire)
            .min(u32::MAX as u64) as u32
    }

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

    /// Check the retained namespace before inspecting or mutating VSOCK options. # C: O(1)
    pub fn check_option(&self) -> Result<(), crate::NetError> {
        crate::security_admission::check(
            self.net_ns(), crate::socket_args::AF_VSOCK as u16,
            security::network::Operation::Option,
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
        Ok(match &*self.kind.lock() {
            VsockKind::Init => (vsock::VMADDR_PORT_ANY, vsock::VMADDR_CID_ANY),
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
mod io;
mod file_ops;
mod shutdown;
pub use file_ops::{make_vsock_socket_inode, vsock_arc_from_inode, vsock_from_inode};

impl Default for VsockSocket { fn default() -> Self { Self::new() } }

impl Drop for VsockSocket {
    fn drop(&mut self) { self.release_file(); }
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

#[cfg(test)]
#[path = "vsock_socket/listen_tests.rs"]
mod listen_tests;

impl VsockSocket {
    /// Blocking stream read: drain buffered RX, park on the conn's
    /// waiters when empty + still live. EOF (Ok(0)) on peer shutdown.
    /// # C: backend-dependent
    pub fn read(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        if self.socket_type() == VsockSocketType::Seqpacket {
            return self.read_seqpacket(buf, false);
        }
        self.check_receive().map_err(|_| vfs::VfsError::Eacces)?;
        if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
        if self.is_datagram() { return Err(vfs::VfsError::Eopnotsupp); }
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
                        // Linux `vsock_connectible_recvmsg` (`af_vsock.c:2384`):
                        // `err = sock_intr_errno(timeout);`.
                        // NOTE: AF_VSOCK carries no SO_RCVTIMEO/SO_SNDTIMEO here (`VsockSocket` has
                        // no timeo fields), so the wait is always untimed and `sock_intr_errno`
                        // necessarily yields ERESTARTSYS. Linux DOES honour them on this path
                        // (`af_vsock.c:2267` send, `:2384` recv, both off sock_{snd,rcv}timeo);
                        // wiring those options is a separate gap, tracked in the plan.
                        if sched::live::deliverable_signals_self() != 0 {
                            return Err(crate::sock_intr::sock_intr_vfs(
                                crate::sock_intr::NO_TIMEOUT));
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
        if self.socket_type() == VsockSocketType::Seqpacket {
            return self.read_seqpacket(buf, true);
        }
        self.check_receive().map_err(|_| vfs::VfsError::Eacces)?;
        if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
        if self.is_datagram() { return Err(vfs::VfsError::Eopnotsupp); }
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

    /// Snapshot VSOCK readiness from canonical endpoint state. # C: O(1)
    pub fn poll(&self) -> u32 {
        use core::sync::atomic::Ordering::Acquire;
        use vfs::{POLL_ERR, POLL_IN, POLL_OUT, POLL_HUP, POLL_RDHUP};
        let read_shut = self.read_shut.load(Acquire);
        self.attach_poll_source();
        if self.is_datagram() {
            let write_shut = self.dgram_write_shut.load(Acquire);
            let mut mask = if read_shut { POLL_IN | POLL_RDHUP } else { 0 };
            if !write_shut { mask |= POLL_OUT; }
            if read_shut && write_shut { mask |= POLL_HUP; }
            return if self.has_pending_recv_error() { mask | POLL_ERR } else { mask };
        }
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
                let readable = if self.socket_type() == VsockSocketType::Seqpacket {
                    c.seq_rx.lock().ready_count() != 0
                } else { !c.rx.lock().is_empty() };
                if readable || read_shut { mask |= POLL_IN; }
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
