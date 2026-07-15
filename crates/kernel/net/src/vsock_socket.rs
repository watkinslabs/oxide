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

/// AF_VSOCK socket VFS state. # C: O(1)
pub struct VsockSocket {
    pub net_namespace: network_namespace::NetworkNamespaceRef,
    pub kind: Spinlock<VsockKind, SockLockClass>,
    released: core::sync::atomic::AtomicBool,
    pub so_type: core::sync::atomic::AtomicU8,
    /// Canonical Linux `sk_err`.
    pub error: crate::SocketError,
    /// SHUT_RD latch → read returns EOF.
    pub read_shut: core::sync::atomic::AtomicBool,
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
            released: core::sync::atomic::AtomicBool::new(false),
            so_type: core::sync::atomic::AtomicU8::new(typ as u8),
            error: crate::SocketError::new(),
            read_shut: core::sync::atomic::AtomicBool::new(false),
            poll_subs: Arc::new(vfs::PollSubscribers::new()),
        }
    }

    /// Build an accepted socket by cloning the listener's owner. # C: O(1)
    pub fn new_accepted(listener: &Self) -> Self {
        Self::new_type_in(listener.so_type.load(core::sync::atomic::Ordering::Acquire) as u32,
            listener.net_namespace.clone())
    }

    /// Derive the short-lived namespace table key. # C: O(1)
    pub fn net_ns(&self) -> u64 { crate::net_ns::namespace_id(&self.net_namespace) }

    /// Snapshot the live connection Arc if this socket is connected.
    /// # C: O(1)
    pub fn conn(&self) -> Option<Arc<VsockConn>> {
        match &*self.kind.lock() {
            VsockKind::Conn(c) => Some(c.clone()),
            _ => None,
        }
    }

    /// Record the latest positive Linux receive errno until it is consumed. # C: O(1)
    pub fn set_pending_recv_error(&self, errno: i32) -> bool {
        let conn = self.conn();
        let _rx = conn.as_ref().map(|c| c.rx.lock());
        let changed = self.error.set(errno);
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

    /// Tear down the endpoint at final open-file-description release. # C: O(N pending accepts)
    pub fn release_file(&self) {
        if self.released.swap(true, core::sync::atomic::Ordering::AcqRel) { return; }
        let kind = core::mem::replace(&mut *self.kind.lock(), VsockKind::Released);
        match kind {
            VsockKind::Listener(listener) => { let _ = vsock::TABLE.remove_listener_exact(&listener); }
            VsockKind::Conn(c) => vsock::close(&c),
            VsockKind::Init | VsockKind::Bound { .. } | VsockKind::Released => {}
        }
    }
}

impl Default for VsockSocket { fn default() -> Self { Self::new() } }

impl Drop for VsockSocket {
    fn drop(&mut self) { self.release_file(); }
}

/// Build the `Arc<Inode>` wrapping an AF_VSOCK socket fd. The socket lives in
/// `i_private` (recover it with [`vsock_from_inode`]); `ino()` carries
/// [`VSOCK_INO_TAG`] OR'd with the socket pointer's low bits. # C: O(1)
pub fn make_vsock_socket_inode(sock: Arc<VsockSocket>) -> vfs::InodeRef {
    let ino = VSOCK_INO_TAG | (Arc::as_ptr(&sock) as u64 & 0xFFFF_FFFF);
    vfs::InodeBuilder::new(ino, vfs::mk_mode(vfs::FileType::Regular, 0o600),
        vfs::default_inode_ops(), Arc::new(VsockFileOps))
        .private(sock)
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
    fn ioctl_int(&self, file: &vfs::File, cmd: vfs::IoctlIntCmd) -> vfs::KResult<u32> {
        let Some(s) = file.inode().private::<VsockSocket>() else { return Err(vfs::VfsError::Einval); };
        Ok(match cmd {
            vfs::IoctlIntCmd::Fionread => s.conn().map(|c| c.rx.lock().len() as u32).unwrap_or(0),
            vfs::IoctlIntCmd::Siocoutq => s.conn().map(|c| { let cr = c.credit.lock(); cr.tx_cnt.wrapping_sub(cr.peer_fwd_cnt) }).unwrap_or(0),
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

impl VsockSocket {
    /// Blocking stream read: drain buffered RX, park on the conn's
    /// waiters when empty + still live. EOF (Ok(0)) on peer shutdown.
    /// # C: backend-dependent
    pub fn read(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
        let Some(c) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        loop {
            #[cfg(target_os = "oxide-kernel")]
            let _ = vsock::poll_rx_for(c.owner);
            match vsock::recv(&c, buf) {
                Ok(n)  => return Ok(n),
                Err(crate::NetError::Eagain) => {
                    let eno = self.take_pending_recv_error();
                    if eno != 0 { return Err(vsock_vfs_error(eno)); }
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        if sched::live::deliverable_signals_self() != 0 {
                            return Err(vfs::VfsError::Eintr);
                        }
                        let rx = c.rx.lock();
                        if !rx.is_empty() || self.has_pending_recv_error() { continue; }
                        // SAFETY: process ctx (VsockSocket::read); runqueue
                        // installed; preempt-off owned by the read syscall stub;
                        // RX lock closes data/error publication before park.
                        unsafe { c.waiters.park(); }
                        drop(rx);
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

    pub fn read_nonblock(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
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
    /// conn's waiters until credit reopens (a peer CREDIT_UPDATE wakes us).
    pub fn write(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
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
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        if sched::live::deliverable_signals_self() != 0 {
                            return Err(vfs::VfsError::Eintr);
                        }
                        // SAFETY: process ctx (VsockSocket::write); runqueue
                        // installed; preempt-off owned by the write syscall stub;
                        // a peer OP_CREDIT_UPDATE wakes c.waiters via deliver_rx.
                        unsafe { c.waiters.park(); sched::live::schedule::schedule(); }
                    }
                    #[cfg(not(target_os = "oxide-kernel"))]
                    return Err(vfs::VfsError::Eagain);
                }
                Err(crate::NetError::Enotconn) => return Err(vfs::VfsError::Epipe),
                Err(_) => return Err(vfs::VfsError::Eio),
            }
        }
        Ok(sent)
    }

    pub fn write_nonblock(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        let Some(c) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        match vsock::send(&c, buf) {
            Ok(n)  => Ok(n),
            Err(crate::NetError::Eagain)  => Err(vfs::VfsError::Eagain),
            Err(crate::NetError::Enotconn) => Err(vfs::VfsError::Epipe),
            Err(_) => Err(vfs::VfsError::Eio),
        }
    }

    pub fn poll(&self) -> u32 {
        use vfs::{POLL_ERR, POLL_IN, POLL_OUT, POLL_HUP};
        let pending = if self.has_pending_recv_error() { POLL_ERR } else { 0 };
        match &*self.kind.lock() {
            VsockKind::Conn(c) => {
                let mut mask = 0;
                if !c.rx.lock().is_empty() { mask |= POLL_IN; }
                match *c.st.lock() {
                    VsockState::Connected => {
                        if c.credit.lock().peer_credit() > 0 { mask |= POLL_OUT; }
                    }
                    VsockState::RcvShutdown => { mask |= POLL_IN; }
                    VsockState::Closed => { mask |= POLL_HUP; }
                    VsockState::Connecting => {}
                }
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
