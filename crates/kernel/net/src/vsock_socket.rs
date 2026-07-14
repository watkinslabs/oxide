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
    /// `bind()`+`listen()` — accepts inbound OP_REQUESTs on `port`.
    /// None means VMADDR_CID_ANY.
    Listener { port: u32, owner: Option<vsock::VsockOwner> },
}

/// AF_VSOCK socket VFS state. # C: O(1)
pub struct VsockSocket {
    pub kind: Spinlock<VsockKind, SockLockClass>,
    pub so_type: core::sync::atomic::AtomicU8,
    /// Socket-owned pending receive error, stored as a positive Linux errno.
    pending_recv_error: core::sync::atomic::AtomicI32,
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
        VsockSocket {
            kind: Spinlock::new(VsockKind::Init),
            so_type: core::sync::atomic::AtomicU8::new(typ as u8),
            pending_recv_error: core::sync::atomic::AtomicI32::new(0),
            read_shut: core::sync::atomic::AtomicBool::new(false),
            poll_subs: Arc::new(vfs::PollSubscribers::new()),
        }
    }

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
        if errno <= 0 { return false; }
        self.pending_recv_error.store(errno, core::sync::atomic::Ordering::Release);
        true
    }

    /// Consume the pending positive Linux receive errno, or zero. # C: O(1)
    pub fn take_pending_recv_error(&self) -> i32 {
        self.pending_recv_error.swap(0, core::sync::atomic::Ordering::AcqRel)
    }

    /// Observe whether a receive error is pending without consuming it. # C: O(1)
    pub fn has_pending_recv_error(&self) -> bool {
        self.pending_recv_error.load(core::sync::atomic::Ordering::Acquire) != 0
    }
}

impl Default for VsockSocket { fn default() -> Self { Self::new() } }

impl Drop for VsockSocket {
    fn drop(&mut self) {
        match &*self.kind.lock() {
            VsockKind::Listener { port, owner } => {
                let _ = vsock::TABLE.remove_listener(*owner, *port);
            }
            VsockKind::Conn(c) => {
                vsock::close(c);
            }
            VsockKind::Init | VsockKind::Bound { .. } => {}
        }
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vsock::{ConnKey, VsockState};

    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn owner(raw: u32) -> vsock::VsockOwner {
        vsock::VsockOwner::from_raw(raw).expect("test owner is nonzero")
    }

    #[test]
    fn drop_listener_removes_vsock_listener() {
        let _guard = SERIAL.lock().unwrap();
        let owner = Some(owner(0x0a00_0001));
        let port = 61_001;
        let _ = vsock::TABLE.remove_listener(owner, port);
        vsock::TABLE.add_listener(owner, port);
        let key = ConnKey {
            owner: owner.expect("concrete test owner"),
            local_cid: 3,
            local_port: port,
            peer_cid: 2,
            peer_port: 1024,
        };
        vsock::TABLE.remove(key);
        let conn = Arc::new(VsockConn::new(
            owner.expect("concrete test owner"),
            key.local_cid,
            key.local_port,
            key.peer_cid,
            key.peer_port,
            VsockState::Connected,
        ));
        vsock::TABLE.insert(conn.clone());
        vsock::TABLE.queue_accept(owner.expect("concrete test owner"), port, key);
        assert!(vsock::TABLE.is_listening(owner.expect("concrete test owner"), port));
        assert!(vsock::TABLE.pop_accept_peek(owner, port));

        let sock = Arc::new(VsockSocket::new());
        *sock.kind.lock() = VsockKind::Listener { port, owner };
        drop(sock);

        assert!(!vsock::TABLE.is_listening(owner.expect("concrete test owner"), port));
        assert_eq!(*conn.st.lock(), VsockState::Closed);
        assert!(vsock::TABLE.find(key).is_none());
        assert!(!vsock::TABLE.remove_listener(owner, port));
    }

    #[test]
    fn drop_connected_socket_closes_connection_record() {
        let _guard = SERIAL.lock().unwrap();
        let owner = owner(0x0a00_0002);
        let key = ConnKey {
            owner,
            local_cid: 3,
            local_port: 61_002,
            peer_cid: 2,
            peer_port: 1024,
        };
        vsock::TABLE.remove(key);
        let conn = Arc::new(VsockConn::new(
            owner,
            key.local_cid,
            key.local_port,
            key.peer_cid,
            key.peer_port,
            VsockState::Connected,
        ));
        vsock::TABLE.insert(conn.clone());
        assert!(vsock::TABLE.find(key).is_some());

        let sock = Arc::new(VsockSocket::new());
        *sock.kind.lock() = VsockKind::Conn(conn.clone());
        drop(sock);

        assert_eq!(*conn.st.lock(), VsockState::Closed);
        assert!(vsock::TABLE.find(key).is_none());
    }

    #[test]
    fn pending_recv_error_overwrites_with_latest_positive_errno() {
        let sock = VsockSocket::new();
        assert_eq!(sock.take_pending_recv_error(), 0);
        assert!(!sock.set_pending_recv_error(0));
        assert!(!sock.set_pending_recv_error(-5));
        assert!(sock.set_pending_recv_error(111));
        assert!(sock.set_pending_recv_error(104));
        assert_eq!(sock.take_pending_recv_error(), 104);
        assert_eq!(sock.take_pending_recv_error(), 0);
    }
}

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
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        if sched::live::deliverable_signals_self() != 0 {
                            return Err(vfs::VfsError::Eintr);
                        }
                        // SAFETY: process ctx (VsockSocket::read); runqueue
                        // installed; preempt-off owned by the read syscall stub;
                        // the driver RX drain wakes c.waiters after pushing data.
                        unsafe { c.waiters.park(); sched::live::schedule::schedule(); }
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
            Err(crate::NetError::Eagain) => Err(vfs::VfsError::Eagain),
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
        use vfs::{POLL_IN, POLL_OUT, POLL_HUP};
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
                mask
            }
            VsockKind::Listener { port, owner } => {
                if vsock::TABLE.pop_accept_peek(*owner, *port) { POLL_IN } else { 0 }
            }
            VsockKind::Init | VsockKind::Bound { .. } => POLL_OUT,
        }
    }
}
