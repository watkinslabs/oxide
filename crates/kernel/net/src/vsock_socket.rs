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
    /// `connect()` succeeded or `accept()` produced this — live stream.
    Conn(Arc<VsockConn>),
    /// `bind()`+`listen()` — accepts inbound OP_REQUESTs on `port`.
    Listener(u32),
}

/// AF_VSOCK socket VFS state. # C: O(1)
pub struct VsockSocket {
    pub kind: Spinlock<VsockKind, SockLockClass>,
    /// SHUT_RD latch → read returns EOF.
    pub read_shut: core::sync::atomic::AtomicBool,
    pub poll_subs: Arc<vfs::PollSubscribers>,
}

impl VsockSocket {
    /// `socket(AF_VSOCK, SOCK_STREAM, 0)`. # C: O(1)
    pub fn new() -> Self {
        VsockSocket {
            kind: Spinlock::new(VsockKind::Init),
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
}

impl Default for VsockSocket { fn default() -> Self { Self::new() } }

impl vfs::Inode for VsockSocket {
    fn ino(&self) -> vfs::Ino {
        VSOCK_INO_TAG | (self as *const _ as u64 & 0xFFFF_FFFF) as vfs::Ino
    }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn poll_subscribers(&self) -> Option<&vfs::PollSubscribers> { Some(self.poll_subs.as_ref()) }

    /// Blocking stream read: drain buffered RX, park on the conn's
    /// waiters when empty + still live. EOF (Ok(0)) on peer shutdown.
    fn read(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
        let Some(c) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        loop {
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

    fn read_nonblock(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
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
    fn write(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        let Some(c) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        let mut sent = 0usize;
        while sent < buf.len() {
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

    fn write_nonblock(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        let Some(c) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        match vsock::send(&c, buf) {
            Ok(n)  => Ok(n),
            Err(crate::NetError::Eagain)  => Err(vfs::VfsError::Eagain),
            Err(crate::NetError::Enotconn) => Err(vfs::VfsError::Epipe),
            Err(_) => Err(vfs::VfsError::Eio),
        }
    }

    fn poll(&self) -> u32 {
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
            VsockKind::Listener(port) => {
                if vsock::TABLE.pop_accept_peek(*port) { POLL_IN } else { 0 }
            }
            VsockKind::Init => POLL_OUT,
        }
    }
}
