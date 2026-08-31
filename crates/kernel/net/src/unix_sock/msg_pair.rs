use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};

use vfs;

use super::wake_msgpair_peer_subs;
use super::{EndCred, GcNode, GcRights, UnixEnd};

mod wait;
mod endpoint;
mod receive;
pub use wait::{ArmMsgRead, ArmMsgReadAfter, ArmMsgWrite};

const ECONNRESET: i32 = syscall::errno::Errno::Econnreset as i32;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixMsgKind { Datagram, SeqPacket }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixMsgError { PeerClosed, PeerRefused }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixMsgSendError { PeerClosed, PeerRefused, WouldBlock, MessageTooLarge }

pub struct UnixMsgRing {
    pub msgs: VecDeque<UnixMsg>,
    pub closed_writer: bool,
    pub reader_shutdown: bool,
    pub shutdown_generation: u64,
    pub bytes: usize,
}

pub struct UnixMsgPair {
    pub kind: UnixMsgKind,
    pub a_to_b: Spinlock<UnixMsgRing, UnixLockClass>,
    pub b_to_a: Spinlock<UnixMsgRing, UnixLockClass>,
    pub a_to_b_waiters: crate::sock_wait::SockWaitQueue,
    pub b_to_a_waiters: crate::sock_wait::SockWaitQueue,
    pub a_to_b_writers: crate::sock_wait::SockWaitQueue,
    pub b_to_a_writers: crate::sock_wait::SockWaitQueue,
    error_a: Spinlock<Arc<crate::SocketError>, UnixLockClass>,
    error_b: Spinlock<Arc<crate::SocketError>, UnixLockClass>,
    filter_a: Spinlock<Arc<crate::bpf_filter::SocketFilter>, UnixLockClass>,
    filter_b: Spinlock<Arc<crate::bpf_filter::SocketFilter>, UnixLockClass>,
    /// Per-end creds for SO_PEERCRED / SCM_CREDENTIALS
    pub cred_a: EndCred,
    pub cred_b: EndCred,
    peer_gone_a: core::sync::atomic::AtomicBool,
    peer_gone_b: core::sync::atomic::AtomicBool,
    reset_pending_a: core::sync::atomic::AtomicBool,
    reset_pending_b: core::sync::atomic::AtomicBool,
    released_a: core::sync::atomic::AtomicBool,
    released_b: core::sync::atomic::AtomicBool,
    gc_a: GcNode,
    gc_b: GcNode,
}

pub struct UnixMsg {
    pub payload: Vec<u8>,
    pub fds: Vec<Arc<vfs::File>>,
    pub(crate) rights: Option<GcRights>,
    /// Sender (pid, uid, gid) captured at send time for SO_PASSCRED /
    /// SCM_CREDENTIALS. Per-MESSAGE (not the shared per-end cred slot) so a
    /// socketpair shared by many senders (systemd-udevd's worker_watch: all
    /// workers write one end) attributes each message to its true sender.
    pub creds: crate::unix_sock::MsgCred,
}

impl UnixMsg {
    /// Empty EOF/shutdown sentinel for syscall receive paths. # C: O(1)
    pub fn empty() -> Self { Self { payload: Vec::new(), fds: Vec::new(), rights: None, creds: Default::default() } }
}

impl UnixMsgPair {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        Self::new_kind(UnixMsgKind::SeqPacket)
    }

    /// Build a datagram socketpair with datagram close semantics.
    /// # C: O(1)
    pub fn new_datagram() -> Arc<Self> {
        Self::new_kind(UnixMsgKind::Datagram)
    }

    fn new_kind(kind: UnixMsgKind) -> Arc<Self> {
        Arc::new(Self {
            kind,
            a_to_b: Spinlock::new(UnixMsgRing { msgs: VecDeque::new(), closed_writer: false,
                reader_shutdown: false, shutdown_generation: 0, bytes: 0 }),
            b_to_a: Spinlock::new(UnixMsgRing { msgs: VecDeque::new(), closed_writer: false,
                reader_shutdown: false, shutdown_generation: 0, bytes: 0 }),
            a_to_b_waiters: crate::sock_wait::SockWaitQueue::new(),
            b_to_a_waiters: crate::sock_wait::SockWaitQueue::new(),
            a_to_b_writers: crate::sock_wait::SockWaitQueue::new(),
            b_to_a_writers: crate::sock_wait::SockWaitQueue::new(),
            error_a: Spinlock::new(Arc::new(crate::SocketError::new())),
            error_b: Spinlock::new(Arc::new(crate::SocketError::new())),
            filter_a: Spinlock::new(Arc::new(crate::bpf_filter::SocketFilter::new())),
            filter_b: Spinlock::new(Arc::new(crate::bpf_filter::SocketFilter::new())),
            cred_a: EndCred::new(),
            cred_b: EndCred::new(),
            peer_gone_a: core::sync::atomic::AtomicBool::new(false),
            peer_gone_b: core::sync::atomic::AtomicBool::new(false),
            reset_pending_a: core::sync::atomic::AtomicBool::new(false),
            reset_pending_b: core::sync::atomic::AtomicBool::new(false),
            released_a: core::sync::atomic::AtomicBool::new(false),
            released_b: core::sync::atomic::AtomicBool::new(false),
            gc_a: GcNode::new(),
            gc_b: GcNode::new(),
        })
    }

    /// Stable receive-queue identity for one endpoint. # C: O(1)
    pub fn gc_node(&self, end: UnixEnd) -> GcNode {
        match end { UnixEnd::A => self.gc_a.clone(), UnixEnd::B => self.gc_b.clone() }
    }

    /// Stamp `end`'s stable socketpair credentials.
    /// # C: O(1)
    pub fn set_end_cred(&self, end: crate::UnixEnd, cred: crate::PeerCred) {
        match end {
            crate::UnixEnd::A => self.cred_a.set(cred),
            crate::UnixEnd::B => self.cred_b.set(cred),
        }
    }

    /// Record the security label of the socket owning `end`.
    ///
    /// A datagram pair records both labels exactly as a stream pair does, and
    /// `SO_PEERSEC` still reports none for it: the socket's CLASS decides
    /// whether a peer label is reportable, not whether one was recorded.
    /// # C: O(1)
    pub fn set_end_sid(&self, end: crate::UnixEnd, sid: u32) {
        match end {
            crate::UnixEnd::A => self.cred_a.set_sid(sid),
            crate::UnixEnd::B => self.cred_b.set_sid(sid),
        }
    }

    /// The PEER's security label as seen from `end`. # C: O(1)
    pub fn peer_sid(&self, end: crate::UnixEnd) -> u32 {
        match end {
            crate::UnixEnd::A => self.cred_b.sid(),
            crate::UnixEnd::B => self.cred_a.sid(),
        }
    }

    /// Peer (sender) creds for the reader on `end`.
    /// # C: O(1)
    pub fn peer_cred(&self, end: crate::UnixEnd) -> crate::PeerCred {
        match end {
            crate::UnixEnd::A => self.cred_b.get(),
            crate::UnixEnd::B => self.cred_a.get(),
        }
    }

    /// Pin the identity of the process owning `end` (`SO_PEERPIDFD` source).
    /// # C: O(1)
    pub fn set_end_identity(&self, end: crate::UnixEnd, identity: Option<Arc<sched::pid::PidIdentity>>) {
        match end {
            crate::UnixEnd::A => self.cred_a.set_identity(identity),
            crate::UnixEnd::B => self.cred_b.set_identity(identity),
        }
    }

    /// The PEER's pinned identity as seen from `end`. # C: O(1)
    pub fn peer_identity(&self, end: crate::UnixEnd) -> Option<Arc<sched::pid::PidIdentity>> {
        match end {
            crate::UnixEnd::A => self.cred_b.identity(),
            crate::UnixEnd::B => self.cred_a.identity(),
        }
    }

    /// F181a: register an end's subscribers (mirrors `UnixPair`).
    /// # C: O(1)

    /// WaitList the reader of `end` should park on.
    /// # C: O(1)
    pub fn reader_waiters(&self, end: UnixEnd) -> &crate::sock_wait::SockWaitQueue {
        match end {
            UnixEnd::A => &self.b_to_a_waiters,
            UnixEnd::B => &self.a_to_b_waiters,
        }
    }

    /// Enqueue one message from `end` into the ring it writes to.
    /// # C: O(payload.len())
    pub fn send(&self, end: UnixEnd, payload: &[u8]) -> Result<usize, UnixMsgError> {
        self.send_bounded(end, payload, usize::MAX).map_err(legacy_error)
    }

    /// Enqueue one atomic record under a sender queue cap. # C: O(payload.len())
    pub fn send_bounded(&self, end: UnixEnd, payload: &[u8], cap: usize) -> Result<usize, UnixMsgSendError> {
        self.send_with_rights_inner(end, payload, GcRights::from_files(Vec::new()), None, cap)
    }

    /// Enqueue one message plus SCM_RIGHTS files from `end`.
    /// # C: O(payload.len())
    pub fn send_with_fds(&self, end: UnixEnd, payload: &[u8], fds: Vec<Arc<vfs::File>>) -> Result<usize, UnixMsgError> {
        self.send_with_rights(end, payload, GcRights::from_files(fds))
    }

    /// Enqueue one message with a classified canonical rights batch. # C: O(payload + rights)
    pub fn send_with_rights(&self, end: UnixEnd, payload: &[u8], rights: GcRights) -> Result<usize, UnixMsgError> {
        self.send_with_rights_inner(end, payload, rights, None, usize::MAX).map_err(legacy_error)
    }

    /// Enqueue one rights-bearing atomic record under a sender queue cap. # C: O(payload + rights)
    pub fn send_with_rights_bounded(&self, end: UnixEnd, payload: &[u8], rights: GcRights,
        cap: usize) -> Result<usize, UnixMsgSendError>
    { self.send_with_rights_inner(end, payload, rights, None, cap) }

    /// Enqueue rights with an explicitly validated SCM_CREDENTIALS record. # C: O(payload + rights)
    pub fn send_with_rights_and_creds(&self, end: UnixEnd, payload: &[u8], rights: GcRights,
        creds: (u32, u32, u32)) -> Result<usize, UnixMsgError>
    {
        self.send_with_rights_inner(end, payload, rights, Some(creds), usize::MAX).map_err(legacy_error)
    }

    /// Enqueue one credential-bearing atomic record under a sender queue cap. # C: O(payload + rights)
    pub fn send_with_rights_and_creds_bounded(&self, end: UnixEnd, payload: &[u8], rights: GcRights,
        creds: (u32, u32, u32), cap: usize) -> Result<usize, UnixMsgSendError>
    { self.send_with_rights_inner(end, payload, rights, Some(creds), cap) }

    fn send_with_rights_inner(&self, end: UnixEnd, payload: &[u8], rights: GcRights,
        supplied_creds: Option<(u32, u32, u32)>, cap: usize) -> Result<usize, UnixMsgSendError>
    {
        let sent = payload.len();
        if message_charge(sent) > cap {
            drop(rights);
            super::collect_scm_rights();
            return Err(UnixMsgSendError::MessageTooLarge);
        }
        let verdict = self.end_filter(end.other()).verdict(payload);
        if verdict == 0 {
            drop(rights);
            super::collect_scm_rights();
            return Ok(sent);
        }
        let payload = &payload[..payload.len().min(verdict as usize)];
        // Capture the SENDER's creds per-message (SO_PASSCRED) BEFORE the ring
        // lock: resolving the sender's identity walks the task registry, which
        // must never be entered with a socket queue held.
        let creds = match supplied_creds {
            Some(ids) => crate::unix_sock::MsgCred::from_supplied(ids),
            None => crate::unix_sock::MsgCred::of_current((0, 0, 0)),
        };
        let receiver = self.gc_node(end.other());
        let transition = receiver.pin();
        rights.register(&receiver);
        let mut g = match end {
            UnixEnd::A => self.a_to_b.lock(),
            UnixEnd::B => self.b_to_a.lock(),
        };
        if self.peer_gone(end) {
            return Err(if self.kind == UnixMsgKind::Datagram { UnixMsgSendError::PeerRefused } else { UnixMsgSendError::PeerClosed });
        }
        if g.closed_writer || g.reader_shutdown { return Err(UnixMsgSendError::PeerClosed); }
        let charge = message_charge(payload.len());
        if g.bytes.saturating_add(charge) > cap { return Err(UnixMsgSendError::WouldBlock); }
        g.msgs.push_back(UnixMsg { payload: payload.to_vec(), fds: Vec::new(), rights: Some(rights), creds });
        g.bytes += charge;
        let n = sent;
        drop(g);
        drop(transition);
                // Ungated: the hosted suite must be able to prove this wake fires.
        let waiters = match end {
            UnixEnd::A => &self.a_to_b_waiters,
            UnixEnd::B => &self.b_to_a_waiters,
        };
        waiters.wake_all();
        wake_msgpair_peer_subs(self, end, vfs::POLL_IN);
        Ok(n)
    }

}

fn message_charge(len: usize) -> usize { len.max(1) }

fn legacy_error(error: UnixMsgSendError) -> UnixMsgError {
    match error {
        UnixMsgSendError::PeerClosed => UnixMsgError::PeerClosed,
        UnixMsgSendError::PeerRefused => UnixMsgError::PeerRefused,
        UnixMsgSendError::WouldBlock | UnixMsgSendError::MessageTooLarge => UnixMsgError::PeerClosed,
    }
}
