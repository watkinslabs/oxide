use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};

use sched;
use vfs;

#[cfg(target_os = "oxide-kernel")]
use super::wake_msgpair_peer_subs;
use super::{EndCred, GcNode, GcRights, UnixEnd};

const ECONNRESET: i32 = syscall::errno::Errno::Econnreset as i32;

#[cfg(target_os = "oxide-kernel")]
pub enum ArmMsgRead { Retry, Reset, Eof, Parked { reader_shutdown: bool } }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixMsgKind { Datagram, SeqPacket }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixMsgError { PeerClosed, PeerRefused }

pub struct UnixMsgRing {
    pub msgs: VecDeque<UnixMsg>,
    pub closed_writer: bool,
    pub reader_shutdown: bool,
}

pub struct UnixMsgPair {
    pub kind: UnixMsgKind,
    pub a_to_b: Spinlock<UnixMsgRing, UnixLockClass>,
    pub b_to_a: Spinlock<UnixMsgRing, UnixLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub a_to_b_waiters: sched::live::WaitList,
    #[cfg(target_os = "oxide-kernel")]
    pub b_to_a_waiters: sched::live::WaitList,
    /// F181a: per-end epoll subscribers — see `UnixPair`.
    pub end_a_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    pub end_b_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    error_a: Spinlock<Arc<crate::SocketError>, UnixLockClass>,
    error_b: Spinlock<Arc<crate::SocketError>, UnixLockClass>,
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
    pub creds: (u32, u32, u32),
}

impl UnixMsg {
    /// Empty EOF/shutdown sentinel for syscall receive paths. # C: O(1)
    pub fn empty() -> Self { Self { payload: Vec::new(), fds: Vec::new(), rights: None, creds: (0, 0, 0) } }
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
            a_to_b: Spinlock::new(UnixMsgRing { msgs: VecDeque::new(), closed_writer: false, reader_shutdown: false }),
            b_to_a: Spinlock::new(UnixMsgRing { msgs: VecDeque::new(), closed_writer: false, reader_shutdown: false }),
            #[cfg(target_os = "oxide-kernel")]
            a_to_b_waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            b_to_a_waiters: sched::live::WaitList::new(),
            end_a_subs: Spinlock::new(None),
            end_b_subs: Spinlock::new(None),
            error_a: Spinlock::new(Arc::new(crate::SocketError::new())),
            error_b: Spinlock::new(Arc::new(crate::SocketError::new())),
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
    pub fn set_end_cred(&self, end: crate::UnixEnd, pid: u32, uid: u32, gid: u32) {
        match end {
            crate::UnixEnd::A => self.cred_a.set(pid, uid, gid),
            crate::UnixEnd::B => self.cred_b.set(pid, uid, gid),
        }
    }

    /// Peer (sender) creds for the reader on `end`.
    /// # C: O(1)
    pub fn peer_cred(&self, end: crate::UnixEnd) -> (u32, u32, u32) {
        match end {
            crate::UnixEnd::A => self.cred_b.get(),
            crate::UnixEnd::B => self.cred_a.get(),
        }
    }

    /// F181a: register an end's subscribers (mirrors `UnixPair`).
    /// # C: O(1)
    pub fn register_end_subs(&self, end: UnixEnd, subs: &Arc<vfs::PollSubscribers>) {
        let slot = match end {
            UnixEnd::A => &self.end_a_subs,
            UnixEnd::B => &self.end_b_subs,
        };
        *slot.lock() = Some(Arc::downgrade(subs));
    }

    /// Share the bound InetSocket's canonical error state with this endpoint. # C: O(1)
    pub fn attach_end_error(&self, end: UnixEnd, error: &Arc<crate::SocketError>) {
        *self.error_slot(end).lock() = error.clone();
    }

    /// Canonical error state allocated for an endpoint not yet bound to a socket. # C: O(1)
    pub fn end_error(&self, end: UnixEnd) -> Arc<crate::SocketError> {
        self.error_slot(end).lock().clone()
    }

    fn error_slot(&self, end: UnixEnd) -> &Spinlock<Arc<crate::SocketError>, UnixLockClass> {
        match end { UnixEnd::A => &self.error_a, UnixEnd::B => &self.error_b }
    }

    /// WaitList the reader of `end` should park on.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn reader_waiters(&self, end: UnixEnd) -> &sched::live::WaitList {
        match end {
            UnixEnd::A => &self.b_to_a_waiters,
            UnixEnd::B => &self.a_to_b_waiters,
        }
    }

    /// Atomically recheck a message receive and park the caller.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_read(&self, end: UnixEnd, deadline_ns: u64) -> ArmMsgRead {
        let g = match end { UnixEnd::A => self.b_to_a.lock(), UnixEnd::B => self.a_to_b.lock() };
        if !g.msgs.is_empty() { return ArmMsgRead::Retry; }
        if self.reset_pending(end) { return ArmMsgRead::Reset; }
        if self.kind == UnixMsgKind::SeqPacket && (g.reader_shutdown || g.closed_writer) { return ArmMsgRead::Eof; }
        // SAFETY: process context; registration occurs under the queue lock
        // also acquired by send, shutdown, and release before their wake.
        let reader_shutdown = g.reader_shutdown;
        unsafe { self.reader_waiters(end).park_interruptible_with_deadline(deadline_ns); }
        drop(g);
        ArmMsgRead::Parked { reader_shutdown }
    }

    /// Enqueue one message from `end` into the ring it writes to.
    /// # C: O(payload.len())
    pub fn send(&self, end: UnixEnd, payload: &[u8]) -> Result<usize, UnixMsgError> {
        self.send_with_fds(end, payload, Vec::new())
    }

    /// Enqueue one message plus SCM_RIGHTS files from `end`.
    /// # C: O(payload.len())
    pub fn send_with_fds(&self, end: UnixEnd, payload: &[u8], fds: Vec<Arc<vfs::File>>) -> Result<usize, UnixMsgError> {
        self.send_with_rights(end, payload, GcRights::from_files(fds))
    }

    /// Enqueue one message with a classified canonical rights batch. # C: O(payload + rights)
    pub fn send_with_rights(&self, end: UnixEnd, payload: &[u8], rights: GcRights) -> Result<usize, UnixMsgError> {
        self.send_with_rights_inner(end, payload, rights, None)
    }

    /// Enqueue rights with an explicitly validated SCM_CREDENTIALS record. # C: O(payload + rights)
    pub fn send_with_rights_and_creds(&self, end: UnixEnd, payload: &[u8], rights: GcRights,
        creds: (u32, u32, u32)) -> Result<usize, UnixMsgError>
    {
        self.send_with_rights_inner(end, payload, rights, Some(creds))
    }

    fn send_with_rights_inner(&self, end: UnixEnd, payload: &[u8], rights: GcRights,
        supplied_creds: Option<(u32, u32, u32)>) -> Result<usize, UnixMsgError>
    {
        let receiver = self.gc_node(end.other());
        let transition = receiver.pin();
        rights.register(&receiver);
        let mut g = match end {
            UnixEnd::A => self.a_to_b.lock(),
            UnixEnd::B => self.b_to_a.lock(),
        };
        if self.peer_gone(end) {
            return Err(if self.kind == UnixMsgKind::Datagram { UnixMsgError::PeerRefused } else { UnixMsgError::PeerClosed });
        }
        if g.closed_writer || g.reader_shutdown { return Err(UnixMsgError::PeerClosed); }
        // Capture the SENDER's creds per-message (SO_PASSCRED). Hosted tests
        // have no `current()`; default to zero there.
        #[cfg(target_os = "oxide-kernel")]
        let creds = supplied_creds.unwrap_or_else(|| sched::live::current()
            .map(|c| (
                c.visible_pid(),
                c.creds.ruid.load(core::sync::atomic::Ordering::Relaxed),
                c.creds.rgid.load(core::sync::atomic::Ordering::Relaxed),
            ))
            .unwrap_or((0, 0, 0)));
        #[cfg(not(target_os = "oxide-kernel"))]
        let creds = supplied_creds.unwrap_or((0u32, 0u32, 0u32));
        g.msgs.push_back(UnixMsg { payload: payload.to_vec(), fds: Vec::new(), rights: Some(rights), creds });
        let n = payload.len();
        drop(g);
        drop(transition);
        #[cfg(target_os = "oxide-kernel")]
        {
            let waiters = match end {
                UnixEnd::A => &self.a_to_b_waiters,
                UnixEnd::B => &self.b_to_a_waiters,
            };
            waiters.wake_all();
            wake_msgpair_peer_subs(self, end, vfs::POLL_IN);
        }
        Ok(n)
    }

    /// Dequeue one message from the ring `end` reads from. Returns
    /// `Some(bytes)` truncated to `max`; `None` if empty.
    /// # C: O(min(max, payload.len()))
    pub fn recv(&self, end: UnixEnd, max: usize) -> Option<Vec<u8>> {
        self.recv_msg(end, max).map(|msg| {
            let UnixMsg { payload, fds, .. } = msg;
            drop(fds);
            super::collect_scm_rights();
            payload
        })
    }

    /// Inspect one record under its queue lock. Non-peek callbacks consume the
    /// record on success or failure; peek callbacks never consume it. # C: O(max + rights)
    pub fn recv_msg_with<R, E>(&self, end: UnixEnd, max: usize, peek: bool,
        copy: impl FnOnce(&[u8], usize, (u32, u32, u32), usize) -> Result<R, E>)
        -> Result<Option<(R, UnixMsg, usize)>, E>
    {
        let mut g = match end { UnixEnd::A => self.b_to_a.lock(), UnixEnd::B => self.a_to_b.lock() };
        let Some(front) = g.msgs.front() else {
            if self.kind == UnixMsgKind::SeqPacket && self.reset_pending(end) { return Ok(None); }
            if self.kind == UnixMsgKind::SeqPacket && (g.closed_writer || g.reader_shutdown) {
                let copied = copy(&[], 0, (0, 0, 0), 0)?;
                return Ok(Some((copied, UnixMsg::empty(), 0)));
            }
            return Ok(None);
        };
        let full_len = front.payload.len();
        let payload = front.payload[..core::cmp::min(max, full_len)].to_vec();
        let rights_len = front.rights.as_ref().map(GcRights::len).unwrap_or(front.fds.len());
        let creds = front.creds;
        let copied = match copy(&payload, rights_len, creds, full_len) {
            Ok(copied) => copied,
            Err(err) => {
                let dropped = if peek { None } else { g.msgs.pop_front() };
                drop(g);
                drop(dropped);
                if !peek { super::collect_scm_rights(); }
                return Err(err);
            }
        };
        let mut msg = if peek {
            let fds = front.rights.as_ref().map(GcRights::clone_files).unwrap_or_else(|| front.fds.clone());
            UnixMsg { payload, fds, rights: None, creds }
        } else {
            g.msgs.pop_front().unwrap()
        };
        drop(g);
        if let Some(rights) = msg.rights.take() { msg.fds = rights.take_files(); }
        if msg.payload.len() > max { msg.payload.truncate(max); }
        Ok(Some((copied, msg, full_len)))
    }

    /// Dequeue or peek one message payload from the ring `end` reads
    /// from. Returns copied/truncated bytes plus the full message length.
    /// # C: O(min(max, payload.len()))
    pub fn recv_payload(&self, end: UnixEnd, max: usize, peek: bool) -> Option<(Vec<u8>, usize)> {
        let out = self.recv_msg_with(end, max, peek, |payload, _, _, full| Ok::<_, core::convert::Infallible>((payload.to_vec(), full)))
            .unwrap_or_else(|never| match never {}).map(|(out, _, _)| out);
        if !peek { super::collect_scm_rights(); }
        out
    }

    /// Dequeue one message plus any SCM_RIGHTS files from ring `end` reads.
    /// # C: O(min(max, payload.len()))
    pub fn recv_msg(&self, end: UnixEnd, max: usize) -> Option<UnixMsg> {
        self.recv_msg_with(end, max, false, |_, _, _, _| Ok::<(), core::convert::Infallible>(()))
            .unwrap_or_else(|never| match never {}).map(|(_, msg, _)| msg)
    }

    /// Mark this end's writer side closed.
    /// # C: O(1)
    pub fn close_writer(&self, end: UnixEnd) {
        let mut g = match end {
            UnixEnd::A => self.a_to_b.lock(),
            UnixEnd::B => self.b_to_a.lock(),
        };
        g.closed_writer = true;
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        if self.kind == UnixMsgKind::SeqPacket {
            let waiters = match end {
                UnixEnd::A => &self.a_to_b_waiters,
                UnixEnd::B => &self.b_to_a_waiters,
            };
            waiters.wake_all();
            wake_msgpair_peer_subs(self, end, vfs::POLL_IN | vfs::POLL_RDHUP);
        }
    }

    /// Shut down `end`'s receive half while preserving queued records.
    /// # C: O(1)
    pub fn shutdown_reader(&self, end: UnixEnd) {
        let g = match end { UnixEnd::A => &self.b_to_a, UnixEnd::B => &self.a_to_b };
        g.lock().reader_shutdown = true;
        #[cfg(target_os = "oxide-kernel")]
        {
            self.reader_waiters(end).wake_all();
            wake_msgpair_peer_subs(self, end.other(), vfs::POLL_IN | vfs::POLL_RDHUP);
            wake_msgpair_peer_subs(self, end, vfs::POLL_OUT);
        }
    }

    /// Destroy one endpoint and discard records it will never receive.
    /// # C: O(unread records + descriptors)
    pub fn release_end(&self, end: UnixEnd) {
        use core::sync::atomic::Ordering::{AcqRel, Release};
        let released = match end { UnixEnd::A => &self.released_a, UnixEnd::B => &self.released_b };
        if released.swap(true, AcqRel) { return; }
        let incoming = match end { UnixEnd::A => &self.b_to_a, UnixEnd::B => &self.a_to_b };
        let dropped = {
            let mut g = incoming.lock();
            let unread = !g.msgs.is_empty();
            g.reader_shutdown = true;
            (unread, core::mem::take(&mut g.msgs))
        };
        let (gone, reset) = match end {
            UnixEnd::A => (&self.peer_gone_b, &self.reset_pending_b),
            UnixEnd::B => (&self.peer_gone_a, &self.reset_pending_a),
        };
        gone.store(true, Release);
        if self.kind == UnixMsgKind::SeqPacket && dropped.0 {
            self.end_error(end.other()).set(ECONNRESET);
            reset.store(true, Release);
        }
        if self.kind == UnixMsgKind::SeqPacket {
            let outgoing = match end { UnixEnd::A => &self.a_to_b, UnixEnd::B => &self.b_to_a };
            outgoing.lock().closed_writer = true;
        }
        drop(dropped.1);
        #[cfg(target_os = "oxide-kernel")]
        {
            self.reader_waiters(end).wake_all();
            self.reader_waiters(end.other()).wake_all();
            let mut mask = vfs::POLL_OUT;
            if self.kind == UnixMsgKind::SeqPacket {
                mask |= vfs::POLL_IN | vfs::POLL_HUP | vfs::POLL_RDHUP;
                if dropped.0 { mask |= vfs::POLL_ERR; }
            }
            wake_msgpair_peer_subs(self, end, mask);
        }
    }

    /// Consume one close-with-unread marker and canonical reset after records drain.
    /// # C: O(1)
    pub fn take_reset(&self, end: UnixEnd) -> bool {
        use core::sync::atomic::Ordering::AcqRel;
        let marked = match end { UnixEnd::A => self.reset_pending_a.swap(false, AcqRel), UnixEnd::B => self.reset_pending_b.swap(false, AcqRel) };
        marked && self.end_error(end).take() == ECONNRESET
    }

    /// Whether a reset remains pending for `end`. # C: O(1)
    pub fn reset_pending(&self, end: UnixEnd) -> bool {
        use core::sync::atomic::Ordering::Acquire;
        let marked = match end { UnixEnd::A => self.reset_pending_a.load(Acquire), UnixEnd::B => self.reset_pending_b.load(Acquire) };
        marked && self.end_error(end).has()
    }

    /// Whether this endpoint's receive half was shut down. # C: O(1)
    pub fn reader_shutdown(&self, end: UnixEnd) -> bool {
        let g = match end { UnixEnd::A => self.b_to_a.lock(), UnixEnd::B => self.a_to_b.lock() };
        g.reader_shutdown
    }

    /// Whether the opposite endpoint has been released. # C: O(1)
    pub fn peer_gone(&self, end: UnixEnd) -> bool {
        use core::sync::atomic::Ordering::Acquire;
        match end { UnixEnd::A => self.peer_gone_a.load(Acquire), UnixEnd::B => self.peer_gone_b.load(Acquire) }
    }

    /// True when recv from `end` would observe EOF.
    /// # C: O(1)
    pub fn is_eof(&self, end: UnixEnd) -> bool {
        let g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        self.kind == UnixMsgKind::SeqPacket
            && (g.closed_writer || g.reader_shutdown) && g.msgs.is_empty() && !self.reset_pending(end)
    }

    /// True iff there is a pending message for `end` to receive.
    /// # C: O(1)
    pub fn has_msg(&self, end: UnixEnd) -> bool {
        let g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        !g.msgs.is_empty()
    }

    /// Linux message-pair readiness derived from both directional halves.
    /// # C: O(1)
    pub fn poll_mask(&self, end: UnixEnd) -> u32 {
        let (has_msg, peer_send_shut, local_recv_shut) = {
            let g = match end { UnixEnd::A => self.b_to_a.lock(), UnixEnd::B => self.a_to_b.lock() };
            (!g.msgs.is_empty(), g.closed_writer, g.reader_shutdown)
        };
        let (local_send_shut, peer_recv_shut) = {
            let g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
            (g.closed_writer, g.reader_shutdown)
        };
        let gone = self.peer_gone(end);
        let reset = self.reset_pending(end);
        let mut mask = vfs::POLL_OUT;
        if has_msg || local_recv_shut || (self.kind == UnixMsgKind::SeqPacket && (peer_send_shut || gone || reset)) { mask |= vfs::POLL_IN; }
        if local_recv_shut || (self.kind == UnixMsgKind::SeqPacket && (peer_send_shut || gone)) { mask |= vfs::POLL_RDHUP; }
        if (local_recv_shut && local_send_shut)
            || (self.kind == UnixMsgKind::SeqPacket && ((peer_send_shut && peer_recv_shut) || gone))
        {
            mask |= vfs::POLL_HUP;
        }
        if self.kind == UnixMsgKind::SeqPacket && reset { mask |= vfs::POLL_ERR; }
        mask
    }
}
