// AF_UNIX SOCK_STREAM via socketpair(2). One UnixPair owns two
// byte rings (a→b, b→a); the two endpoint handles each hold an
// `Arc<UnixPair>` and an end identifier (A or B) so reads/writes
// route to the correct ring.
//
// Path-bound bind+connect (filesystem socket files) and abstract
// addresses are follow-ups; v1 socketpair-only covers the
// shell-pipeline-equivalent IPC use cases for system services.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Spinlock, Socket as UnixLockClass};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixEnd { A, B }

/// F181a: wake the PEER end's epoll subscribers (the end whose
/// `read` would now succeed). When `end == A` we just wrote to
/// a_to_b (peer = B), so wake end_b_subs; vice versa.
/// Falls back to global epoll broadcast when peer's subs slot is
/// empty (binding race) so no events get silently swallowed.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn wake_peer_subs(pair: &UnixPair, end: UnixEnd) {
    let slot = match end {
        UnixEnd::A => pair.end_b_subs.lock().clone(),
        UnixEnd::B => pair.end_a_subs.lock().clone(),
    };
    if let Some(weak) = slot {
        if let Some(subs) = weak.upgrade() {
            subs.notify();
            return;
        }
    }
    sched::live::notify_epoll_waiters();
}

/// F181a: msgpair sibling of `wake_peer_subs`.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn wake_msgpair_peer_subs(pair: &UnixMsgPair, end: UnixEnd) {
    let slot = match end {
        UnixEnd::A => pair.end_b_subs.lock().clone(),
        UnixEnd::B => pair.end_a_subs.lock().clone(),
    };
    if let Some(weak) = slot {
        if let Some(subs) = weak.upgrade() {
            subs.notify();
            return;
        }
    }
    sched::live::notify_epoll_waiters();
}

/// One stream-pair in-kernel: two unidirectional byte queues.
/// F171: per-direction WaitList lets a parked reader (Inode::read)
/// wake precisely when its ring grows.
/// F181a: each end's epoll-subscriber list is registered via
/// `register_end_subs` so write()/close_writer wake only the
/// peer end's subscribers, not every epoll on the box.
pub struct UnixPair {
    pub a_to_b: Spinlock<UnixRing, UnixLockClass>,
    pub b_to_a: Spinlock<UnixRing, UnixLockClass>,
    /// Reader of a_to_b (UnixEnd::B's read side) parks here.
    /// Writer (UnixEnd::A's write) wakes it after pushing.
    #[cfg(target_os = "oxide-kernel")]
    pub a_to_b_waiters: sched::live::WaitList,
    #[cfg(target_os = "oxide-kernel")]
    pub b_to_a_waiters: sched::live::WaitList,
    /// End A's epoll subscribers (the InetSocket on end A). Wakeable
    /// when a_to_b advances? No — end A reads from b_to_a. So this
    /// is woken when end B writes (write(end=B) advances b_to_a).
    pub end_a_subs: Spinlock<Option<Weak<vfs::PollSubscribers>>, UnixLockClass>,
    pub end_b_subs: Spinlock<Option<Weak<vfs::PollSubscribers>>, UnixLockClass>,
    /// SCM_RIGHTS bursts queued by writes on each direction. Each
    /// burst captures the `Arc<File>` set attached to one sendmsg(2);
    /// the receiver pops the FIFO head on its next recvmsg(2) and
    /// installs the fds into its fd_table. Linux strictly couples fds
    /// to byte offsets — v1 simplifies to FIFO with first-recvmsg
    /// delivery, which matches openssh's monitor/preauth (sendmsg one
    /// header+payload+fds → recvmsg one header → recvmsg one payload).
    pub a_to_b_fds: Spinlock<VecDeque<alloc::vec::Vec<Arc<vfs::File>>>, UnixLockClass>,
    pub b_to_a_fds: Spinlock<VecDeque<alloc::vec::Vec<Arc<vfs::File>>>, UnixLockClass>,
    /// Peer credentials per end (`SO_PEERCRED`).
    pub cred_a: EndCred,
    pub cred_b: EndCred,
}

pub struct UnixRing {
    pub buf: VecDeque<u8>,
    pub closed_writer: bool,
}

/// Per-end peer credentials (`SO_PEERCRED`): the `{pid,uid,gid}` of the
/// task owning that end, snapshotted at socketpair / connect / accept.
pub struct EndCred {
    pub pid: core::sync::atomic::AtomicU32,
    pub uid: core::sync::atomic::AtomicU32,
    pub gid: core::sync::atomic::AtomicU32,
}
impl EndCred {
    /// # C: O(1)
    pub fn new() -> Self {
        use core::sync::atomic::AtomicU32;
        Self { pid: AtomicU32::new(0), uid: AtomicU32::new(0), gid: AtomicU32::new(0) }
    }
    /// # C: O(1)
    pub fn set(&self, pid: u32, uid: u32, gid: u32) {
        use core::sync::atomic::Ordering;
        self.pid.store(pid, Ordering::Release);
        self.uid.store(uid, Ordering::Release);
        self.gid.store(gid, Ordering::Release);
    }
    /// # C: O(1)
    pub fn get(&self) -> (u32, u32, u32) {
        use core::sync::atomic::Ordering;
        (self.pid.load(Ordering::Acquire), self.uid.load(Ordering::Acquire), self.gid.load(Ordering::Acquire))
    }
}

impl UnixPair {
    /// Build an empty pair.
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            a_to_b: Spinlock::new(UnixRing { buf: VecDeque::new(), closed_writer: false }),
            b_to_a: Spinlock::new(UnixRing { buf: VecDeque::new(), closed_writer: false }),
            #[cfg(target_os = "oxide-kernel")]
            a_to_b_waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            b_to_a_waiters: sched::live::WaitList::new(),
            end_a_subs: Spinlock::new(None),
            end_b_subs: Spinlock::new(None),
            a_to_b_fds: Spinlock::new(VecDeque::new()),
            b_to_a_fds: Spinlock::new(VecDeque::new()),
            cred_a: EndCred::new(),
            cred_b: EndCred::new(),
        })
    }

    /// Snapshot the `{pid,uid,gid}` owning `end` (`SO_PEERCRED` source).
    /// # C: O(1)
    pub fn set_end_cred(&self, end: crate::UnixEnd, pid: u32, uid: u32, gid: u32) {
        match end { crate::UnixEnd::A => self.cred_a.set(pid, uid, gid),
                    crate::UnixEnd::B => self.cred_b.set(pid, uid, gid) }
    }

    /// The PEER's `{pid,uid,gid}` as seen from `end` (peer of A is B).
    /// # C: O(1)
    pub fn peer_cred(&self, end: crate::UnixEnd) -> (u32, u32, u32) {
        match end { crate::UnixEnd::A => self.cred_b.get(),
                    crate::UnixEnd::B => self.cred_a.get() }
    }

    /// Queue a SCM_RIGHTS burst from `end` for the peer to pick up
    /// on its next recvmsg-with-cmsg. The fds are captured as
    /// `Arc<File>` so the underlying file stays alive even if the
    /// sender closes its descriptor before the peer drains.
    /// # C: O(1)
    pub fn push_fds(&self, end: UnixEnd, fds: alloc::vec::Vec<Arc<vfs::File>>) {
        if fds.is_empty() { return; }
        let mut g = match end {
            UnixEnd::A => self.a_to_b_fds.lock(),
            UnixEnd::B => self.b_to_a_fds.lock(),
        };
        g.push_back(fds);
    }

    /// Pop the next SCM_RIGHTS burst queued for the reader at `end`.
    /// `end == A` consumes from b_to_a_fds. Returns empty when none.
    /// # C: O(1)
    pub fn pop_fds(&self, end: UnixEnd) -> alloc::vec::Vec<Arc<vfs::File>> {
        let mut g = match end {
            UnixEnd::A => self.b_to_a_fds.lock(),
            UnixEnd::B => self.a_to_b_fds.lock(),
        };
        g.pop_front().unwrap_or_default()
    }

    /// True if reader at `end` has a fd burst pending.
    /// # C: O(1)
    pub fn has_fds(&self, end: UnixEnd) -> bool {
        let g = match end {
            UnixEnd::A => self.b_to_a_fds.lock(),
            UnixEnd::B => self.a_to_b_fds.lock(),
        };
        !g.is_empty()
    }

    /// F181a: register an end's epoll-subscriber list. Called when
    /// an InetSocket is bound to this pair's end (socketpair,
    /// AF_UNIX accept, AF_UNIX connect). Writes wake the OPPOSITE
    /// end's subscribers.
    /// # C: O(1)
    pub fn register_end_subs(&self, end: UnixEnd, subs: &Arc<vfs::PollSubscribers>) {
        let slot = match end { UnixEnd::A => &self.end_a_subs, UnixEnd::B => &self.end_b_subs };
        *slot.lock() = Some(Arc::downgrade(subs));
    }

    /// Returns the WaitList the reader of `end` should park on.
    /// `end == A` reads from b_to_a; `end == B` reads from a_to_b.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn reader_waiters(&self, end: UnixEnd) -> &sched::live::WaitList {
        match end { UnixEnd::A => &self.b_to_a_waiters, UnixEnd::B => &self.a_to_b_waiters }
    }

    /// Append `data` from `end` into the ring it writes to.
    /// Returns the number of bytes accepted (full byte count
    /// for v1 — unbounded growth, as VecDeque is heap-backed).
    /// F125: wake any epoll_wait parker; F171: wake the specific
    /// per-ring read waiter so blocking-read callers unpark.
    /// # C: O(data.len())
    pub fn write(&self, end: UnixEnd, data: &[u8]) -> usize {
        let mut g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
        if g.closed_writer { return 0; }
        g.buf.extend(data.iter().copied());
        let n = data.len();
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        {
            // Writer on `end` feeds the ring the OTHER end reads from.
            let waiters = match end {
                UnixEnd::A => &self.a_to_b_waiters,
                UnixEnd::B => &self.b_to_a_waiters,
            };
            waiters.wake_all();
            // F181a: targeted epoll wake — peer end's subscribers
            // are the ones whose poll() flips to POLL_IN. Fall back
            // to global broadcast only if peer's subs not registered
            // (pre-binding race; rare and safe).
            wake_peer_subs(self, end);
        }
        n
    }

    /// Drain up to `max` bytes from the ring `end` reads from.
    /// Returns the bytes consumed (empty when queue is empty).
    /// # C: O(min(max, queue))
    pub fn read(&self, end: UnixEnd, max: usize) -> Vec<u8> {
        let mut g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        let take = core::cmp::min(max, g.buf.len());
        let mut out = Vec::with_capacity(take);
        for _ in 0..take { out.push(g.buf.pop_front().unwrap()); }
        out
    }

    /// Mark this end's writer side closed. The peer's next read
    /// on this ring returns 0 once the queue drains (EOF).
    /// F125: wake epoll_wait parkers so a peer blocked on POLL_HUP
    /// observes the transition. F171: also wake the per-ring
    /// reader waitq so a blocking read returns EOF promptly.
    /// # C: O(1)
    pub fn close_writer(&self, end: UnixEnd) {
        let mut g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
        g.closed_writer = true;
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        {
            let waiters = match end {
                UnixEnd::A => &self.a_to_b_waiters,
                UnixEnd::B => &self.b_to_a_waiters,
            };
            waiters.wake_all();
            wake_peer_subs(self, end);
        }
    }

    /// True when reads from `end` would observe EOF (peer closed
    /// + queue drained).
    /// # C: O(1)
    pub fn is_eof(&self, end: UnixEnd) -> bool {
        let g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        g.closed_writer && g.buf.is_empty()
    }
}

/// AF_UNIX SOCK_SEQPACKET / SOCK_DGRAM socketpair plumbing —
/// bidirectional, message-boundary preserving. Two msg-queues
/// (a→b, b→a); each `send` enqueues one atomic payload, each
/// `recv` dequeues exactly one and truncates if the user buffer
/// is smaller than the message (Linux: SOCK_SEQPACKET drops the
/// remainder). F125: dhcpcd's privsep helper asks for
/// `socketpair(AF_UNIX, SOCK_SEQPACKET, 0)`; the prior STREAM-only
/// path returned ESOCKTNOSUPPORT and broke the lease loop.
pub struct UnixMsgPair {
    pub a_to_b: Spinlock<UnixMsgRing, UnixLockClass>,
    pub b_to_a: Spinlock<UnixMsgRing, UnixLockClass>,
    /// F171: per-ring read waitqs — same shape as UnixPair.
    #[cfg(target_os = "oxide-kernel")]
    pub a_to_b_waiters: sched::live::WaitList,
    #[cfg(target_os = "oxide-kernel")]
    pub b_to_a_waiters: sched::live::WaitList,
    /// F181a: per-end epoll subscribers — see UnixPair.
    pub end_a_subs: Spinlock<Option<Weak<vfs::PollSubscribers>>, UnixLockClass>,
    pub end_b_subs: Spinlock<Option<Weak<vfs::PollSubscribers>>, UnixLockClass>,
}

pub struct UnixMsgRing {
    pub msgs: VecDeque<Vec<u8>>,
    pub closed_writer: bool,
}

impl UnixMsgPair {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            a_to_b: Spinlock::new(UnixMsgRing { msgs: VecDeque::new(), closed_writer: false }),
            b_to_a: Spinlock::new(UnixMsgRing { msgs: VecDeque::new(), closed_writer: false }),
            #[cfg(target_os = "oxide-kernel")]
            a_to_b_waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            b_to_a_waiters: sched::live::WaitList::new(),
            end_a_subs: Spinlock::new(None),
            end_b_subs: Spinlock::new(None),
        })
    }

    /// F181a: register an end's subscribers (mirrors UnixPair).
    /// # C: O(1)
    pub fn register_end_subs(&self, end: UnixEnd, subs: &Arc<vfs::PollSubscribers>) {
        let slot = match end { UnixEnd::A => &self.end_a_subs, UnixEnd::B => &self.end_b_subs };
        *slot.lock() = Some(Arc::downgrade(subs));
    }

    /// WaitList the reader of `end` should park on.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn reader_waiters(&self, end: UnixEnd) -> &sched::live::WaitList {
        match end { UnixEnd::A => &self.b_to_a_waiters, UnixEnd::B => &self.a_to_b_waiters }
    }

    /// Enqueue one message from `end` into the ring it writes to.
    /// Returns bytes accepted (full payload — VecDeque is heap so
    /// unbounded for v1). Returns 0 if peer closed. F125/F171: wakes
    /// per-ring read waitq + epoll parkers.
    /// # C: O(payload.len())
    pub fn send(&self, end: UnixEnd, payload: &[u8]) -> usize {
        let mut g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
        if g.closed_writer { return 0; }
        g.msgs.push_back(payload.to_vec());
        let n = payload.len();
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        {
            let waiters = match end {
                UnixEnd::A => &self.a_to_b_waiters,
                UnixEnd::B => &self.b_to_a_waiters,
            };
            waiters.wake_all();
            wake_msgpair_peer_subs(self, end);
        }
        n
    }

    /// Dequeue one message from the ring `end` reads from. Returns
    /// `Some(bytes)` truncated to `max` bytes (Linux SEQPACKET
    /// truncation semantics — dropped tail not retained); `None`
    /// if no message is pending. EOF (peer closed + drained) →
    /// `Some(empty)` so the read syscall returns 0.
    /// # C: O(min(max, payload.len()))
    pub fn recv(&self, end: UnixEnd, max: usize) -> Option<Vec<u8>> {
        let mut g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        if let Some(mut msg) = g.msgs.pop_front() {
            if msg.len() > max { msg.truncate(max); }
            Some(msg)
        } else if g.closed_writer {
            Some(Vec::new())
        } else {
            None
        }
    }

    /// Mark this end's writer side closed. Peer's next recv on the
    /// drained queue returns `Some(empty)` (EOF → read returns 0).
    /// F171: wakes per-ring read waitq + epoll parkers.
    /// # C: O(1)
    pub fn close_writer(&self, end: UnixEnd) {
        let mut g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
        g.closed_writer = true;
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        {
            let waiters = match end {
                UnixEnd::A => &self.a_to_b_waiters,
                UnixEnd::B => &self.b_to_a_waiters,
            };
            waiters.wake_all();
            wake_msgpair_peer_subs(self, end);
        }
    }

    /// True when recv from `end` would observe EOF (peer closed +
    /// queue drained).
    /// # C: O(1)
    pub fn is_eof(&self, end: UnixEnd) -> bool {
        let g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        g.closed_writer && g.msgs.is_empty()
    }

    /// True iff there is a pending message for `end` to receive.
    /// Used by poll() for POLL_IN.
    /// # C: O(1)
    pub fn has_msg(&self, end: UnixEnd) -> bool {
        let g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        !g.msgs.is_empty()
    }
}

/// AF_UNIX SOCK_DGRAM per-socket message queue. Each enqueued
/// `UnixDgram` carries its payload bytes plus the metadata needed
/// to honor SCM_CREDS / SCM_RIGHTS at recvmsg time. F120 admits the
/// queue + payload path; F121 wires creds + fd-passing.
pub struct UnixDgramQueue {
    pub msgs: Spinlock<VecDeque<UnixDgram>, UnixLockClass>,
    /// F171: single per-queue read waitlist (only one reader on a
    /// SOCK_DGRAM socket today — no per-direction split needed).
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    /// F181a: epoll subscribers of the owning InetSocket. Set via
    /// `register_subs` when the InetSocket is bound to this queue
    /// at socket() time. push() wakes targeted subscribers instead
    /// of broadcasting.
    pub subs: Spinlock<Option<Weak<vfs::PollSubscribers>>, UnixLockClass>,
}

pub struct UnixDgram {
    pub payload: Vec<u8>,
    /// Sender's (pid, uid, gid) at sendmsg time. (0, 0, 0) if unset.
    pub creds: (u32, u32, u32),
    /// F189: SCM_RIGHTS — files carried alongside the payload. Sender
    /// captures Arc<File> refs from its fd_table; receiver dup's them
    /// into its own table on recvmsg.
    #[cfg(target_os = "oxide-kernel")]
    pub fds: Vec<Arc<vfs::File>>,
    /// Hosted-test stub for the same slot. # C: O(1)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub fds: Vec<u32>,
}

impl UnixDgramQueue {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            msgs: Spinlock::new(VecDeque::new()),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            subs: Spinlock::new(None),
        })
    }

    /// F181a: register owning InetSocket's subscribers.
    /// # C: O(1)
    pub fn register_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.subs.lock() = Some(Arc::downgrade(subs));
    }

    /// Push a complete dgram onto the queue.
    /// # C: O(1)
    pub fn push(&self, msg: UnixDgram) {
        self.msgs.lock().push_back(msg);
        #[cfg(target_os = "oxide-kernel")]
        {
            self.waiters.wake_all();
            // F181a: wake owning socket's epoll subscribers; fall
            // back to global broadcast if subs not yet registered.
            let slot = self.subs.lock().clone();
            if let Some(weak) = slot {
                if let Some(s) = weak.upgrade() { s.notify(); return; }
            }
            sched::live::notify_epoll_waiters();
        }
    }
    /// Pop one dgram if any. Returns the full message (caller copies
    /// payload + cmsgs into user buffers).
    /// # C: O(1)
    pub fn pop(&self) -> Option<UnixDgram> {
        self.msgs.lock().pop_front()
    }
}

/// AF_UNIX path-bound listener. `bind(path)` inserts one into
/// `UnixRegistry`; `connect(path)` looks it up + allocates a
/// fresh `UnixPair`, queues the listener's-side handle into the
/// listener's accept queue.
pub struct UnixListener {
    pub path: String,
    pub accept_q: Spinlock<VecDeque<Arc<UnixPair>>, UnixLockClass>,
    /// F170: per-listener waitlist for `sys_accept`. Connect()
    /// wakes after pushing a freshly-paired UnixPair onto
    /// `accept_q`. Kernel-only — hosted tests don't run sched.
    #[cfg(target_os = "oxide-kernel")]
    pub accept_waiters: sched::live::WaitList,
}

impl UnixListener {
    /// # C: O(1)
    pub fn new(path: String) -> Arc<Self> {
        Arc::new(Self {
            path,
            accept_q: Spinlock::new(VecDeque::new()),
            #[cfg(target_os = "oxide-kernel")]
            accept_waiters: sched::live::WaitList::new(),
        })
    }
}

/// Process-global path → listener registry. New listeners go in
/// here on `bind`; clients consult on `connect`.
pub struct UnixRegistry {
    pub(crate) inner: Spinlock<BTreeMap<String, Arc<UnixListener>>, UnixLockClass>,
    /// AF_UNIX SOCK_DGRAM path-bound queues (F121). bind(path) on a
    /// SOCK_DGRAM socket inserts (path → its queue); sendto from any
    /// peer socket looks up here.
    pub(crate) dgrams: Spinlock<BTreeMap<String, Arc<UnixDgramQueue>>, UnixLockClass>,
}

impl UnixRegistry {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            inner: Spinlock::new(BTreeMap::new()),
            dgrams: Spinlock::new(BTreeMap::new()),
        }
    }

    /// Bind a SOCK_DGRAM socket's queue to `path`. Eaddrinuse if
    /// already bound.
    /// # C: O(log N)
    pub fn dgram_bind(&self, path: String, q: Arc<UnixDgramQueue>) -> Result<(), ()> {
        let mut g = self.dgrams.lock();
        if g.contains_key(&path) { return Err(()); }
        g.insert(path, q);
        Ok(())
    }

    /// Look up a SOCK_DGRAM queue by path.
    /// # C: O(log N)
    pub fn dgram_lookup(&self, path: &str) -> Option<Arc<UnixDgramQueue>> {
        self.dgrams.lock().get(path).cloned()
    }

    /// Insert a listener for `path`. `Eaddrinuse` semantic if
    /// already bound (caller maps to errno).
    /// # C: O(log N)
    pub fn bind(&self, path: String) -> Result<Arc<UnixListener>, ()> {
        let mut g = self.inner.lock();
        if g.contains_key(&path) { return Err(()); }
        let l = UnixListener::new(path.clone());
        g.insert(path, l.clone());
        Ok(l)
    }

    /// Look up a listener; returns `None` if no listener is bound.
    /// # C: O(log N)
    pub fn lookup(&self, path: &str) -> Option<Arc<UnixListener>> {
        self.inner.lock().get(path).cloned()
    }

    /// True if `path` is registered as a SOCK_STREAM listener or a
    /// SOCK_DGRAM queue. Used by AF_UNIX-aware path syscalls
    /// (chmod / unlink / stat) to no-op gracefully instead of
    /// returning ENOENT for sockets that don't yet have a backing
    /// tmpfs entry.
    /// # C: O(log N) × 2
    pub fn is_bound(&self, path: &str) -> bool {
        if self.inner.lock().contains_key(path) { return true; }
        self.dgrams.lock().contains_key(path)
    }

    /// Snapshot all bound paths grouped by kind (stream listener vs
    /// dgram queue). Used by /proc/net/unix to render one row per
    /// bind. `(kind, path)` where kind ∈ {0001 = SOCK_STREAM,
    /// 0002 = SOCK_DGRAM} per linux/socket.h.
    /// # C: O(N)
    pub fn snapshot_paths(&self) -> alloc::vec::Vec<(u16, String)> {
        let mut out: alloc::vec::Vec<(u16, String)> = alloc::vec::Vec::new();
        for k in self.inner.lock().keys() { out.push((0x0001, k.clone())); }
        for k in self.dgrams.lock().keys() { out.push((0x0002, k.clone())); }
        out
    }

    /// Connect to `path`: allocate a new UnixPair; queue the A
    /// end into the listener's accept_q so the server's
    /// `accept()` retrieves it; return the B end to the client.
    /// `None` if no listener bound to `path`.
    /// # C: O(log N)
    pub fn connect(&self, path: &str) -> Option<Arc<UnixPair>> {
        let listener = self.lookup(path)?;
        let pair = UnixPair::new();
        listener.accept_q.lock().push_back(pair.clone());
        // F170: wake any blocking accept() parked on this listener.
        #[cfg(target_os = "oxide-kernel")]
        listener.accept_waiters.wake_all();
        Some(pair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let p = UnixPair::new();
        p.write(UnixEnd::A, b"hello");
        let got = p.read(UnixEnd::B, 64);
        assert_eq!(&got[..], b"hello");
        p.write(UnixEnd::B, b"world");
        let got = p.read(UnixEnd::A, 64);
        assert_eq!(&got[..], b"world");
    }

    #[test]
    fn close_writer_then_eof() {
        let p = UnixPair::new();
        p.write(UnixEnd::A, b"abc");
        p.close_writer(UnixEnd::A);
        let got = p.read(UnixEnd::B, 64);
        assert_eq!(&got[..], b"abc");
        assert!(p.is_eof(UnixEnd::B));
        // Further writes from the closed end land in /dev/null.
        let n = p.write(UnixEnd::A, b"more");
        assert_eq!(n, 0);
    }

    #[test]
    fn empty_read_returns_empty() {
        let p = UnixPair::new();
        let got = p.read(UnixEnd::A, 16);
        assert!(got.is_empty());
    }

    // ─── UnixMsgPair (SEQPACKET/DGRAM socketpair) ─────────────

    #[test]
    fn msgpair_preserves_boundaries() {
        let p = UnixMsgPair::new();
        p.send(UnixEnd::A, b"one");
        p.send(UnixEnd::A, b"two");
        assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"one");
        assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"two");
        assert!(p.recv(UnixEnd::B, 64).is_none());
    }

    #[test]
    fn msgpair_truncates_to_buf() {
        let p = UnixMsgPair::new();
        p.send(UnixEnd::A, b"abcdefgh");
        let got = p.recv(UnixEnd::B, 3).unwrap();
        assert_eq!(&got[..], b"abc");
        // Linux SEQPACKET drops the tail — no peek of "defgh".
        assert!(p.recv(UnixEnd::B, 64).is_none());
    }

    #[test]
    fn msgpair_eof_after_close() {
        let p = UnixMsgPair::new();
        p.send(UnixEnd::A, b"final");
        p.close_writer(UnixEnd::A);
        assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"final");
        assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"");
        assert!(p.is_eof(UnixEnd::B));
        assert_eq!(p.send(UnixEnd::A, b"more"), 0);
    }

    #[test]
    fn msgpair_bidirectional() {
        let p = UnixMsgPair::new();
        p.send(UnixEnd::A, b"hello");
        p.send(UnixEnd::B, b"world");
        assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"hello");
        assert_eq!(p.recv(UnixEnd::A, 64).unwrap(), b"world");
    }
}
