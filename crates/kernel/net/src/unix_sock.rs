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
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as UnixLockClass};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixEnd { A, B }

/// One stream-pair in-kernel: two unidirectional byte queues.
pub struct UnixPair {
    pub a_to_b: Spinlock<UnixRing, UnixLockClass>,
    pub b_to_a: Spinlock<UnixRing, UnixLockClass>,
}

pub struct UnixRing {
    pub buf: VecDeque<u8>,
    pub closed_writer: bool,
}

impl UnixPair {
    /// Build an empty pair.
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            a_to_b: Spinlock::new(UnixRing { buf: VecDeque::new(), closed_writer: false }),
            b_to_a: Spinlock::new(UnixRing { buf: VecDeque::new(), closed_writer: false }),
        })
    }

    /// Append `data` from `end` into the ring it writes to.
    /// Returns the number of bytes accepted (full byte count
    /// for v1 — unbounded growth, as VecDeque is heap-backed).
    /// F125: wake any epoll_wait parker so a reader blocked on
    /// the peer's fd re-scans and sees POLL_IN.
    /// # C: O(data.len())
    pub fn write(&self, end: UnixEnd, data: &[u8]) -> usize {
        let mut g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
        if g.closed_writer { return 0; }
        g.buf.extend(data.iter().copied());
        let n = data.len();
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        sched::live::notify_epoll_waiters();
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
    /// observes the transition.
    /// # C: O(1)
    pub fn close_writer(&self, end: UnixEnd) {
        let mut g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
        g.closed_writer = true;
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        sched::live::notify_epoll_waiters();
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
        })
    }

    /// Enqueue one message from `end` into the ring it writes to.
    /// Returns bytes accepted (full payload — VecDeque is heap so
    /// unbounded for v1). Returns 0 if peer closed. Wakes epoll
    /// parkers so a peer blocked on poll observes POLL_IN.
    /// # C: O(payload.len())
    pub fn send(&self, end: UnixEnd, payload: &[u8]) -> usize {
        let mut g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
        if g.closed_writer { return 0; }
        g.msgs.push_back(payload.to_vec());
        let n = payload.len();
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        sched::live::notify_epoll_waiters();
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
    /// Wakes epoll parkers so a peer blocked on POLL_HUP observes
    /// the transition.
    /// # C: O(1)
    pub fn close_writer(&self, end: UnixEnd) {
        let mut g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
        g.closed_writer = true;
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        sched::live::notify_epoll_waiters();
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
}

pub struct UnixDgram {
    pub payload: Vec<u8>,
    /// Sender's (pid, uid, gid) at sendmsg time. (0, 0, 0) if unset.
    pub creds: (u32, u32, u32),
    /// fds-to-pass — placeholder for SCM_RIGHTS. F121 wires the real
    /// kernel-side Arc<File> capture; F120 keeps the field at length
    /// zero (caller's cmsg parsing ignores).
    pub fds: Vec<u32>,
}

impl UnixDgramQueue {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        Arc::new(Self { msgs: Spinlock::new(VecDeque::new()) })
    }
    /// Push a complete dgram onto the queue. F125: wake epoll
    /// parkers — a peer's poll() flips POLL_IN once a msg lands.
    /// # C: O(1)
    pub fn push(&self, msg: UnixDgram) {
        self.msgs.lock().push_back(msg);
        #[cfg(target_os = "oxide-kernel")]
        sched::live::notify_epoll_waiters();
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
}

impl UnixListener {
    /// # C: O(1)
    pub fn new(path: String) -> Arc<Self> {
        Arc::new(Self {
            path,
            accept_q: Spinlock::new(VecDeque::new()),
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

    /// Connect to `path`: allocate a new UnixPair; queue the A
    /// end into the listener's accept_q so the server's
    /// `accept()` retrieves it; return the B end to the client.
    /// `None` if no listener bound to `path`.
    /// # C: O(log N)
    pub fn connect(&self, path: &str) -> Option<Arc<UnixPair>> {
        let listener = self.lookup(path)?;
        let pair = UnixPair::new();
        listener.accept_q.lock().push_back(pair.clone());
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
