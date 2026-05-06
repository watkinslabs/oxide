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
    /// # C: O(data.len())
    pub fn write(&self, end: UnixEnd, data: &[u8]) -> usize {
        let mut g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
        if g.closed_writer { return 0; }
        g.buf.extend(data.iter().copied());
        data.len()
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
    /// # C: O(1)
    pub fn close_writer(&self, end: UnixEnd) {
        let mut g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
        g.closed_writer = true;
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

/// AF_UNIX path-bound listener. `bind(path)` inserts one into
/// `UnixRegistry`; `connect(path)` looks it up + allocates a
/// fresh `UnixPair`, queues the listener's-side handle into the
/// listener's accept queue.
pub struct UnixListener {
    pub path: String,
    pub accept_q: Spinlock<VecDeque<Arc<UnixPair>>, UnixLockClass>,
}

impl UnixListener {
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
}

impl UnixRegistry {
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(BTreeMap::new()) }
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
}
