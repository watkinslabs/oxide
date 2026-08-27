use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};

use vfs;

use super::super::{EndCred, GcNode, GcRights};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixStreamError {
    PeerClosed,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixStreamSendError { PeerClosed, WouldBlock }

/// One stream-pair in-kernel: two unidirectional byte queues.
/// F171: per-direction WaitList lets a parked reader (Inode::read)
/// wake precisely when its ring grows.
/// F181a: each end's epoll-subscriber list is registered via
/// `register_end_subs` so write()/close_writer wake only the
/// peer end's subscribers, not every epoll on the box.
pub struct UnixPair {
    pub a_to_b: Spinlock<UnixRing, UnixLockClass>,
    pub b_to_a: Spinlock<UnixRing, UnixLockClass>,
    /// Serializes stream readers while user memory is copied. The copy may
    /// fault and sleep; it must never hold a ring Spinlock.
    pub(crate) recv_gate: sched::live::Mutex<()>,
    /// Reader of a_to_b (UnixEnd::B's read side) parks here.
    /// Writer (UnixEnd::A's write) wakes it after pushing.
    pub a_to_b_waiters: crate::sock_wait::SockWaitQueue,
    pub b_to_a_waiters: crate::sock_wait::SockWaitQueue,
    pub a_to_b_writers: crate::sock_wait::SockWaitQueue,
    pub b_to_a_writers: crate::sock_wait::SockWaitQueue,
    /// End A's epoll subscribers (the InetSocket on end A). Wakeable
    /// when a_to_b advances? No - end A reads from b_to_a. So this
    /// is woken when end B writes (write(end=B) advances b_to_a).
    pub end_a_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    pub end_b_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    /// Canonical endpoint `sk_err`; the bound InetSocket shares this Arc.
    pub(super) error_a: Spinlock<Arc<crate::SocketError>, UnixLockClass>,
    pub(super) error_b: Spinlock<Arc<crate::SocketError>, UnixLockClass>,
    /// Persistent peer-loss state plus reset ordering markers per end.
    pub(super) peer_gone_a: core::sync::atomic::AtomicBool,
    pub(super) peer_gone_b: core::sync::atomic::AtomicBool,
    pub(super) reset_pending_a: core::sync::atomic::AtomicBool,
    pub(super) reset_pending_b: core::sync::atomic::AtomicBool,
    pub(crate) released_a: core::sync::atomic::AtomicBool,
    pub(crate) released_b: core::sync::atomic::AtomicBool,
    /// Peer credentials per end (`SO_PEERCRED`).
    pub cred_a: EndCred,
    pub cred_b: EndCred,
    /// The listener's bound `sun_path` this pair was accept()ed from
    /// (`connect(path)`). It is the LOCAL name of end A (the server-side
    /// accepted socket, which inherits the listener path in Linux) and the
    /// PEER name of end B (the connecting client). `None` for a socketpair /
    /// an unbound listener (abstract-autobind not yet retained). Used by
    /// `getsockname`/`getpeername` to report the real path.
    pub bind_path: Spinlock<Option<Vec<u8>>, UnixLockClass>,
    pub(super) gc_a: GcNode,
    pub(super) gc_b: GcNode,
}

/// One directional byte queue plus its in-band SCM_RIGHTS bursts.
///
/// S8 fix: SCM_RIGHTS fds on a SOCK_STREAM are NOT held in a FIFO
/// decoupled from byte position (the old `a_to_b_fds`/`b_to_a_fds`
/// queues), because that let a recvmsg pop the front burst regardless
/// of which bytes it read and desync a D-Bus reply's fd onto an earlier
/// fd-less message (logind Inhibit/CreateSession fd dropped). Instead
/// each burst is tagged with the absolute stream offset of the FIRST
/// byte it rides with (`produced` at the carrying write), matching
/// Linux `unix_stream_read_generic` where an skb's `fp` fds ride that
/// skb's first byte. `produced`/`consumed` are monotonic byte counters.
pub struct UnixRing {
    /// Owned payload chunks are the Rust equivalent of Linux receive-queue
    /// skbs. They precede the legacy byte buffer and avoid a second payload
    /// copy when the imported allocation can be transferred wholesale.
    pub owned: VecDeque<Vec<u8>>,
    pub owned_len: usize,
    pub buf: VecDeque<u8>,
    pub closed_writer: bool,
    pub reader_shutdown: bool,
    /// Total bytes ever pushed into `buf` (monotonic; drains don't lower it).
    pub produced: u64,
    /// Total bytes ever drained from `buf` (monotonic).
    pub consumed: u64,
    /// Per-write SCM_RIGHTS and sender credentials tagged with the absolute
    /// stream offset of their first byte. FIFO / ascending by offset.
    pub ancillary: VecDeque<(u64, GcRights, crate::unix_sock::MsgCred)>,
    /// Absolute stream offset of the one out-of-band byte still awaiting a
    /// `recv(MSG_OOB)`. A second out-of-band send while this one is unread
    /// replaces it, demoting the earlier byte to ordinary in-band data.
    pub oob: Option<u64>,
    /// Ascending absolute offsets of out-of-band bytes already delivered
    /// through `recv(MSG_OOB)`. The byte stays queued and carries no data; all
    /// it still does is bound a receive. See `stream::oob`.
    pub oob_marks: VecDeque<u64>,
}

impl UnixRing {
    /// # C: O(1)
    pub(super) fn new() -> Self {
        Self {
            owned: VecDeque::new(),
            owned_len: 0,
            buf: VecDeque::new(),
            closed_writer: false,
            reader_shutdown: false,
            produced: 0,
            consumed: 0,
            ancillary: VecDeque::new(),
            oob: None,
            oob_marks: VecDeque::new(),
        }
    }

    /// Bytes a receive may still take. A spent out-of-band record occupies a
    /// queue slot but delivers nothing, so `SIOCINQ`/`FIONREAD` and every
    /// other queued-byte report discount it. # C: O(1)
    pub fn queued_len(&self) -> usize { self.owned_len + self.buf.len() }

    /// Bytes a receive may still take after the spent OOB marks are removed.
    /// # C: O(1)
    pub fn readable_len(&self) -> usize { self.queued_len().saturating_sub(self.oob_marks.len()) }

    /// Transfer an already-imported payload into the receive queue. The
    /// compatibility buffer must be empty, making FIFO order unambiguous.
    /// # C: O(1) amortized
    pub fn append_owned(&mut self, data: Vec<u8>) {
        debug_assert!(self.buf.is_empty());
        self.owned_len += data.len();
        self.owned.push_back(data);
    }

    /// # C: O(data.len())
    pub fn append_borrowed(&mut self, data: &[u8]) { self.buf.extend(data.iter().copied()); }

    /// Copy a logical queue range into `out`. # C: O(offset + len)
    pub fn copy_range(&self, mut offset: usize, len: usize, out: &mut Vec<u8>) {
        let mut left = len;
        for chunk in &self.owned {
            if left == 0 { return; }
            if offset >= chunk.len() { offset -= chunk.len(); continue; }
            let take = core::cmp::min(left, chunk.len() - offset);
            out.extend_from_slice(&chunk[offset..offset + take]);
            left -= take;
            offset = 0;
        }
        if left != 0 { out.extend(self.buf.iter().skip(offset).take(left).copied()); }
    }

    /// Remove the logical prefix of the queue. # C: O(number of chunks + len)
    pub fn consume(&mut self, mut count: usize) {
        while count != 0 {
            let Some(front) = self.owned.front_mut() else { break };
            let take = core::cmp::min(count, front.len());
            if take == front.len() { self.owned.pop_front(); }
            else { front.drain(..take); }
            self.owned_len -= take;
            count -= take;
        }
        while count != 0 && !self.buf.is_empty() {
            self.buf.pop_front();
            count -= 1;
        }
    }

    /// # C: O(number of chunks)
    pub fn clear_data(&mut self) { self.owned.clear(); self.owned_len = 0; self.buf.clear(); }

    /// # C: O(number of chunks)
    pub fn byte_at(&self, mut index: usize) -> Option<u8> {
        for chunk in &self.owned {
            if index < chunk.len() { return Some(chunk[index]); }
            index -= chunk.len();
        }
        self.buf.get(index).copied()
    }
}
