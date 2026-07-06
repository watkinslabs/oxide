use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};

use sched;
use vfs;

#[cfg(target_os = "oxide-kernel")]
use super::wake_peer_subs;
use super::{EndCred, UnixEnd};

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
    pub end_a_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    pub end_b_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    /// Peer credentials per end (`SO_PEERCRED`).
    pub cred_a: EndCred,
    pub cred_b: EndCred,
}

pub struct UnixRing {
    pub buf: VecDeque<u8>,
    pub closed_writer: bool,
    /// Total bytes ever pushed into `buf` (monotonic; drains don't lower it).
    pub produced: u64,
    /// Total bytes ever drained from `buf` (monotonic).
    pub consumed: u64,
    /// SCM_RIGHTS bursts, each tagged with the absolute stream offset
    /// (`produced` at the moment of the carrying write) of the FIRST byte
    /// they ride with. Linux delivers an skb's `fp` fds with that skb's
    /// first byte and never coalesces a read across the boundary; the
    /// offset tag reproduces that so a fd can't be popped early and
    /// mis-attached to a preceding D-Bus message.
    pub fds: VecDeque<(u64, Vec<Arc<vfs::File>>)>,
}

impl UnixRing {
    /// # C: O(1)
    fn new() -> Self {
        Self { buf: VecDeque::new(), closed_writer: false, produced: 0, consumed: 0, fds: VecDeque::new() }
    }
}

impl UnixPair {
    /// Build an empty pair.
    /// # C: O(1)
    pub fn new() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            a_to_b: Spinlock::new(UnixRing::new()),
            b_to_a: Spinlock::new(UnixRing::new()),
            #[cfg(target_os = "oxide-kernel")]
            a_to_b_waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            b_to_a_waiters: sched::live::WaitList::new(),
            end_a_subs: Spinlock::new(None),
            end_b_subs: Spinlock::new(None),
            cred_a: EndCred::new(),
            cred_b: EndCred::new(),
        })
    }

    /// Snapshot the `{pid,uid,gid}` owning `end` (`SO_PEERCRED` source).
    /// # C: O(1)
    pub fn set_end_cred(&self, end: crate::UnixEnd, pid: u32, uid: u32, gid: u32) {
        match end {
            crate::UnixEnd::A => self.cred_a.set(pid, uid, gid),
            crate::UnixEnd::B => self.cred_b.set(pid, uid, gid),
        }
    }

    /// The PEER's `{pid,uid,gid}` as seen from `end` (peer of A is B).
    /// # C: O(1)
    pub fn peer_cred(&self, end: crate::UnixEnd) -> (u32, u32, u32) {
        match end {
            crate::UnixEnd::A => self.cred_b.get(),
            crate::UnixEnd::B => self.cred_a.get(),
        }
    }

    /// F181a: register an end's epoll-subscriber list. Called when
    /// an InetSocket is bound to this pair's end (socketpair,
    /// AF_UNIX accept, AF_UNIX connect). Writes wake only the
    /// opposite end's subscribers.
    /// # C: O(1)
    pub fn register_end_subs(&self, end: UnixEnd, subs: &alloc::sync::Arc<vfs::PollSubscribers>) {
        let slot = match end {
            UnixEnd::A => &self.end_a_subs,
            UnixEnd::B => &self.end_b_subs,
        };
        *slot.lock() = Some(alloc::sync::Arc::downgrade(subs));
    }

    /// Returns the WaitList the reader of `end` should park on.
    /// `end == A` reads from b_to_a; `end == B` reads from a_to_b.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn reader_waiters(&self, end: UnixEnd) -> &sched::live::WaitList {
        match end {
            UnixEnd::A => &self.b_to_a_waiters,
            UnixEnd::B => &self.a_to_b_waiters,
        }
    }

    /// Append `data` from `end` into the ring it writes to.
    /// Returns the number of bytes accepted (full byte count for v1).
    /// # C: O(data.len())
    pub fn write(&self, end: UnixEnd, data: &[u8]) -> usize {
        self.write_inner(end, data, Vec::new())
    }

    /// Append `data` plus a SCM_RIGHTS burst, tagging the fds to the
    /// stream offset of `data`'s first byte so the peer's recvmsg
    /// delivers them exactly with that byte (Linux skb-`fp` semantics)
    /// rather than popping them ahead of their D-Bus message.
    /// # C: O(data.len() + fds)
    pub fn write_with_fds(&self, end: UnixEnd, data: &[u8], fds: Vec<Arc<vfs::File>>) -> usize {
        self.write_inner(end, data, fds)
    }

    /// # C: O(data.len() + fds)
    fn write_inner(&self, end: UnixEnd, data: &[u8], fds: Vec<Arc<vfs::File>>) -> usize {
        let mut g = match end {
            UnixEnd::A => self.a_to_b.lock(),
            UnixEnd::B => self.b_to_a.lock(),
        };
        if g.closed_writer {
            return 0;
        }
        if !fds.is_empty() {
            let off = g.produced;
            g.fds.push_back((off, fds));
        }
        g.buf.extend(data.iter().copied());
        let n = data.len();
        g.produced += n as u64;
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        {
            // SCM_CREDENTIALS: stamp the writing end with the live
            // sender creds so the peer's SO_PASSCRED recvmsg delivers
            // the real sender {pid,uid,gid}. Socketpair() seeds both
            // ends with creator creds; after fork the child's
            // write must re-stamp its end.
            if let Some(c) = sched::live::current() {
                use core::sync::atomic::Ordering::Relaxed;
                self.set_end_cred(
                    end,
                    c.visible_pid(),
                    c.creds.euid.load(Relaxed),
                    c.creds.egid.load(Relaxed),
                );
            }
            // Writer on `end` feeds the ring the OTHER end reads from.
            let waiters = match end {
                UnixEnd::A => &self.a_to_b_waiters,
                UnixEnd::B => &self.b_to_a_waiters,
            };
            waiters.wake_all();
            // F181a: targeted epoll wake
            wake_peer_subs(self, end);
        }
        n
    }

    /// Drain up to `max` bytes from the ring `end` reads from.
    /// Returns the bytes consumed (empty when queue is empty). Any
    /// SCM_RIGHTS fds riding the drained bytes are dropped (no control
    /// buffer, as with a plain `read(2)`/`recvfrom(2)`).
    /// # C: O(min(max, queue))
    pub fn read(&self, end: UnixEnd, max: usize) -> Vec<u8> {
        self.read_stream(end, max).0
    }

    /// Boundary-aware stream drain: return up to `max` bytes AND the
    /// SCM_RIGHTS burst attached to the first byte returned. A read
    /// never crosses an fd boundary, so fds are handed over with (and
    /// only with) the bytes of the write that carried them — matching
    /// Linux `unix_stream_read_generic`, where an skb's `fp` fds ride
    /// that skb's first byte and the read stops at the next `fp` skb.
    /// # C: O(min(max, queue))
    pub fn read_stream(&self, end: UnixEnd, max: usize) -> (Vec<u8>, Vec<Arc<vfs::File>>) {
        let mut g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        // Cap the read so it does not cross the NEXT boundary strictly
        // ahead of the cursor; a boundary AT the cursor releases now.
        let mut fds_out: Vec<Arc<vfs::File>> = Vec::new();
        let mut cap = max;
        loop {
            match g.fds.front() {
                Some((off, _)) if *off <= g.consumed => {
                    let (_, f) = g.fds.pop_front().unwrap();
                    fds_out.extend(f);
                }
                Some((off, _)) => {
                    let dist = (*off - g.consumed) as usize;
                    cap = core::cmp::min(cap, dist);
                    break;
                }
                None => break,
            }
        }
        let take = core::cmp::min(cap, g.buf.len());
        // No data available to carry the fds: leave them queued for the
        // next read rather than delivering fds with an empty payload.
        if take == 0 && !fds_out.is_empty() {
            let off = g.consumed;
            g.fds.push_front((off, fds_out));
            return (Vec::new(), Vec::new());
        }
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            out.push(g.buf.pop_front().unwrap());
        }
        g.consumed += take as u64;
        (out, fds_out)
    }

    /// MSG_PEEK variant of `read`: copy without draining.
    /// # C: O(min(max, queued))
    pub fn peek(&self, end: UnixEnd, max: usize) -> Vec<u8> {
        let g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        let take = core::cmp::min(max, g.buf.len());
        g.buf.iter().take(take).copied().collect()
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
        {
            let waiters = match end {
                UnixEnd::A => &self.a_to_b_waiters,
                UnixEnd::B => &self.b_to_a_waiters,
            };
            waiters.wake_all();
            wake_peer_subs(self, end);
        }
    }

    /// True when reads from `end` would observe EOF (peer closed + drained).
    /// # C: O(1)
    pub fn is_eof(&self, end: UnixEnd) -> bool {
        let g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        g.closed_writer && g.buf.is_empty()
    }
}
