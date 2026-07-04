use alloc::{collections::VecDeque, vec::Vec};

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
    /// SCM_RIGHTS bursts queued by writes on each direction.
    pub a_to_b_fds: Spinlock<VecDeque<alloc::vec::Vec<vfs::File>>, UnixLockClass>,
    pub b_to_a_fds: Spinlock<VecDeque<alloc::vec::Vec<vfs::File>>, UnixLockClass>,
    /// Peer credentials per end (`SO_PEERCRED`).
    pub cred_a: EndCred,
    pub cred_b: EndCred,
}

pub struct UnixRing {
    pub buf: VecDeque<u8>,
    pub closed_writer: bool,
}

impl UnixPair {
    /// Build an empty pair.
    /// # C: O(1)
    pub fn new() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
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

    /// Queue a SCM_RIGHTS burst from `end` for the peer to pick up
    /// on its next recvmsg-with-cmsg.
    /// # C: O(1)
    pub fn push_fds(&self, end: UnixEnd, fds: alloc::vec::Vec<vfs::File>) {
        if fds.is_empty() {
            return;
        }
        let mut g = match end {
            UnixEnd::A => self.a_to_b_fds.lock(),
            UnixEnd::B => self.b_to_a_fds.lock(),
        };
        g.push_back(fds);
    }

    /// Pop the next SCM_RIGHTS burst queued for the reader at `end`.
    /// `end == A` consumes from b_to_a_fds. Returns empty when none.
    /// # C: O(1)
    pub fn pop_fds(&self, end: UnixEnd) -> alloc::vec::Vec<vfs::File> {
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
        let mut g = match end {
            UnixEnd::A => self.a_to_b.lock(),
            UnixEnd::B => self.b_to_a.lock(),
        };
        if g.closed_writer {
            return 0;
        }
        g.buf.extend(data.iter().copied());
        let n = data.len();
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
    /// Returns the bytes consumed (empty when queue is empty).
    /// # C: O(min(max, queue))
    pub fn read(&self, end: UnixEnd, max: usize) -> Vec<u8> {
        let mut g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        let take = core::cmp::min(max, g.buf.len());
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            out.push(g.buf.pop_front().unwrap());
        }
        out
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
