use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};

use sched;
use vfs;

#[cfg(target_os = "oxide-kernel")]
use super::wake_msgpair_peer_subs;
use super::{EndCred, UnixEnd};

pub struct UnixMsgRing {
    pub msgs: VecDeque<UnixMsg>,
    pub closed_writer: bool,
}

pub struct UnixMsgPair {
    pub a_to_b: Spinlock<UnixMsgRing, UnixLockClass>,
    pub b_to_a: Spinlock<UnixMsgRing, UnixLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub a_to_b_waiters: sched::live::WaitList,
    #[cfg(target_os = "oxide-kernel")]
    pub b_to_a_waiters: sched::live::WaitList,
    /// F181a: per-end epoll subscribers — see `UnixPair`.
    pub end_a_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    pub end_b_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    /// Per-end creds for SO_PEERCRED / SCM_CREDENTIALS
    pub cred_a: EndCred,
    pub cred_b: EndCred,
}

pub struct UnixMsg {
    pub payload: Vec<u8>,
    pub fds: Vec<Arc<vfs::File>>,
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
            cred_a: EndCred::new(),
            cred_b: EndCred::new(),
        })
    }

    /// Stamp `end`'s creds (socketpair creation + each send).
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

    /// WaitList the reader of `end` should park on.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn reader_waiters(&self, end: UnixEnd) -> &sched::live::WaitList {
        match end {
            UnixEnd::A => &self.b_to_a_waiters,
            UnixEnd::B => &self.a_to_b_waiters,
        }
    }

    /// Enqueue one message from `end` into the ring it writes to.
    /// # C: O(payload.len())
    pub fn send(&self, end: UnixEnd, payload: &[u8]) -> usize {
        self.send_with_fds(end, payload, Vec::new())
    }

    /// Enqueue one message plus SCM_RIGHTS files from `end`.
    /// # C: O(payload.len())
    pub fn send_with_fds(&self, end: UnixEnd, payload: &[u8], fds: Vec<Arc<vfs::File>>) -> usize {
        let mut g = match end {
            UnixEnd::A => self.a_to_b.lock(),
            UnixEnd::B => self.b_to_a.lock(),
        };
        if g.closed_writer {
            return 0;
        }
        g.msgs.push_back(UnixMsg { payload: payload.to_vec(), fds });
        let n = payload.len();
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        {
            // SCM_CREDENTIALS: stamp writing end with live creds.
            if let Some(c) = sched::live::current() {
                use core::sync::atomic::Ordering::Relaxed;
                self.set_end_cred(
                    end,
                    c.visible_pid(),
                    c.creds.euid.load(Relaxed),
                    c.creds.egid.load(Relaxed),
                );
            }
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
    /// `Some(bytes)` truncated to `max`; `None` if empty.
    /// # C: O(min(max, payload.len()))
    pub fn recv(&self, end: UnixEnd, max: usize) -> Option<Vec<u8>> {
        self.recv_msg(end, max).map(|m| m.payload)
    }

    /// Dequeue or peek one message payload from the ring `end` reads
    /// from. Returns copied/truncated bytes plus the full message length.
    /// # C: O(min(max, payload.len()))
    pub fn recv_payload(&self, end: UnixEnd, max: usize, peek: bool) -> Option<(Vec<u8>, usize)> {
        let mut g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        if let Some(msg) = g.msgs.front() {
            let full_len = msg.payload.len();
            let take = core::cmp::min(max, full_len);
            let mut out = Vec::with_capacity(take);
            out.extend_from_slice(&msg.payload[..take]);
            if !peek {
                g.msgs.pop_front();
            }
            Some((out, full_len))
        } else if g.closed_writer {
            Some((Vec::new(), 0))
        } else {
            None
        }
    }

    /// Dequeue one message plus any SCM_RIGHTS files from ring `end` reads.
    /// # C: O(min(max, payload.len()))
    pub fn recv_msg(&self, end: UnixEnd, max: usize) -> Option<UnixMsg> {
        let mut g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        if let Some(mut msg) = g.msgs.pop_front() {
            if msg.payload.len() > max {
                msg.payload.truncate(max);
            }
            Some(msg)
        } else if g.closed_writer {
            Some(UnixMsg { payload: Vec::new(), fds: Vec::new() })
        } else {
            None
        }
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
            wake_msgpair_peer_subs(self, end);
        }
    }

    /// True when recv from `end` would observe EOF.
    /// # C: O(1)
    pub fn is_eof(&self, end: UnixEnd) -> bool {
        let g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        g.closed_writer && g.msgs.is_empty()
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
}
