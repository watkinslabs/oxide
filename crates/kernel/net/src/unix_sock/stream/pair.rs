use alloc::vec::Vec;

use sync::Spinlock;

use vfs;

use super::{UnixPair, UnixRing};
use super::super::{EndCred, GcNode, UnixEnd};

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
            #[cfg(target_os = "oxide-kernel")]
            a_to_b_writers: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            b_to_a_writers: sched::live::WaitList::new(),
            end_a_subs: Spinlock::new(None),
            end_b_subs: Spinlock::new(None),
            error_a: Spinlock::new(alloc::sync::Arc::new(crate::SocketError::new())),
            error_b: Spinlock::new(alloc::sync::Arc::new(crate::SocketError::new())),
            peer_gone_a: core::sync::atomic::AtomicBool::new(false),
            peer_gone_b: core::sync::atomic::AtomicBool::new(false),
            reset_pending_a: core::sync::atomic::AtomicBool::new(false),
            reset_pending_b: core::sync::atomic::AtomicBool::new(false),
            released_a: core::sync::atomic::AtomicBool::new(false),
            released_b: core::sync::atomic::AtomicBool::new(false),
            cred_a: EndCred::new(),
            cred_b: EndCred::new(),
            bind_path: Spinlock::new(None),
            gc_a: GcNode::new(),
            gc_b: GcNode::new(),
        })
    }

    /// Stable receive-queue identity for one endpoint. # C: O(1)
    pub fn gc_node(&self, end: UnixEnd) -> GcNode {
        match end { UnixEnd::A => self.gc_a.clone(), UnixEnd::B => self.gc_b.clone() }
    }

    /// Record the listener's bound `sun_path` this pair was connected to.
    /// Called by the registry `connect(path)` before the ends go live.
    /// # C: O(path len)
    pub fn set_bind_path(&self, path: Vec<u8>) {
        *self.bind_path.lock() = Some(path);
    }

    /// The peer's bound `sun_path` as seen from `end`. Linux: the client
    /// (`end == B`) sees the listener's path it connected to; the accepted
    /// server socket (`end == A`) sees the client's address - unnamed here.
    /// # C: O(path len)
    pub fn peer_path(&self, end: UnixEnd) -> Option<Vec<u8>> {
        match end {
            UnixEnd::B => self.bind_path.lock().clone(),
            UnixEnd::A => None,
        }
    }

    /// The local bound `sun_path` as seen from `end`. Linux: the accepted
    /// server socket (`end == A`) inherits the listener path; the client
    /// (`end == B`) is unnamed. # C: O(path len)
    pub fn local_path(&self, end: UnixEnd) -> Option<Vec<u8>> {
        match end {
            UnixEnd::A => self.bind_path.lock().clone(),
            UnixEnd::B => None,
        }
    }

    /// Snapshot the `{pid,uid,gid}` owning `end` (`SO_PEERCRED` source).
    /// # C: O(1)
    pub fn set_end_cred(&self, end: crate::UnixEnd, cred: crate::PeerCred) {
        match end {
            crate::UnixEnd::A => self.cred_a.set(cred),
            crate::UnixEnd::B => self.cred_b.set(cred),
        }
    }

    /// The PEER's `{pid,uid,gid}` as seen from `end` (peer of A is B).
    /// # C: O(1)
    pub fn peer_cred(&self, end: crate::UnixEnd) -> crate::PeerCred {
        match end {
            crate::UnixEnd::A => self.cred_b.get(),
            crate::UnixEnd::B => self.cred_a.get(),
        }
    }

    /// Pin the identity of the process owning `end` (`SO_PEERPIDFD` source).
    /// # C: O(1)
    pub fn set_end_identity(&self, end: crate::UnixEnd, identity: Option<alloc::sync::Arc<sched::pid::PidIdentity>>) {
        match end {
            crate::UnixEnd::A => self.cred_a.set_identity(identity),
            crate::UnixEnd::B => self.cred_b.set_identity(identity),
        }
    }

    /// The PEER's pinned identity as seen from `end`. # C: O(1)
    pub fn peer_identity(&self, end: crate::UnixEnd) -> Option<alloc::sync::Arc<sched::pid::PidIdentity>> {
        match end {
            crate::UnixEnd::A => self.cred_b.identity(),
            crate::UnixEnd::B => self.cred_a.identity(),
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

    /// Share the bound InetSocket's canonical error state with this endpoint. # C: O(1)
    pub fn attach_end_error(&self, end: UnixEnd, error: &alloc::sync::Arc<crate::SocketError>) {
        *self.error_slot(end).lock() = error.clone();
    }

    /// Canonical error state allocated for an endpoint not yet bound to a socket. # C: O(1)
    pub fn end_error(&self, end: UnixEnd) -> alloc::sync::Arc<crate::SocketError> {
        self.error_slot(end).lock().clone()
    }

    /// Return one endpoint's canonical error slot. # C: O(1)
    pub(super) fn error_slot(&self, end: UnixEnd) -> &Spinlock<alloc::sync::Arc<crate::SocketError>, sync::Socket> {
        match end { UnixEnd::A => &self.error_a, UnixEnd::B => &self.error_b }
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

    /// Returns the WaitList for writers on `end`. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn writer_waiters(&self, end: UnixEnd) -> &sched::live::WaitList {
        match end {
            UnixEnd::A => &self.a_to_b_writers,
            UnixEnd::B => &self.b_to_a_writers,
        }
    }
}
