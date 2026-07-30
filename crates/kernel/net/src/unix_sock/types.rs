use alloc::sync::Arc;
use core::sync::atomic::AtomicU32;

use sched::pid::PidIdentity;
use sync::{Socket as UnixLockClass, Spinlock};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixEnd {
    A,
    B,
}

impl UnixEnd {
    /// Opposite endpoint in a connected AF_UNIX pair. # C: O(1)
    pub const fn other(self) -> Self {
        match self { Self::A => Self::B, Self::B => Self::A }
    }
}

/// Per-end peer credentials (`SO_PEERCRED`): the `{pid,uid,gid}` of the
/// task owning that end, snapshotted at socketpair / connect / accept.
pub struct EndCred {
    pub pid: AtomicU32,
    pub uid: AtomicU32,
    pub gid: AtomicU32,
    /// Linux `sk->sk_peer_pid`: the pinned pid identity — not the numeric pid —
    /// of the process owning this end, taken at the same instant as the numbers
    /// above. `SO_PEERPIDFD` hands a descriptor for THIS identity, so the fd
    /// still names the original process after the number has been recycled;
    /// resolving the stored `pid` again at read time would not.
    identity: Spinlock<Option<Arc<PidIdentity>>, UnixLockClass>,
}

impl EndCred {
    /// # C: O(1)
    pub fn new() -> Self {
        Self {
            pid: AtomicU32::new(0), uid: AtomicU32::new(0), gid: AtomicU32::new(0),
            identity: Spinlock::new(None),
        }
    }

    /// # C: O(1)
    pub fn set(&self, pid: u32, uid: u32, gid: u32) {
        use core::sync::atomic::Ordering;
        self.pid.store(pid, Ordering::Release);
        self.uid.store(uid, Ordering::Release);
        self.gid.store(gid, Ordering::Release);
    }

    /// Pin the owning process's identity alongside its numbers. # C: O(1)
    pub fn set_identity(&self, identity: Option<Arc<PidIdentity>>) {
        *self.identity.lock() = identity;
    }

    /// # C: O(1)
    pub fn identity(&self) -> Option<Arc<PidIdentity>> { self.identity.lock().clone() }

    /// # C: O(1)
    pub fn get(&self) -> (u32, u32, u32) {
        use core::sync::atomic::Ordering;
        (
            self.pid.load(Ordering::Acquire),
            self.uid.load(Ordering::Acquire),
            self.gid.load(Ordering::Acquire),
        )
    }
}
