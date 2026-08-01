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

/// One end's owning credentials, taken as a single snapshot so `SO_PEERCRED`
/// and `SO_PEERGROUPS` can never report two different instants. # C: O(1)
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct PeerCred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    /// The refcounted supplementary list; cloning shares it.
    pub groups: sched::GroupList,
}

impl PeerCred {
    /// # C: O(1)
    pub fn new(pid: u32, uid: u32, gid: u32, groups: sched::GroupList) -> Self {
        Self { pid, uid, gid, groups }
    }
    /// # C: O(1)
    pub fn ids(&self) -> (u32, u32, u32) { (self.pid, self.uid, self.gid) }
    /// Supplementary group count; an empty list is still a list. # C: O(1)
    pub fn group_count(&self) -> usize { self.groups.as_ref().map_or(0, |ids| ids.len()) }

    /// The running task's identity, taken as one snapshot at the instant a
    /// pair is created, connected, or published for accept. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn of_current() -> Option<Self> {
        use core::sync::atomic::Ordering;
        let cur = sched::live::current()?;
        Some(Self {
            pid: cur.visible_pid(),
            uid: cur.creds.euid.load(Ordering::Relaxed),
            gid: cur.creds.egid.load(Ordering::Relaxed),
            groups: cur.creds.group_list(),
        })
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
    /// Linux `cred->group_info` for the same instant as the ids above.
    groups: Spinlock<sched::GroupList, UnixLockClass>,
}

impl EndCred {
    /// # C: O(1)
    pub fn new() -> Self {
        Self {
            pid: AtomicU32::new(0), uid: AtomicU32::new(0), gid: AtomicU32::new(0),
            identity: Spinlock::new(None),
            groups: Spinlock::new(None),
        }
    }

    /// # C: O(1)
    pub fn set(&self, cred: PeerCred) {
        use core::sync::atomic::Ordering;
        // The group list is published first so a reader that sees the new pid
        // never pairs it with the previous owner's groups.
        *self.groups.lock() = cred.groups;
        self.uid.store(cred.uid, Ordering::Release);
        self.gid.store(cred.gid, Ordering::Release);
        self.pid.store(cred.pid, Ordering::Release);
    }

    /// Pin the owning process's identity alongside its numbers. # C: O(1)
    pub fn set_identity(&self, identity: Option<Arc<PidIdentity>>) {
        *self.identity.lock() = identity;
    }

    /// # C: O(1)
    pub fn identity(&self) -> Option<Arc<PidIdentity>> { self.identity.lock().clone() }

    /// # C: O(1)
    pub fn get(&self) -> PeerCred {
        use core::sync::atomic::Ordering;
        PeerCred {
            pid: self.pid.load(Ordering::Acquire),
            uid: self.uid.load(Ordering::Acquire),
            gid: self.gid.load(Ordering::Acquire),
            groups: self.groups.lock().clone(),
        }
    }
}
