use core::sync::atomic::AtomicU32;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixEnd {
    A,
    B,
}

/// Per-end peer credentials (`SO_PEERCRED`): the `{pid,uid,gid}` of the
/// task owning that end, snapshotted at socketpair / connect / accept.
pub struct EndCred {
    pub pid: AtomicU32,
    pub uid: AtomicU32,
    pub gid: AtomicU32,
}

impl EndCred {
    /// # C: O(1)
    pub fn new() -> Self {
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
        (
            self.pid.load(Ordering::Acquire),
            self.uid.load(Ordering::Acquire),
            self.gid.load(Ordering::Acquire),
        )
    }
}
