// Personalities: run an SQE under the credentials the ring registered rather
// than the submitter's own.
//
// A personality is a snapshot of the registering task's credentials taken at
// `IORING_REGISTER_PERSONALITY` time. An SQE naming one runs with those
// credentials installed on the submitting thread and the thread's own
// credentials restored the instant the operation returns — including on every
// error path, which is what the guard type exists to guarantee. Reporting
// `IORING_FEAT_CUR_PERSONALITY` without this would tell callers that a ring
// created by a privileged process keeps that privilege for later submissions
// when it silently would not.

use core::sync::atomic::Ordering;

use sched::GroupList;

/// A frozen copy of one task's credentials.
pub struct CredSnapshot {
    ruid: u32, euid: u32, suid: u32, fsuid: u32,
    rgid: u32, egid: u32, sgid: u32, fsgid: u32,
    cap_effective: u64, cap_permitted: u64, cap_inheritable: u64,
    cap_ambient: u64, cap_bounding: u64,
    groups: GroupList,
}

/// Read the running task's credentials. # C: O(1)
pub fn snapshot_current() -> Option<CredSnapshot> {
    let cur = sched::live::current()?;
    Some(snapshot_of(cur))
}

/// # C: O(1)
fn snapshot_of(t: &sched::Task) -> CredSnapshot {
    let c = &t.creds;
    CredSnapshot {
        ruid: c.ruid.load(Ordering::Acquire), euid: c.euid.load(Ordering::Acquire),
        suid: c.suid.load(Ordering::Acquire), fsuid: c.fsuid.load(Ordering::Acquire),
        rgid: c.rgid.load(Ordering::Acquire), egid: c.egid.load(Ordering::Acquire),
        sgid: c.sgid.load(Ordering::Acquire), fsgid: c.fsgid.load(Ordering::Acquire),
        cap_effective: c.cap_effective.load(Ordering::Acquire),
        cap_permitted: c.cap_permitted.load(Ordering::Acquire),
        cap_inheritable: c.cap_inheritable.load(Ordering::Acquire),
        cap_ambient: c.cap_ambient.load(Ordering::Acquire),
        cap_bounding: c.cap_bounding.load(Ordering::Acquire),
        groups: t.creds.groups.lock().clone(),
    }
}

/// Install `snap` on the running task. # C: O(1)
fn install(t: &sched::Task, snap: &CredSnapshot) {
    let c = &t.creds;
    c.ruid.store(snap.ruid, Ordering::Release); c.euid.store(snap.euid, Ordering::Release);
    c.suid.store(snap.suid, Ordering::Release); c.fsuid.store(snap.fsuid, Ordering::Release);
    c.rgid.store(snap.rgid, Ordering::Release); c.egid.store(snap.egid, Ordering::Release);
    c.sgid.store(snap.sgid, Ordering::Release); c.fsgid.store(snap.fsgid, Ordering::Release);
    c.cap_effective.store(snap.cap_effective, Ordering::Release);
    c.cap_permitted.store(snap.cap_permitted, Ordering::Release);
    c.cap_inheritable.store(snap.cap_inheritable, Ordering::Release);
    c.cap_ambient.store(snap.cap_ambient, Ordering::Release);
    c.cap_bounding.store(snap.cap_bounding, Ordering::Release);
    *c.groups.lock() = snap.groups.clone();
}

/// Credentials installed for the life of one operation. Dropping it puts the
/// submitter's own credentials back, so no early return can leak a
/// personality into the rest of the syscall.
///
/// The saved credentials live BEHIND a pointer rather than in this guard: the
/// guard sits in the frame every operation runs beneath, and the deepest
/// operations run close to the kernel stack budget, so a whole credential set
/// stored inline here would be charged to all of them. Only an entry that
/// actually names a personality pays for the allocation.
pub struct CredsOverride {
    saved: Option<alloc::boxed::Box<CredSnapshot>>,
}

impl CredsOverride {
    /// Install `snap`, remembering what to restore.
    ///
    /// Never inlined: the snapshot it takes is built here and moved to the
    /// heap, and this frame is gone before the operation itself runs, so the
    /// copy is not charged to the operation's stack depth.
    /// # C: O(1)
    #[inline(never)]
    pub fn install(snap: &CredSnapshot) -> Self {
        let Some(cur) = sched::live::current() else { return Self { saved: None } };
        let saved = alloc::boxed::Box::new(snapshot_of(cur));
        install(cur, snap);
        Self { saved: Some(saved) }
    }
}

impl Drop for CredsOverride {
    /// # C: O(1)
    fn drop(&mut self) {
        let (Some(saved), Some(cur)) = (self.saved.as_ref(), sched::live::current()) else { return };
        install(cur, saved);
    }
}
