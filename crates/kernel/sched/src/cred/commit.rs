// Linux `commit_creds` (`kernel/cred.c`) side effects that are observable
// through the credential syscalls: the dumpability downgrade and the
// `pdeath_signal` reset that fire whenever a task's privilege identity
// changes.
//
// Without this a process that drops privileges stays `SUID_DUMP_USER`, so a
// `ptrace`/`/proc/PID/mem` attacher that would be rejected on real Linux is
// admitted here — the exact hole `commit_creds`' `smp_wmb()` comment names.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::Task;
use crate::task::SUID_DUMP_DISABLE;

/// Linux `fs/exec.c` `int suid_dumpable = 0`, exported to userspace as
/// `/proc/sys/fs/suid_dumpable`. Canonical here (the credential owner);
/// procfs BINDS its sysctl leaf to this cell rather than keeping a copy.
static SUID_DUMPABLE: AtomicU8 = AtomicU8::new(SUID_DUMP_DISABLE);

/// Read `fs.suid_dumpable`. # C: O(1)
pub fn suid_dumpable() -> u8 { SUID_DUMPABLE.load(Ordering::Acquire) }

/// Write `fs.suid_dumpable` (`/proc/sys/fs/suid_dumpable`). Out-of-range
/// values are rejected by the sysctl bounds, so this stores what it is given.
/// # C: O(1)
pub fn set_suid_dumpable(value: u8) { SUID_DUMPABLE.store(value, Ordering::Release); }

/// The privilege identity `commit_creds` compares before/after a change.
#[derive(Clone, Copy)]
pub(super) struct CredIdentity {
    pub euid: u32,
    pub egid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub cap_permitted: u64,
}

impl CredIdentity {
    /// Capture the task's current privilege identity. # C: O(1)
    pub(super) fn capture(cur: &Task) -> Self {
        Self {
            euid:  cur.creds.euid.load(Ordering::Acquire),
            egid:  cur.creds.egid.load(Ordering::Acquire),
            fsuid: cur.creds.fsuid.load(Ordering::Acquire),
            fsgid: cur.creds.fsgid.load(Ordering::Acquire),
            cap_permitted: cur.creds.cap_permitted.load(Ordering::Acquire),
        }
    }
}

/// Linux `commit_creds`' dumpability block: on any change to euid, egid,
/// fsuid, fsgid, or a capability set that is NOT a subset of the old one,
/// downgrade dumpability to `fs.suid_dumpable` and clear `pdeath_signal`.
/// A task with no mm (kernel thread) keeps the shared init dumpability.
/// # C: O(1); # Lk: TaskList
pub(super) fn commit_creds(cur: &Task, old: CredIdentity) {
    let now = CredIdentity::capture(cur);
    let changed = now.euid != old.euid
        || now.egid != old.egid
        || now.fsuid != old.fsuid
        || now.fsgid != old.fsgid
        || !cur.creds.cap_permitted_is_subset_of(old.cap_permitted);
    if !changed { return; }
    if cur.clone_mm().is_some() {
        cur.dumpable.store(suid_dumpable(), Ordering::Release);
    }
    cur.pdeathsig.store(0, Ordering::Release);
}
