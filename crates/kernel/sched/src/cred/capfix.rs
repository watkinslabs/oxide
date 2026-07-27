// Linux `security_task_fix_setuid`/`security_task_fix_setgid` as implemented
// by commoncap (`security/commoncap.c` `cap_task_fix_setuid`).
//
// Two DISJOINT juggles, selected by the LSM_SETID_* flag the caller passes:
//   * `LSM_SETID_RE` / `LSM_SETID_ID` / `LSM_SETID_RES` (the whole set*uid
//     family) run `cap_emulate_setxuid` and NOTHING else.
//   * `LSM_SETID_FS` (`setfsuid`/`setfsgid`) runs ONLY the fs-capability
//     drop/raise. Conflating the two would let a set*uid transition also
//     touch the fs mask, which Linux never does.
// Both are suppressed entirely by `SECBIT_NO_SETUID_FIXUP`.

use core::sync::atomic::Ordering;

use crate::Task;
use crate::task::creds::securebits::SECBIT_NO_SETUID_FIXUP;
use crate::task::creds::securebits::SECBIT_KEEP_CAPS;

/// Linux `CAP_FS_MASK` (`include/linux/capability.h`): the capabilities that
/// follow the FILESYSTEM uid rather than the effective uid.
const FS_CAP_MASK: u64 = (1u64 << crate::cap::CHOWN)
    | (1u64 << crate::cap::DAC_OVERRIDE)
    | (1u64 << crate::cap::DAC_READ_SEARCH)
    | (1u64 << crate::cap::FOWNER)
    | (1u64 << crate::cap::FSETID)
    | (1u64 << crate::cap::MKNOD)
    | (1u64 << crate::cap::LINUX_IMMUTABLE);

/// The uid triple before/after one transition, in the shape
/// `cap_emulate_setxuid` consumes it.
#[derive(Clone, Copy)]
pub(super) struct UidTriple { pub r: u32, pub e: u32, pub s: u32 }

impl UidTriple {
    /// # C: O(1)
    fn has_root(&self) -> bool { self.r == ROOT_UID || self.e == ROOT_UID || self.s == ROOT_UID }
}

/// Linux `make_kuid(ns, 0)` — the superuser id inside the task's user ns.
const ROOT_UID: u32 = 0;

/// True when `SECBIT_NO_SETUID_FIXUP` suppresses every capability juggle.
/// # C: O(1)
fn fixup_suppressed(cur: &Task) -> bool {
    cur.creds.securebits.load(Ordering::Acquire) & SECBIT_NO_SETUID_FIXUP != 0
}

/// Linux `cap_emulate_setxuid` — the `LSM_SETID_RE`/`ID`/`RES` juggle.
///
/// Without it a privileged daemon that drops uid keeps its capabilities:
/// openssh's `permanently_set_uid` safety probe (`setuid(0)` after
/// `setresuid(uid,uid,uid)`) would succeed and sshd aborts with
/// `was able to restore old [e]uid`.
/// # C: O(1)
pub(super) fn task_fix_setuid(cur: &Task, old: UidTriple, new: UidTriple) {
    if fixup_suppressed(cur) { return; }
    if old.has_root() && !new.has_root() {
        if cur.creds.securebits.load(Ordering::Acquire) & SECBIT_KEEP_CAPS == 0 {
            cur.creds.cap_permitted.store(0, Ordering::Release);
            cur.creds.cap_effective.store(0, Ordering::Release);
        }
        // Linux clears ambient on EVERY complete root-to-non-root
        // transition, `SECURE_KEEP_CAPS` included.
        cur.creds.cap_ambient.store(0, Ordering::Release);
    }
    if old.e == ROOT_UID && new.e != ROOT_UID {
        cur.creds.cap_effective.store(0, Ordering::Release);
    } else if old.e != ROOT_UID && new.e == ROOT_UID {
        let permitted = cur.creds.cap_permitted.load(Ordering::Acquire);
        cur.creds.cap_effective.store(permitted, Ordering::Release);
    }
}

/// Linux `cap_task_fix_setuid(LSM_SETID_FS)` — `cap_drop_fs_set` when the
/// fsuid leaves root, `cap_raise_fs_set` when it returns.
/// # C: O(1)
pub(super) fn task_fix_setfsuid(cur: &Task, old_fsuid: u32, new_fsuid: u32) {
    if fixup_suppressed(cur) { return; }
    let effective = cur.creds.cap_effective.load(Ordering::Acquire);
    if old_fsuid == ROOT_UID && new_fsuid != ROOT_UID {
        cur.creds.cap_effective.store(effective & !FS_CAP_MASK, Ordering::Release);
    } else if old_fsuid != ROOT_UID && new_fsuid == ROOT_UID {
        let permitted = cur.creds.cap_permitted.load(Ordering::Acquire);
        cur.creds.cap_effective.store(effective | (permitted & FS_CAP_MASK), Ordering::Release);
    }
}
