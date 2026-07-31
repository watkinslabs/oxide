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
    /// Whether ANY of the three ids is the namespace's superuser. A namespace
    /// that maps no id 0 has no superuser at all, so no id can match.
    /// # C: O(1)
    fn has_root(&self, root: Option<u32>) -> bool {
        root.is_some_and(|k| self.r == k || self.e == k || self.s == k)
    }
}

/// Whether `id` is the superuser of the namespace whose root maps to `root`.
/// # C: O(1)
fn is_root(id: u32, root: Option<u32>) -> bool { root == Some(id) }

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
/// `root` is Linux `make_kuid(old->user_ns, 0)`: the INTERNAL id that is uid
/// 0 inside the task's user namespace, not the literal 0. A task whose
/// namespace maps 0 to host 100000 drops its capabilities on leaving 100000,
/// and leaving host 0 — which it cannot even name — is not a root exit.
/// # C: O(1)
pub(super) fn task_fix_setuid(cur: &Task, old: UidTriple, new: UidTriple, root: Option<u32>) {
    if fixup_suppressed(cur) { return; }
    if old.has_root(root) && !new.has_root(root) {
        if cur.creds.securebits.load(Ordering::Acquire) & SECBIT_KEEP_CAPS == 0 {
            cur.creds.cap_permitted.store(0, Ordering::Release);
            cur.creds.cap_effective.store(0, Ordering::Release);
        }
        // Linux clears ambient on EVERY complete root-to-non-root
        // transition, `SECURE_KEEP_CAPS` included.
        cur.creds.cap_ambient.store(0, Ordering::Release);
    }
    if is_root(old.e, root) && !is_root(new.e, root) {
        cur.creds.cap_effective.store(0, Ordering::Release);
    } else if !is_root(old.e, root) && is_root(new.e, root) {
        let permitted = cur.creds.cap_permitted.load(Ordering::Acquire);
        cur.creds.cap_effective.store(permitted, Ordering::Release);
    }
}

/// Linux `cap_task_fix_setuid(LSM_SETID_FS)` — `cap_drop_fs_set` when the
/// fsuid leaves root, `cap_raise_fs_set` when it returns.
/// `root` is `make_kuid(old->user_ns, 0)`, as in [`task_fix_setuid`].
/// # C: O(1)
pub(super) fn task_fix_setfsuid(cur: &Task, old_fsuid: u32, new_fsuid: u32, root: Option<u32>) {
    if fixup_suppressed(cur) { return; }
    let effective = cur.creds.cap_effective.load(Ordering::Acquire);
    if is_root(old_fsuid, root) && !is_root(new_fsuid, root) {
        cur.creds.cap_effective.store(effective & !FS_CAP_MASK, Ordering::Release);
    } else if !is_root(old_fsuid, root) && is_root(new_fsuid, root) {
        let permitted = cur.creds.cap_permitted.load(Ordering::Acquire);
        cur.creds.cap_effective.store(effective | (permitted & FS_CAP_MASK), Ordering::Release);
    }
}
