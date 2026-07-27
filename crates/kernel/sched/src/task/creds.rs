use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

use super::Task;

/// Linux `cred->group_info`: a refcounted, ASCENDING-SORTED supplementary
/// gid list (`kernel/groups.c` `groups_alloc`/`groups_sort`). `None` is the
/// empty list (Linux `init_groups`, `ngroups == 0`) and costs no allocation.
pub type GroupList = Option<Arc<[u32]>>;

/// Linux securebits from `include/uapi/linux/securebits.h`.
///
/// These are credential state, not independent task flags: `PR_SET_KEEPCAPS`
/// is specified as a compatibility interface for `SECBIT_KEEP_CAPS`.
pub(crate) mod securebits {
    pub const SECURE_NOROOT: u32 = 0;
    pub const SECURE_NOROOT_LOCKED: u32 = 1;
    pub const SECURE_NO_SETUID_FIXUP: u32 = 2;
    pub const SECURE_NO_SETUID_FIXUP_LOCKED: u32 = 3;
    pub const SECURE_KEEP_CAPS: u32 = 4;
    pub const SECURE_KEEP_CAPS_LOCKED: u32 = 5;
    pub const SECURE_NO_CAP_AMBIENT_RAISE: u32 = 6;
    pub const SECURE_NO_CAP_AMBIENT_RAISE_LOCKED: u32 = 7;

    pub const fn mask(bit: u32) -> u32 { 1u32 << bit }

    pub const SECBIT_NOROOT: u32 = mask(SECURE_NOROOT);
    pub const SECBIT_NOROOT_LOCKED: u32 = mask(SECURE_NOROOT_LOCKED);
    pub const SECBIT_NO_SETUID_FIXUP: u32 = mask(SECURE_NO_SETUID_FIXUP);
    pub const SECBIT_NO_SETUID_FIXUP_LOCKED: u32 = mask(SECURE_NO_SETUID_FIXUP_LOCKED);
    pub const SECBIT_KEEP_CAPS: u32 = mask(SECURE_KEEP_CAPS);
    pub const SECBIT_KEEP_CAPS_LOCKED: u32 = mask(SECURE_KEEP_CAPS_LOCKED);
    pub const SECBIT_NO_CAP_AMBIENT_RAISE: u32 = mask(SECURE_NO_CAP_AMBIENT_RAISE);
    pub const SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED: u32 = mask(SECURE_NO_CAP_AMBIENT_RAISE_LOCKED);

    pub const SECURE_ALL_BITS: u32 = SECBIT_NOROOT
        | SECBIT_NO_SETUID_FIXUP
        | SECBIT_KEEP_CAPS
        | SECBIT_NO_CAP_AMBIENT_RAISE;
    pub const SECURE_ALL_LOCKS: u32 = SECBIT_NOROOT_LOCKED
        | SECBIT_NO_SETUID_FIXUP_LOCKED
        | SECBIT_KEEP_CAPS_LOCKED
        | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;
    pub const VALID_MASK: u32 = SECURE_ALL_BITS | SECURE_ALL_LOCKS;

    /// Linux `cap_task_prctl(PR_SET_SECUREBITS)`: a lock freezes its
    /// associated setting and locks themselves can only ever be added.
    pub const fn replacement_is_allowed(old: u32, requested: u32) -> bool {
        let locked_values = (old & SECURE_ALL_LOCKS) >> 1;
        (requested & !VALID_MASK) == 0
            && (locked_values & (old ^ requested)) == 0
            && (old & SECURE_ALL_LOCKS & !requested) == 0
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn keep_caps_lock_prevents_changing_its_value_or_removing_the_lock() {
            let locked = SECBIT_KEEP_CAPS | SECBIT_KEEP_CAPS_LOCKED;
            assert!(replacement_is_allowed(locked, locked));
            assert!(!replacement_is_allowed(locked, SECBIT_KEEP_CAPS_LOCKED));
            assert!(!replacement_is_allowed(locked, SECBIT_KEEP_CAPS));
        }

        #[test]
        fn securebits_reject_unknown_bits_and_allows_adding_a_lock() {
            assert!(!replacement_is_allowed(0, !VALID_MASK));
            assert!(replacement_is_allowed(SECBIT_NO_SETUID_FIXUP,
                SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED));
        }
    }
}

pub struct Creds {
    pub ruid:  AtomicU32,
    pub euid:  AtomicU32,
    pub suid:  AtomicU32,
    pub fsuid: AtomicU32,
    pub rgid:  AtomicU32,
    pub egid:  AtomicU32,
    pub sgid:  AtomicU32,
    pub fsgid: AtomicU32,
    /// Linux `cred->group_info`. Sole source of truth for both the count and
    /// the ids — there is no separate `ngroups` counter to disagree with it.
    pub groups: Spinlock<GroupList, TaskListClass>,

    /// Linux capability bitmasks (CAP_*). 64-bit for v3 layout
    /// per `capget(2)` / `capset(2)` and `capability.h`. Init = all
    /// bits set on root tasks; non-root inherits parent's. Real
    /// permission checks at privileged operations ride a follow-up;
    /// storage + capget/capset round-trip is the substrate.
    pub cap_effective:   AtomicU64,
    pub cap_permitted:   AtomicU64,
    pub cap_inheritable: AtomicU64,
    pub cap_ambient:     AtomicU64,
    pub cap_bounding:    AtomicU64,
    /// Linux securebits (SECBIT_* flags + their locks) per
    /// `prctl(PR_SET_SECUREBITS)`. Capability and uid-transition code
    /// consult this canonical state directly.
    pub securebits:      AtomicU32,
}

impl Creds {
    /// Linux `NGROUPS_MAX` (`include/uapi/linux/limits.h`): the largest
    /// supplementary group list `setgroups(2)` accepts.
    pub const NGROUPS_MAX: usize = 65536;

    /// Initial creds for a fresh task — root, no supplementary groups.
    /// # C: O(1)
    pub const fn root() -> Self {
        Self {
            ruid: AtomicU32::new(0), euid: AtomicU32::new(0),
            suid: AtomicU32::new(0), fsuid: AtomicU32::new(0),
            rgid: AtomicU32::new(0), egid: AtomicU32::new(0),
            sgid: AtomicU32::new(0), fsgid: AtomicU32::new(0),
            groups: Spinlock::new(None),
            cap_effective:   AtomicU64::new(Self::CAP_FULL),
            cap_permitted:   AtomicU64::new(Self::CAP_FULL),
            cap_inheritable: AtomicU64::new(0),
            cap_ambient:     AtomicU64::new(0),
            cap_bounding:    AtomicU64::new(Self::CAP_FULL),
            securebits:      AtomicU32::new(0),
        }
    }

    /// All-bits-set bounding/permitted mask for v1 root tasks. Linux
    /// has ~40 capability bits defined; storing 64 leaves room for
    /// future additions and matches the v3 capset ABI shape exactly.
    pub const CAP_FULL: u64 = 0xFFFF_FFFF_FFFF_FFFF;

    /// Snapshot for fork/clone — copies every field and SHARES the
    /// supplementary group list (Linux `get_group_info`: `group_info` is
    /// copy-on-write, so a fork never duplicates the array). Caller is the
    /// running parent task, preempt-off; child task is not yet scheduled.
    /// # SAFETY: caller holds the single-mutator invariant on `self`.
    /// # C: O(1)
    pub unsafe fn snapshot(&self) -> Self {
        use core::sync::atomic::Ordering::Relaxed;
        let out = Self {
            ruid:  AtomicU32::new(self.ruid.load(Relaxed)),
            euid:  AtomicU32::new(self.euid.load(Relaxed)),
            suid:  AtomicU32::new(self.suid.load(Relaxed)),
            fsuid: AtomicU32::new(self.fsuid.load(Relaxed)),
            rgid:  AtomicU32::new(self.rgid.load(Relaxed)),
            egid:  AtomicU32::new(self.egid.load(Relaxed)),
            sgid:  AtomicU32::new(self.sgid.load(Relaxed)),
            fsgid: AtomicU32::new(self.fsgid.load(Relaxed)),
            groups: Spinlock::new(self.group_list()),
            cap_effective:   AtomicU64::new(self.cap_effective.load(Relaxed)),
            cap_permitted:   AtomicU64::new(self.cap_permitted.load(Relaxed)),
            cap_inheritable: AtomicU64::new(self.cap_inheritable.load(Relaxed)),
            cap_ambient:     AtomicU64::new(self.cap_ambient.load(Relaxed)),
            cap_bounding:    AtomicU64::new(self.cap_bounding.load(Relaxed)),
            securebits:      AtomicU32::new(self.securebits.load(Relaxed)),
        };
        out
    }

    /// Share the current supplementary group list (Linux `get_group_info`).
    /// # C: O(1); # Lk: TaskList
    pub fn group_list(&self) -> GroupList { self.groups.lock().clone() }

    /// Install a new supplementary group list (Linux `set_groups`).
    /// # C: O(1); # Lk: TaskList
    pub fn set_group_list(&self, list: GroupList) { *self.groups.lock() = list; }

    /// Supplementary group count (Linux `cred->group_info->ngroups`).
    /// # C: O(1); # Lk: TaskList
    pub fn ngroups(&self) -> usize {
        self.groups.lock().as_ref().map(|g| g.len()).unwrap_or(0)
    }

    /// Copy the supplementary group list into `out`, returning the count
    /// written. Truncates to `out.len()` for the fixed-width snapshot
    /// consumers (`vfs::Cred`, IPC, quota).
    /// # C: O(min(ngroups, out.len())); # Lk: TaskList
    pub fn copy_groups(&self, out: &mut [u32]) -> usize {
        let guard = self.groups.lock();
        let Some(list) = guard.as_ref() else { return 0; };
        let n = list.len().min(out.len());
        out[..n].copy_from_slice(&list[..n]);
        n
    }

    /// Linux `groups_search`: binary search over the sorted list.
    /// # C: O(log ngroups); # Lk: TaskList
    pub fn in_supplementary_group(&self, gid: u32) -> bool {
        let guard = self.groups.lock();
        guard.as_ref().is_some_and(|list| list.binary_search(&gid).is_ok())
    }

    /// Build the fixed-width `vfs::Cred` DAC snapshot Linux's permission
    /// checks consume. THE construction site: every crate that needs a
    /// caller credential comes through here rather than reassembling one
    /// from the individual `creds` fields.
    /// # C: O(CRED_NGROUPS); # Lk: TaskList
    pub fn to_vfs_cred(&self, uid: u32, gid: u32, effective: u64) -> vfs::Cred {
        let mut groups = [0u32; vfs::CRED_NGROUPS];
        let ngroups = self.copy_groups(&mut groups);
        let has = |capability: u32| effective & (1u64 << capability) != 0;
        vfs::Cred {
            uid, gid,
            cap_dac_override: has(super::cap::DAC_OVERRIDE),
            cap_dac_read_search: has(super::cap::DAC_READ_SEARCH),
            cap_fowner: has(super::cap::FOWNER), cap_chown: has(super::cap::CHOWN),
            cap_fsetid: has(super::cap::FSETID), ngroups: ngroups as u32, groups,
        }
    }

    /// Linux `cred_cap_issubset(set, subset)` restricted to one user
    /// namespace: true when `permitted` gained no bit over `old_permitted`.
    /// # C: O(1)
    pub fn cap_permitted_is_subset_of(&self, old_permitted: u64) -> bool {
        self.cap_permitted.load(Ordering::Acquire) & !old_permitted == 0
    }

    /// True when the effective uid is root (uid 0). Used by setuid
    /// permission checks: root may set ids freely; non-root may only
    /// transition between {ruid, euid, suid}.
    /// # C: O(1)
    pub fn is_root(&self) -> bool {
        self.euid.load(core::sync::atomic::Ordering::Acquire) == 0
    }

    /// True when securebits retains permitted capabilities over a uid drop.
    /// # C: O(1)
    pub fn keeps_caps(&self) -> bool {
        self.securebits.load(core::sync::atomic::Ordering::Acquire)
            & securebits::SECBIT_KEEP_CAPS != 0
    }

}

impl Task {
    /// Linux clears `SECBIT_KEEP_CAPS` at every successful execve. The lock
    /// bit remains, so a task that locked KEEP_CAPS cannot re-enable it after
    /// exec.
    /// # C: O(1)
    pub fn clear_keep_caps_after_exec(&self) {
        use core::sync::atomic::Ordering;
        self.creds.securebits.fetch_and(!securebits::SECBIT_KEEP_CAPS, Ordering::AcqRel);
    }

    /// True when this task holds capability `cap` in its effective
    /// set. Linux capability numbers per `task::cap` consts.
    /// # C: O(1)
    pub fn has_cap(&self, cap: u32) -> bool {
        self.creds.has_cap(cap)
    }
}

impl Creds {
    /// True when this Creds holds capability `cap` in its effective
    /// set. v1 single-bit check.
    /// # C: O(1)
    pub fn has_cap(&self, cap: u32) -> bool {
        if cap >= 64 { return false; }
        (self.cap_effective.load(core::sync::atomic::Ordering::Acquire) >> cap) & 1 == 1
    }
}
