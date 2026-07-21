use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64};

use super::Task;

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
    pub ngroups: AtomicU32,
    pub groups:  UnsafeCell<[u32; Creds::NGROUPS_V1]>,

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
    pub const NGROUPS_V1: usize = 32;
    pub const SECURE_KEEP_CAPS: u32 = 4;
    pub const SECBIT_KEEP_CAPS: u32 = 1 << Self::SECURE_KEEP_CAPS;
    pub const SECBIT_KEEP_CAPS_LOCKED: u32 = 1 << (Self::SECURE_KEEP_CAPS + 1);
    pub const SECBIT_NO_CAP_AMBIENT_RAISE: u32 = 1 << 6;

    /// Initial creds for a fresh task — root, no supplementary groups.
    /// # C: O(1)
    pub const fn root() -> Self {
        Self {
            ruid: AtomicU32::new(0), euid: AtomicU32::new(0),
            suid: AtomicU32::new(0), fsuid: AtomicU32::new(0),
            rgid: AtomicU32::new(0), egid: AtomicU32::new(0),
            sgid: AtomicU32::new(0), fsgid: AtomicU32::new(0),
            ngroups: AtomicU32::new(0),
            groups: UnsafeCell::new([0u32; Self::NGROUPS_V1]),
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

    /// Snapshot for fork/clone — copies every field including
    /// supplementary group list. Caller is the running parent task,
    /// preempt-off; child task is not yet scheduled (no concurrent
    /// reader on the new Creds).
    /// # SAFETY: caller holds the single-mutator invariant on `self`.
    /// # C: O(NGROUPS_V1)
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
            ngroups: AtomicU32::new(self.ngroups.load(Relaxed)),
            groups:  UnsafeCell::new([0u32; Self::NGROUPS_V1]),
            cap_effective:   AtomicU64::new(self.cap_effective.load(Relaxed)),
            cap_permitted:   AtomicU64::new(self.cap_permitted.load(Relaxed)),
            cap_inheritable: AtomicU64::new(self.cap_inheritable.load(Relaxed)),
            cap_ambient:     AtomicU64::new(self.cap_ambient.load(Relaxed)),
            cap_bounding:    AtomicU64::new(self.cap_bounding.load(Relaxed)),
            securebits:      AtomicU32::new(self.securebits.load(Relaxed)),
        };
        // SAFETY: caller holds the single-mutator invariant; we just
        // built `out` and no other CPU has observed it yet, so writing
        // its `groups` UnsafeCell is sound.
        unsafe {
            let dst = &mut *out.groups.get();
            let src = &*self.groups.get();
            dst.copy_from_slice(src);
        }
        out
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
            & Self::SECBIT_KEEP_CAPS != 0
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
