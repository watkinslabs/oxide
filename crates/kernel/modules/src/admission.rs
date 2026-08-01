// Module-syscall admission: Linux `kernel/module/main.c may_init_module()`
// plus the `kernel.modules_disabled` variable it reads.
//
// Kept out of the syscall slot files (which are `#![cfg(target_os =
// "oxide-kernel")]`, so tests there compile out silently) and out of
// `registry.rs` (already near the file cap): the admission LADDER is the whole
// security contract of `init_module`/`finit_module`/`delete_module` and has to
// be provable hosted.

use core::sync::atomic::{AtomicBool, Ordering};

/// Linux `MODULE_NAME_LEN` = `64 - sizeof(unsigned long)`
/// (`include/linux/moduleparam.h __MODULE_NAME_LEN`). `delete_module` copies at
/// most this many bytes and treats a full buffer as "no such module".
pub const MODULE_NAME_LEN: usize = 64 - core::mem::size_of::<u64>();

/// `finit_module` flag: skip the `__versions` CRC check.
pub const MODULE_INIT_IGNORE_MODVERSIONS: u64 = 1;
/// `finit_module` flag: skip the vermagic string comparison.
pub const MODULE_INIT_IGNORE_VERMAGIC: u64 = 2;
/// `finit_module` flag: the fd holds a compressed image to be decompressed first.
pub const MODULE_INIT_COMPRESSED_FILE: u64 = 4;

/// Every flag `finit_module` accepts; anything else is EINVAL.
pub const MODULE_INIT_FLAGS_ALL: u64 =
    MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC | MODULE_INIT_COMPRESSED_FILE;

/// `delete_module` flag reusing `O_TRUNC`: force-unload a module whose
/// reference count is non-zero (`try_force_unload`).
pub const DELETE_MODULE_FORCE: u64 = 0o1000;

/// Linux `static int modules_disabled` (`kernel/module/main.c`), exported as
/// `/proc/sys/kernel/modules_disabled`. A one-way latch: hardened systems set
/// it once at boot and no later write can clear it.
static MODULES_DISABLED: AtomicBool = AtomicBool::new(false);

/// Current `kernel.modules_disabled` value. # C: O(1)
pub fn modules_disabled() -> bool { MODULES_DISABLED.load(Ordering::Acquire) }

/// `/proc/sys/kernel/modules_disabled` write hook. Linux binds the leaf with
/// `extra1 = extra2 = SYSCTL_ONE`, i.e. only the 0→1 transition is accepted —
/// writing 0 is rejected by the range check, so the latch can never be
/// released. Returns whether the write was accepted, mirroring
/// `proc_dointvec_minmax`'s EINVAL for an out-of-window value.
/// # C: O(1)
pub fn set_modules_disabled(value: i64) -> bool {
    if value != 1 { return false; }
    MODULES_DISABLED.store(true, Ordering::Release);
    true
}

/// Why a module operation was refused, in the order Linux tests.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Admission {
    /// `may_init_module()` passed.
    Allow,
    /// `!capable(CAP_SYS_MODULE) || modules_disabled` — Linux returns EPERM
    /// here, and EPERM is TRUE for this one: the operation exists, the caller
    /// simply is not allowed to perform it. `modules_disabled` collapses into
    /// the same errno by Linux's own construction.
    Denied,
}

/// Linux `may_init_module()` as a pure decision over both of its inputs, so
/// the ladder is provable without touching the process-wide latch:
/// `if (!capable(CAP_SYS_MODULE) || modules_disabled) return -EPERM;`
/// # C: O(1)
pub fn admit(has_cap_sys_module: bool, disabled: bool) -> Admission {
    if !has_cap_sys_module || disabled { return Admission::Denied; }
    Admission::Allow
}

/// Linux `may_init_module()` against the live `modules_disabled` latch.
///
/// Both `init_module` and `finit_module` call it FIRST — before argument
/// validation, before the fd lookup, before any read of the image — so an
/// unprivileged caller can learn nothing about the arguments it passed.
/// `delete_module` open-codes the identical pair of tests.
/// # C: O(1)
pub fn may_init_module(has_cap_sys_module: bool) -> Admission {
    admit(has_cap_sys_module, modules_disabled())
}

/// `finit_module` flag validation, run AFTER `may_init_module` (Linux tests
/// capability first, then `flags & ~(...)` → EINVAL).
/// # C: O(1)
pub fn finit_flags_valid(flags: u64) -> bool { flags & !MODULE_INIT_FLAGS_ALL == 0 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_len_matches_linux_64bit() {
        let _modules = crate::test_serial::claim();
        // __MODULE_NAME_LEN = 64 - sizeof(unsigned long) = 56 on LP64.
        assert_eq!(MODULE_NAME_LEN, 56);
    }

    /// The hole this lane closed: before F757 the three module syscalls ran no
    /// capability test at all, so ANY unprivileged process could relocate and
    /// execute arbitrary bytes in ring 0.
    #[test]
    fn a_caller_without_cap_sys_module_is_denied() {
        let _modules = crate::test_serial::claim();
        assert_eq!(admit(false, false), Admission::Denied);
        assert_eq!(admit(true, false), Admission::Allow);
        // The latch denies even a fully capable caller.
        assert_eq!(admit(true, true), Admission::Denied);
    }

    #[test]
    fn finit_flags_window_matches_linux() {
        let _modules = crate::test_serial::claim();
        for f in [0, 1, 2, 4, 7] { assert!(finit_flags_valid(f), "flags {f} are accepted by Linux"); }
        for f in [8, 0x10, u64::MAX] { assert!(!finit_flags_valid(f), "flags {f} must be EINVAL"); }
    }

    /// The latch is one-way by Linux's own `extra1 = extra2 = SYSCTL_ONE`
    /// binding: a write of 0 (or anything but 1) is rejected outright rather
    /// than quietly re-enabling module loading on a hardened system.
    #[test]
    fn modules_disabled_latch_rejects_every_value_but_one() {
        let _modules = crate::test_serial::claim();
        assert!(!set_modules_disabled(0));
        assert!(!set_modules_disabled(2));
        assert!(!set_modules_disabled(-1));
        assert!(!modules_disabled(), "a rejected write must not move the latch");
        assert!(set_modules_disabled(1));
        assert!(modules_disabled());
        // Still latched: the release path does not exist.
        assert!(!set_modules_disabled(0));
        assert!(modules_disabled());
        // Once set, EVERY module operation is denied regardless of capability.
        assert_eq!(may_init_module(true), Admission::Denied);
        assert_eq!(may_init_module(false), Admission::Denied);
    }
}
