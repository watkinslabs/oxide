// The `/proc/sys/kernel/kexec_*` leaves' bindings.
//
// Ungated on purpose. The `/proc/sys` tree itself only compiles for the kernel
// target, so a test written beside it never runs; the three decisions these
// leaves carry all have a wrong answer that no boot would report:
//
//   * `kexec_load_disabled` is a ONE-WAY latch. A leaf that accepted `0` would
//     let a machine that has already refused to trust a replacement kernel be
//     talked back into loading one, and the file would still read back the
//     value that was written, so nothing would look wrong.
//   * the two load budgets may only ever be TIGHTENED. A leaf that accepted a
//     larger value would let whoever tightened the budget undo it, which is
//     the entire mechanism.
//   * a refused write must answer EINVAL rather than succeeding silently: a
//     hardening script that writes a value and reads back the success it did
//     not get believes a restriction is in force that is not.
//
// The bounds constants here are the ones the tree's leaf declarations use, so
// the leaf and these tests cannot describe different windows.

use crate::proc_handler::{CheckedIntHook, IntHook};

/// The only value `kexec_load_disabled` accepts. Writing it latches the
/// refusal for the rest of the boot; every other value is refused.
pub const LOAD_DISABLED_LATCH: i64 = 1;

/// `kexec_load_disabled`'s window. Both ends are the latch value, which is what
/// makes every other write — including `0` — fall outside it and answer EINVAL.
pub const LOAD_DISABLED_BOUNDS: (i64, i64) = (LOAD_DISABLED_LATCH, LOAD_DISABLED_LATCH);

/// The load budgets carry NO static window: `-1` (unlimited) must be readable
/// and every accept/refuse decision is relative to the CURRENT value, which a
/// min/max pair cannot express. The setter decides.
pub const LOAD_LIMIT_BOUNDS: Option<(i64, i64)> = None;

/// `kexec_load_disabled`, bound to the latch every load admission reads.
/// # C: O(1)
pub fn load_disabled() -> i64 { kexec::load_disabled() as i64 }

/// Latch the refusal. Only the latch value reaches here — the window rejects
/// everything else before the setter runs. # C: O(1)
pub fn set_load_disabled(_value: i64) { kexec::disable_load(); }

/// `kexec_load_limit_panic`: how many more crash images this boot will accept.
/// # C: O(1)
pub fn load_limit_panic() -> i64 { kexec::load_limit(kexec::ImageType::Crash) }

/// # C: O(1)
pub fn set_load_limit_panic(value: i64) -> Result<(), ()> {
    accepted(kexec::set_load_limit(kexec::ImageType::Crash, value))
}

/// `kexec_load_limit_reboot`: how many more reboot images this boot will
/// accept. A separate budget from the panic one — spending one must not spend
/// the other. # C: O(1)
pub fn load_limit_reboot() -> i64 { kexec::load_limit(kexec::ImageType::Default) }

/// # C: O(1)
pub fn set_load_limit_reboot(value: i64) -> Result<(), ()> {
    accepted(kexec::set_load_limit(kexec::ImageType::Default, value))
}

/// A refused tightening is `Err(())`, which the leaf reports as EINVAL.
fn accepted(ok: bool) -> Result<(), ()> { if ok { Ok(()) } else { Err(()) } }

/// The `kexec_load_disabled` leaf's handler, built exactly as the tree builds
/// it. # C: O(1)
pub fn load_disabled_handler() -> IntHook {
    IntHook { get: load_disabled, set: set_load_disabled, bounds: Some(LOAD_DISABLED_BOUNDS) }
}

/// The `kexec_load_limit_panic` leaf's handler. # C: O(1)
pub fn load_limit_panic_handler() -> CheckedIntHook {
    CheckedIntHook { get: load_limit_panic, set: set_load_limit_panic, bounds: LOAD_LIMIT_BOUNDS }
}

/// The `kexec_load_limit_reboot` leaf's handler. # C: O(1)
pub fn load_limit_reboot_handler() -> CheckedIntHook {
    CheckedIntHook { get: load_limit_reboot, set: set_load_limit_reboot, bounds: LOAD_LIMIT_BOUNDS }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc_handler::ProcHandler;

    // The three values these leaves bind to are process-global and one-way, so
    // each of the two statics is exercised by exactly ONE test: a second test
    // reading the same static would see whatever the first left behind, and
    // pass or fail on scheduling order.

    #[test]
    fn kexec_load_disabled_is_a_one_way_latch_that_refuses_every_other_value() {
        let h = load_disabled_handler();
        assert_eq!(h.format(), b"0\n".to_vec());
        // `0` is the value that would UNDO the latch. Refusing it is the whole
        // point; accepting it reads back as success and disarms the machine.
        assert_eq!(h.store(b"0\n"), Err(()));
        assert_eq!(h.store(b"2\n"), Err(()));
        assert_eq!(h.store(b"-1\n"), Err(()));
        assert_eq!(h.store(b"yes\n"), Err(()));
        assert_eq!(h.format(), b"0\n".to_vec());

        assert_eq!(h.store(b"1\n"), Ok(()));
        assert_eq!(h.format(), b"1\n".to_vec());
        assert!(kexec::load_disabled());

        // Still latched: the refusal survives a later write of any value.
        assert_eq!(h.store(b"0\n"), Err(()));
        assert_eq!(h.format(), b"1\n".to_vec());
        // Re-writing the latch value is accepted and changes nothing.
        assert_eq!(h.store(b"1\n"), Ok(()));
        assert_eq!(h.format(), b"1\n".to_vec());
    }

    #[test]
    fn each_load_budget_only_tightens_and_the_two_are_independent() {
        let panic = load_limit_panic_handler();
        let reboot = load_limit_reboot_handler();
        // `-1` is the initial unlimited state and prints as `-1`, not as a
        // large unsigned number: a reader that saw `18446744073709551615`
        // would believe a budget had been set.
        assert_eq!(panic.format(), b"-1\n".to_vec());
        assert_eq!(reboot.format(), b"-1\n".to_vec());

        // Unlimited accepts any non-negative value.
        assert_eq!(panic.store(b"5\n"), Ok(()));
        assert_eq!(panic.format(), b"5\n".to_vec());
        // The other budget is untouched — one file must not spend the other.
        assert_eq!(reboot.format(), b"-1\n".to_vec());

        // Raising, repeating, and restoring the unlimited sentinel are all
        // refused, and none of them moves the value.
        assert_eq!(panic.store(b"6\n"), Err(()));
        assert_eq!(panic.store(b"5\n"), Err(()));
        assert_eq!(panic.store(b"-1\n"), Err(()));
        assert_eq!(panic.store(b"nine\n"), Err(()));
        assert_eq!(panic.format(), b"5\n".to_vec());

        // Tightening further is accepted, down to and including zero.
        assert_eq!(panic.store(b"1\n"), Ok(()));
        assert_eq!(panic.store(b"0\n"), Ok(()));
        assert_eq!(panic.format(), b"0\n".to_vec());
        // An exhausted budget cannot be reopened.
        assert_eq!(panic.store(b"1\n"), Err(()));

        assert_eq!(reboot.store(b"3\n"), Ok(()));
        assert_eq!(reboot.format(), b"3\n".to_vec());
        assert_eq!(panic.format(), b"0\n".to_vec());
    }

    #[test]
    fn every_kexec_leaf_is_writable_and_world_readable() {
        // A read-only binding would make the whole surface a report rather
        // than a control, and the mode is derived from the handler.
        assert!(load_disabled_handler().writable());
        assert!(load_limit_panic_handler().writable());
        assert!(load_limit_reboot_handler().writable());
        assert!(!load_disabled_handler().owner_only());
        assert!(!load_limit_panic_handler().owner_only());
        assert!(!load_limit_reboot_handler().owner_only());
    }
}
