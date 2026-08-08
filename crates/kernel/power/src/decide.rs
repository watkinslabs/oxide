// Pure `reboot(2)` decisions, matching Linux's reboot syscall and its
// pid-namespace reboot handling.
//
// Kept out of the syscall slot (which is `#![cfg(target_os = "oxide-kernel")]`
// and therefore untestable) and out of the machine layer (which cannot be run
// hosted at all — every branch ends in a triple fault or a PSCI call).

use crate::uapi::*;

/// Failure classes the reboot path reports at the ABI boundary.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, Perm, Io }

pub type KResult<T> = core::result::Result<T, Error>;

/// Terminal machine transition selected by a reboot command.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TerminalCmd { Restart, PowerOff, Halt }

/// What a valid `cmd` asks the machine to do.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RebootAction {
    /// Irreversible transition.
    Terminal(TerminalCmd),
    /// `LINUX_REBOOT_CMD_RESTART2`: read the command string from `arg` first,
    /// then restart. Split out because the copy-in can fail with EFAULT AFTER
    /// the magic and capability checks have passed but BEFORE anything
    /// irreversible happens.
    Restart2,
    /// `CAD_ON` / `CAD_OFF`: latch the Ctrl-Alt-Del disposition, return 0.
    SetCad(bool),
}

/// Validate the `reboot(2)` magic pair. Four
/// distinct MAGIC2 values are accepted, all of them dates.
/// # C: O(1)
pub fn check_magic(magic1: u32, magic2: u32) -> bool {
    magic1 == LINUX_REBOOT_MAGIC1
        && (magic2 == LINUX_REBOOT_MAGIC2
            || magic2 == LINUX_REBOOT_MAGIC2A
            || magic2 == LINUX_REBOOT_MAGIC2B
            || magic2 == LINUX_REBOOT_MAGIC2C)
}

/// `reboot(2)`'s admission ladder, in Linux's order:
/// CAP_SYS_BOOT FIRST, the magic pair SECOND.
///
/// The order is observable and is the whole difference between "you may not
/// reboot this machine" and "your magic numbers are wrong". An unprivileged
/// `reboot(0, 0, 0, 0)` — the shape a fuzzer or a confused caller produces —
/// is EPERM on Linux; checking the magic first answers EINVAL and tells a
/// caller with no CAP_SYS_BOOT something about the kernel's expectations.
/// # C: O(1)
pub fn reboot_precheck(cap_sys_boot: bool, magic1: u32, magic2: u32) -> KResult<()> {
    if !cap_sys_boot { return Err(Error::Perm); }
    if !check_magic(magic1, magic2) { return Err(Error::Inval); }
    Ok(())
}

/// Classify a `cmd` for a caller in the INITIAL pid namespace.
///
/// `SW_SUSPEND` and `KEXEC` fall through to `default: ret = -EINVAL` unless
/// `CONFIG_HIBERNATION` / `CONFIG_KEXEC_CORE` are set, so EINVAL is the
/// unconditional answer here — not a stub, the same answer a kernel built
/// without those options gives.
/// # C: O(1)
pub fn classify_cmd(cmd: u32) -> KResult<RebootAction> {
    match cmd {
        LINUX_REBOOT_CMD_RESTART => Ok(RebootAction::Terminal(TerminalCmd::Restart)),
        LINUX_REBOOT_CMD_RESTART2 => Ok(RebootAction::Restart2),
        LINUX_REBOOT_CMD_POWER_OFF => Ok(RebootAction::Terminal(TerminalCmd::PowerOff)),
        LINUX_REBOOT_CMD_HALT => Ok(RebootAction::Terminal(TerminalCmd::Halt)),
        LINUX_REBOOT_CMD_CAD_ON => Ok(RebootAction::SetCad(true)),
        LINUX_REBOOT_CMD_CAD_OFF => Ok(RebootAction::SetCad(false)),
        _ => Err(Error::Inval),
    }
}

/// Signal a child pid namespace records when one of its members calls
/// `reboot(2)`. The namespace's init exits
/// with this as its group exit code, which is how a supervisor outside the
/// namespace learns "reboot" from "poweroff".
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NsRebootSignal { Hup, Int }

impl NsRebootSignal {
    /// Linux signal number stored in `pid_ns->reboot`. # C: O(1)
    pub const fn signo(self) -> i32 {
        match self { Self::Hup => 1, Self::Int => 2 }
    }
}

/// `reboot_pid_ns` for a caller OUTSIDE the initial pid namespace:
/// the machine is never touched. RESTART /
/// RESTART2 record SIGHUP, POWER_OFF / HALT record SIGINT, and every other
/// command — INCLUDING `CAD_ON`/`CAD_OFF`, which succeed in the initial
/// namespace — is EINVAL. On success Linux SIGKILLs the namespace's
/// `child_reaper` and the caller `do_exit(0)`s, so this function returning
/// `Ok` means "the caller does not come back".
/// # C: O(1)
pub fn pid_ns_reboot(cmd: u32) -> KResult<NsRebootSignal> {
    match cmd {
        LINUX_REBOOT_CMD_RESTART | LINUX_REBOOT_CMD_RESTART2 => Ok(NsRebootSignal::Hup),
        LINUX_REBOOT_CMD_POWER_OFF | LINUX_REBOOT_CMD_HALT => Ok(NsRebootSignal::Int),
        _ => Err(Error::Inval),
    }
}

/// Truncate a user-supplied `RESTART2` command string the way
/// `strncpy_from_user(&buffer[0], arg, sizeof(buffer) - 1)` followed by
/// `buffer[sizeof(buffer) - 1] = '\0'` does: at most 255 bytes are kept, an
/// embedded NUL ends the string, and an over-long string is silently cut —
/// there is no ENAMETOOLONG on this path.
/// # C: O(RESTART2_CMD_BYTES)
pub fn restart2_cmd_len(raw: &[u8; RESTART2_CMD_BYTES]) -> usize {
    let max = RESTART2_CMD_BYTES - 1;
    let mut n = 0;
    while n < max && raw[n] != 0 { n += 1; }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic2_hex_matches_the_headers_decimal_spelling() {
        assert_eq!(LINUX_REBOOT_MAGIC1, 0xfee1dead);
        assert_eq!(LINUX_REBOOT_MAGIC2, 672274793);
        assert_eq!(LINUX_REBOOT_MAGIC2A, 85072278);
        assert_eq!(LINUX_REBOOT_MAGIC2B, 369367448);
        assert_eq!(LINUX_REBOOT_MAGIC2C, 537993216);
    }

    #[test]
    fn all_four_magic2_values_are_accepted_and_nothing_else() {
        for m2 in [LINUX_REBOOT_MAGIC2, LINUX_REBOOT_MAGIC2A,
                   LINUX_REBOOT_MAGIC2B, LINUX_REBOOT_MAGIC2C] {
            assert!(check_magic(LINUX_REBOOT_MAGIC1, m2));
            // magic1 must still match.
            assert!(!check_magic(0xdead_fee1, m2));
        }
        assert!(!check_magic(LINUX_REBOOT_MAGIC1, 0));
        assert!(!check_magic(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2 + 1));
    }

    #[test]
    fn the_capability_check_precedes_the_magic_check() {
        // Both wrong -> EPERM, because `ns_capable(CAP_SYS_BOOT)` runs first,
        // ahead of the magic-pair check.
        assert_eq!(reboot_precheck(false, 0, 0), Err(Error::Perm));
        assert_eq!(reboot_precheck(false, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2),
                   Err(Error::Perm));
        // Privileged with bad magic -> EINVAL.
        assert_eq!(reboot_precheck(true, 0, 0), Err(Error::Inval));
        assert_eq!(reboot_precheck(true, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2), Ok(()));
    }

    #[test]
    fn cad_on_and_cad_off_are_the_only_non_terminal_successes() {
        assert_eq!(classify_cmd(LINUX_REBOOT_CMD_CAD_ON), Ok(RebootAction::SetCad(true)));
        assert_eq!(classify_cmd(LINUX_REBOOT_CMD_CAD_OFF), Ok(RebootAction::SetCad(false)));
        // CAD_OFF is literally 0 — the value an uninitialised argument has.
        assert_eq!(LINUX_REBOOT_CMD_CAD_OFF, 0);
    }

    #[test]
    fn restart2_is_not_classified_as_a_plain_restart() {
        // It must stay distinguishable: the command string is copied from user
        // memory BEFORE the machine is touched, and that copy can fail.
        assert_eq!(classify_cmd(LINUX_REBOOT_CMD_RESTART2), Ok(RebootAction::Restart2));
        assert_eq!(classify_cmd(LINUX_REBOOT_CMD_RESTART),
                   Ok(RebootAction::Terminal(TerminalCmd::Restart)));
    }

    #[test]
    fn kexec_and_sw_suspend_are_einval_without_their_config() {
        assert_eq!(classify_cmd(LINUX_REBOOT_CMD_KEXEC), Err(Error::Inval));
        assert_eq!(classify_cmd(LINUX_REBOOT_CMD_SW_SUSPEND), Err(Error::Inval));
        assert_eq!(classify_cmd(0xDEAD_BEEF), Err(Error::Inval));
    }

    #[test]
    fn a_child_pid_namespace_maps_restart_to_sighup_and_halt_to_sigint() {
        assert_eq!(pid_ns_reboot(LINUX_REBOOT_CMD_RESTART), Ok(NsRebootSignal::Hup));
        assert_eq!(pid_ns_reboot(LINUX_REBOOT_CMD_RESTART2), Ok(NsRebootSignal::Hup));
        assert_eq!(pid_ns_reboot(LINUX_REBOOT_CMD_POWER_OFF), Ok(NsRebootSignal::Int));
        assert_eq!(pid_ns_reboot(LINUX_REBOOT_CMD_HALT), Ok(NsRebootSignal::Int));
        assert_eq!(NsRebootSignal::Hup.signo(), 1);
        assert_eq!(NsRebootSignal::Int.signo(), 2);
    }

    #[test]
    fn a_child_pid_namespace_rejects_cad_which_the_initial_one_accepts() {
        // `reboot_pid_ns`'s switch has no CAD arms, so they hit `default:
        // return -EINVAL`. Sharing one classifier between the two namespaces
        // would silently make CAD_ON succeed inside a container.
        assert_eq!(pid_ns_reboot(LINUX_REBOOT_CMD_CAD_ON), Err(Error::Inval));
        assert_eq!(pid_ns_reboot(LINUX_REBOOT_CMD_CAD_OFF), Err(Error::Inval));
        assert!(classify_cmd(LINUX_REBOOT_CMD_CAD_ON).is_ok());
    }

    #[test]
    fn the_restart2_string_is_truncated_at_255_bytes_not_rejected() {
        let mut raw = [b'x'; RESTART2_CMD_BYTES];
        assert_eq!(restart2_cmd_len(&raw), 255);
        raw[3] = 0;
        assert_eq!(restart2_cmd_len(&raw), 3);
        assert_eq!(restart2_cmd_len(&[0u8; RESTART2_CMD_BYTES]), 0);
    }
}
