// Typed signal numbers + signal(7) default-disposition policy.
//
// Pure (no kernel/runqueue state) so the SIG_DFL-terminate decision and
// the killed-by-signal wait-status encoding are provable by
// `cargo test -p sched`, not only at QEMU boot. `Signum` used to live in
// the kernel-only `live::sigpend` module, which made it hosted-unreachable;
// it moved here so the policy below can be unit-tested. `live::sigpend`
// re-exports `Signum`, so every `sched::live::sigpend::Signum` call site
// keeps resolving unchanged.
//
// Numeric values match the Linux uapi `<asm-generic/signal.h>`. This is the
// typed alternative to raw signo literals (CLAUDE.md `07§5`): NEVER open-code
// a bare signal number — route through `Signum` / the helpers here.

/// Full POSIX-1.2024 standard signal set per Linux signal(7). NEVER add a
/// case without checking signal(7) — a silent off-by-one mis-routes handlers.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum Signum {
    Sighup    = 1,
    Sigint    = 2,
    Sigquit   = 3,
    Sigill    = 4,
    Sigtrap   = 5,
    Sigabrt   = 6,        // also SIGIOT
    Sigbus    = 7,
    Sigfpe    = 8,
    Sigkill   = 9,
    Sigusr1   = 10,
    Sigsegv   = 11,
    Sigusr2   = 12,
    Sigpipe   = 13,
    Sigalrm   = 14,
    Sigterm   = 15,
    Sigstkflt = 16,
    Sigchld   = 17,
    Sigcont   = 18,
    Sigstop   = 19,
    Sigtstp   = 20,
    Sigttin   = 21,
    Sigttou   = 22,
    Sigurg    = 23,
    Sigxcpu   = 24,
    Sigxfsz   = 25,
    Sigvtalrm = 26,
    Sigprof   = 27,
    Sigwinch  = 28,
    Sigio     = 29,        // also SIGPOLL
    Sigpwr    = 30,
    Sigsys    = 31,        // also SIGUNUSED
}

impl Signum {
    /// Linux signo (1-based).
    /// # C: O(1)
    pub const fn as_u8(self) -> u8 { self as u8 }
    /// Bit index in the `Task::sigpending` u64 (0-based).
    /// # C: O(1)
    pub const fn bit(self) -> u64 { 1u64 << (self.as_u8() - 1) }
}

/// Linux real-time signal interval used by this kernel ABI.
pub const RT_SIGNAL_MIN: u32 = 33;
pub const RT_SIGNAL_MAX: u32 = 64;

pub const fn is_realtime(sig: u32) -> bool {
    sig >= RT_SIGNAL_MIN && sig <= RT_SIGNAL_MAX
}

pub const fn rt_index(sig: u32) -> Option<usize> {
    if is_realtime(sig) { Some((sig - RT_SIGNAL_MIN) as usize) } else { None }
}

/// Pending-mask bit for a Linux signo, including standard and real-time signals.
/// # C: O(1)
pub const fn bit_for(signo: u32) -> Option<u64> {
    if signo == 0 || signo > RT_SIGNAL_MAX { None } else { Some(1u64 << (signo - 1)) }
}

/// signal(7) default disposition for a signal whose handler is SIG_DFL.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DefaultAction {
    /// Terminate the process (no core).
    Term,
    /// Terminate the process AND dump core.
    Core,
    /// Ignore (discard).
    Ign,
    /// Stop (job control).
    Stop,
    /// Continue if stopped.
    Cont,
}

/// Internal `Task::exit_status` / wait-status encoding bits (the encoding
/// `zombies::push_child_event` and `sys_wait4` decode). Bit 8 = "killed by
/// signal" marker; bit 7 = core dumped. Named per `07§5` (no bare 0x100/0x80).
pub const WSTATUS_SIGNALED: i32 = 0x100;
/// Core-dumped flag within the killed-by-signal wait status.
pub const WSTATUS_CORE: i32 = 0x80;

/// SIGKILL and SIGSTOP — never blockable, never catchable (signal(7)). They
/// must be surfaced for delivery even when masked and forced to SIG_DFL even
/// if a handler-table slot somehow holds one.
/// # C: O(1)
pub fn is_unblockable(sig: u32) -> bool {
    sig == Signum::Sigkill as u32 || sig == Signum::Sigstop as u32
}

/// signal(7) default action for `sig` (the action taken when the disposition
/// is SIG_DFL). Standard signals not explicitly Ignore/Stop/Cont/Core default
/// to Term (SIGHUP/SIGINT/SIGKILL/SIGUSR1/SIGSEGV-handled-below/SIGPIPE/
/// SIGALRM/SIGTERM/...). RT signals (>=32) default to Term.
/// # C: O(1)
pub fn default_action(sig: u32) -> DefaultAction {
    let s = sig as u8;
    // Default-ignore set.
    if s == Signum::Sigchld as u8 || s == Signum::Sigurg as u8 || s == Signum::Sigwinch as u8 {
        return DefaultAction::Ign;
    }
    // Continue-if-stopped.
    if s == Signum::Sigcont as u8 { return DefaultAction::Cont; }
    // Job-control stop set.
    if s == Signum::Sigstop as u8 || s == Signum::Sigtstp as u8
        || s == Signum::Sigttin as u8 || s == Signum::Sigttou as u8 {
        return DefaultAction::Stop;
    }
    // Terminate-with-core set.
    if s == Signum::Sigquit as u8 || s == Signum::Sigill as u8 || s == Signum::Sigtrap as u8
        || s == Signum::Sigabrt as u8 || s == Signum::Sigbus as u8 || s == Signum::Sigfpe as u8
        || s == Signum::Sigsegv as u8 || s == Signum::Sigxcpu as u8 || s == Signum::Sigxfsz as u8
        || s == Signum::Sigsys as u8 {
        return DefaultAction::Core;
    }
    DefaultAction::Term
}

/// Bitmask of the unblockable signals (SIGKILL | SIGSTOP).
const UNBLOCKABLE_MASK: u64 = Signum::Sigkill.bit() | Signum::Sigstop.bit();

/// Lowest-numbered signal eligible for delivery from `pending` given the
/// current `masked` set, or `None` when nothing is deliverable. SIGKILL and
/// SIGSTOP bypass the mask (signal(7) unblockable) so a masked fatal signal
/// can never wedge a task unkillable. Lowest-first matches Linux `next_signal`;
/// since every signal below SIGKILL (1..=8) is itself fatal-by-default, this
/// gives SIGKILL effective priority over any catchable signal.
/// # C: O(1)
pub fn next_deliverable(pending: u64, masked: u64) -> Option<u32> {
    let deliver = (pending & !masked) | (pending & UNBLOCKABLE_MASK);
    if deliver == 0 { return None; }
    Some(deliver.trailing_zeros() + 1)
}

/// Encode the `Task::exit_status` for a task terminated by signal `sig`
/// (default fatal action): low 7 bits = signo, `WSTATUS_SIGNALED` marker set,
/// `WSTATUS_CORE` set for the core-dumping signals (SIGABRT/SIGSEGV/SIGQUIT/...).
/// `wait4`/`waitid` decode this into WIFSIGNALED / WTERMSIG / WCOREDUMP and
/// CLD_KILLED vs CLD_DUMPED. Single source of truth for both the syscall-tail
/// SIG_DFL terminate and the page-fault `terminate_current_with_signal`.
/// # C: O(1)
pub fn killed_status(sig: u32) -> i32 {
    let core = matches!(default_action(sig), DefaultAction::Core);
    (sig as i32) | WSTATUS_SIGNALED | if core { WSTATUS_CORE } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_for_covers_standard_and_realtime_bounds() {
        assert_eq!(bit_for(0), None);
        assert_eq!(bit_for(1), Some(1));
        assert_eq!(bit_for(RT_SIGNAL_MAX), Some(1u64 << 63));
        assert_eq!(bit_for(RT_SIGNAL_MAX + 1), None);
    }

    #[test]
    fn default_action_table_matches_signal7() {
        // Terminate (no core).
        for s in [Signum::Sighup, Signum::Sigint, Signum::Sigkill, Signum::Sigusr1,
                  Signum::Sigpipe, Signum::Sigalrm, Signum::Sigterm, Signum::Sigusr2] {
            assert_eq!(default_action(s as u32), DefaultAction::Term, "{:?}", s);
        }
        // Terminate + core.
        for s in [Signum::Sigquit, Signum::Sigill, Signum::Sigtrap, Signum::Sigabrt,
                  Signum::Sigbus, Signum::Sigfpe, Signum::Sigsegv, Signum::Sigxcpu,
                  Signum::Sigxfsz, Signum::Sigsys] {
            assert_eq!(default_action(s as u32), DefaultAction::Core, "{:?}", s);
        }
        // Ignore.
        for s in [Signum::Sigchld, Signum::Sigurg, Signum::Sigwinch] {
            assert_eq!(default_action(s as u32), DefaultAction::Ign, "{:?}", s);
        }
        // Stop / Continue.
        for s in [Signum::Sigstop, Signum::Sigtstp, Signum::Sigttin, Signum::Sigttou] {
            assert_eq!(default_action(s as u32), DefaultAction::Stop, "{:?}", s);
        }
        assert_eq!(default_action(Signum::Sigcont as u32), DefaultAction::Cont);
        // RT signal defaults to Term.
        assert_eq!(default_action(40), DefaultAction::Term);
    }

    #[test]
    fn unblockable_is_kill_and_stop_only() {
        assert!(is_unblockable(Signum::Sigkill as u32));
        assert!(is_unblockable(Signum::Sigstop as u32));
        assert!(!is_unblockable(Signum::Sigterm as u32));
        assert!(!is_unblockable(Signum::Sigchld as u32));
    }

    #[test]
    fn next_deliverable_none_when_empty_or_all_masked() {
        assert_eq!(next_deliverable(0, 0), None);
        // A blockable signal that is masked is not deliverable.
        let term = Signum::Sigterm.bit();
        assert_eq!(next_deliverable(term, term), None);
    }

    #[test]
    fn next_deliverable_picks_lowest_unmasked() {
        let p = Signum::Sigterm.bit() | Signum::Sigusr1.bit();
        // SIGUSR1 = 10 < SIGTERM = 15.
        assert_eq!(next_deliverable(p, 0), Some(Signum::Sigusr1 as u32));
    }

    #[test]
    fn sigkill_surfaces_even_when_masked() {
        // The BOOT-B acceptance: SIGKILL terminates even if masked. A fully
        // masked task with SIGKILL pending must still surface signal 9.
        let p = Signum::Sigkill.bit();
        assert_eq!(next_deliverable(p, !0u64), Some(Signum::Sigkill as u32));
        // SIGSTOP likewise bypasses the mask.
        let ps = Signum::Sigstop.bit();
        assert_eq!(next_deliverable(ps, !0u64), Some(Signum::Sigstop as u32));
    }

    #[test]
    fn sigkill_wins_over_higher_masked_blockable() {
        // SIGKILL masked + a higher masked blockable pending: only SIGKILL
        // bypasses the mask, so it is the one surfaced.
        let p = Signum::Sigkill.bit() | Signum::Sigusr1.bit();
        assert_eq!(next_deliverable(p, !0u64), Some(Signum::Sigkill as u32));
    }

    #[test]
    fn killed_status_encodes_wifsignaled_and_coredump() {
        // SIGTERM: WIFSIGNALED, no core.
        let st = killed_status(Signum::Sigterm as u32);
        assert_ne!(st & WSTATUS_SIGNALED, 0);
        assert_eq!(st & 0x7f, Signum::Sigterm as i32);
        assert_eq!(st & WSTATUS_CORE, 0);
        // SIGKILL: WIFSIGNALED, no core.
        let sk = killed_status(Signum::Sigkill as u32);
        assert_eq!(sk & 0x7f, Signum::Sigkill as i32);
        assert_eq!(sk & WSTATUS_CORE, 0);
        // SIGABRT / SIGSEGV / SIGQUIT: WIFSIGNALED + core.
        for s in [Signum::Sigabrt, Signum::Sigsegv, Signum::Sigquit] {
            let c = killed_status(s as u32);
            assert_ne!(c & WSTATUS_SIGNALED, 0, "{:?}", s);
            assert_eq!(c & 0x7f, s as i32, "{:?}", s);
            assert_ne!(c & WSTATUS_CORE, 0, "{:?}", s);
        }
    }
}
