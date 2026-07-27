// `prctl(2)` option numbers and sub-values — `include/uapi/linux/prctl.h`.
// UAPI only: no dispatch, no policy, no state (`docs/07§5`).

pub const PR_SET_PDEATHSIG:       u64 = 1;
pub const PR_GET_PDEATHSIG:       u64 = 2;
pub const PR_GET_DUMPABLE:        u64 = 3;
pub const PR_SET_DUMPABLE:        u64 = 4;
pub const PR_GET_KEEPCAPS:        u64 = 7;
pub const PR_SET_KEEPCAPS:        u64 = 8;
pub const PR_GET_TIMING:          u64 = 13;
pub const PR_SET_TIMING:          u64 = 14;
pub const PR_SET_NAME:            u64 = 15;
pub const PR_GET_NAME:            u64 = 16;
pub const PR_GET_SECCOMP:         u64 = 21;
pub const PR_SET_SECCOMP:         u64 = 22;
pub const PR_CAPBSET_READ:        u64 = 23;
pub const PR_CAPBSET_DROP:        u64 = 24;
pub const PR_GET_TSC:             u64 = 25;
pub const PR_SET_TSC:             u64 = 26;
pub const PR_GET_SECUREBITS:      u64 = 27;
pub const PR_SET_SECUREBITS:      u64 = 28;
pub const PR_SET_TIMERSLACK:      u64 = 29;
pub const PR_GET_TIMERSLACK:      u64 = 30;
pub const PR_TASK_PERF_EVENTS_DISABLE: u64 = 31;
pub const PR_TASK_PERF_EVENTS_ENABLE:  u64 = 32;
pub const PR_MCE_KILL:            u64 = 33;
pub const PR_MCE_KILL_GET:        u64 = 34;
pub const PR_SET_MM:              u64 = 35;
pub const PR_SET_CHILD_SUBREAPER: u64 = 36;
pub const PR_GET_CHILD_SUBREAPER: u64 = 37;
pub const PR_SET_NO_NEW_PRIVS:    u64 = 38;
pub const PR_GET_NO_NEW_PRIVS:    u64 = 39;
pub const PR_GET_TID_ADDRESS:     u64 = 40;
pub const PR_SET_THP_DISABLE:     u64 = 41;
pub const PR_GET_THP_DISABLE:     u64 = 42;
pub const PR_MPX_ENABLE_MANAGEMENT:  u64 = 43;
pub const PR_MPX_DISABLE_MANAGEMENT: u64 = 44;
pub const PR_CAP_AMBIENT:         u64 = 47;
pub const PR_GET_SPECULATION_CTRL: u64 = 52;
pub const PR_SET_SPECULATION_CTRL: u64 = 53;
pub const PR_SET_VMA:             u64 = 0x5356_4d41;

/// `PR_TIMING_STATISTICAL` — the only accepted `PR_SET_TIMING` value and the
/// value `PR_GET_TIMING` reports. Zero, not one.
pub const PR_TIMING_STATISTICAL: u64 = 0;

/// `PR_TSC_ENABLE` / `PR_TSC_SIGSEGV` (`PR_GET_TSC` writes one of these
/// through its user pointer as an `unsigned int`).
pub const PR_TSC_ENABLE:  u32 = 1;
pub const PR_TSC_SIGSEGV: u32 = 2;

/// `PR_MCE_KILL` sub-commands (arg2) and policies (arg3).
pub const PR_MCE_KILL_CLEAR:   u64 = 0;
pub const PR_MCE_KILL_SET:     u64 = 1;
pub const PR_MCE_KILL_LATE:    u64 = 0;
pub const PR_MCE_KILL_EARLY:   u64 = 1;
pub const PR_MCE_KILL_DEFAULT: u64 = 2;

/// `PR_SET_THP_DISABLE` arg3 flag.
pub const PR_THP_DISABLE_EXCEPT_ADVISED: u64 = 1 << 1;

/// `PR_CAP_AMBIENT` sub-commands (arg2).
pub const PR_CAP_AMBIENT_IS_SET:   u64 = 1;
pub const PR_CAP_AMBIENT_RAISE:    u64 = 2;
pub const PR_CAP_AMBIENT_LOWER:    u64 = 3;
pub const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;

/// `PR_{GET,SET}_SPECULATION_CTRL` `which` selectors.
pub const PR_SPEC_STORE_BYPASS:    u64 = 0;
pub const PR_SPEC_INDIRECT_BRANCH: u64 = 1;
pub const PR_SPEC_L1D_FLUSH:       u64 = 2;

/// `PR_{GET,SET}_SPECULATION_CTRL` state bits.
pub const PR_SPEC_NOT_AFFECTED:   i64 = 0;
pub const PR_SPEC_PRCTL:          i64 = 1 << 0;
pub const PR_SPEC_ENABLE:         i64 = 1 << 1;
pub const PR_SPEC_DISABLE:        i64 = 1 << 2;
pub const PR_SPEC_FORCE_DISABLE:  i64 = 1 << 3;
pub const PR_SPEC_DISABLE_NOEXEC: i64 = 1 << 4;

/// `_NSIG` (`include/uapi/asm-generic/signal.h`) — the ceiling
/// `valid_signal()` compares against for `PR_SET_PDEATHSIG`.
pub const NSIG: u64 = 64;

/// `CAP_LAST_CAP` == `CAP_CHECKPOINT_RESTORE` (`include/uapi/linux/capability.h`).
/// `cap_valid(x)` is `x <= CAP_LAST_CAP`, NOT `x < 64`: capability numbers
/// 41..63 are unassigned and Linux answers EINVAL for them.
pub const CAP_LAST_CAP: u64 = crate::cap::CHECKPOINT_RESTORE as u64;

/// `SECCOMP_MODE_*` (`include/uapi/linux/seccomp.h`) — `PR_GET_SECCOMP`
/// returns `current->seccomp.mode` verbatim.
pub const SECCOMP_MODE_DISABLED: i64 = 0;
pub const SECCOMP_MODE_STRICT:   i64 = 1;
pub const SECCOMP_MODE_FILTER:   i64 = 2;
