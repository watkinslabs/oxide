// `prctl(2)` option numbers and sub-values — `include/uapi/linux/prctl.h`.
// UAPI only: no dispatch, no policy, no state (`docs/07§5`).

pub const PR_SET_PDEATHSIG:       u64 = 1;
pub const PR_GET_PDEATHSIG:       u64 = 2;
pub const PR_GET_DUMPABLE:        u64 = 3;
pub const PR_SET_DUMPABLE:        u64 = 4;
pub const PR_GET_UNALIGN:         u64 = 5;
pub const PR_SET_UNALIGN:         u64 = 6;
pub const PR_GET_KEEPCAPS:        u64 = 7;
pub const PR_GET_FPEMU:           u64 = 9;
pub const PR_SET_FPEMU:           u64 = 10;
pub const PR_GET_FPEXC:           u64 = 11;
pub const PR_SET_FPEXC:           u64 = 12;
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
/// `PR_SET_PTRACER` — Yama's `security_task_prctl` option, whose number is
/// the ASCII of "Yama" rather than a slot in the numeric sequence.
pub const PR_SET_PTRACER:         u64 = 0x5961_6d61;
/// `PR_SET_PTRACER_ANY` — `(unsigned long)-1`, "any process may attach".
pub const PR_SET_PTRACER_ANY:     u64 = u64::MAX;
pub const PR_SET_NO_NEW_PRIVS:    u64 = 38;
pub const PR_GET_NO_NEW_PRIVS:    u64 = 39;
pub const PR_GET_TID_ADDRESS:     u64 = 40;
pub const PR_SET_THP_DISABLE:     u64 = 41;
pub const PR_GET_THP_DISABLE:     u64 = 42;
pub const PR_MPX_ENABLE_MANAGEMENT:  u64 = 43;
pub const PR_MPX_DISABLE_MANAGEMENT: u64 = 44;
pub const PR_GET_ENDIAN:          u64 = 19;
pub const PR_SET_ENDIAN:          u64 = 20;
pub const PR_SET_FP_MODE:         u64 = 45;
pub const PR_GET_FP_MODE:         u64 = 46;
pub const PR_CAP_AMBIENT:         u64 = 47;
pub const PR_SVE_SET_VL:          u64 = 50;
pub const PR_SVE_GET_VL:          u64 = 51;
pub const PR_SME_SET_VL:          u64 = 63;
pub const PR_SME_GET_VL:          u64 = 64;
pub const PR_GET_SPECULATION_CTRL: u64 = 52;
pub const PR_SET_SPECULATION_CTRL: u64 = 53;
pub const PR_PAC_RESET_KEYS:      u64 = 54;
pub const PR_SET_TAGGED_ADDR_CTRL: u64 = 55;
pub const PR_GET_TAGGED_ADDR_CTRL: u64 = 56;
pub const PR_SET_IO_FLUSHER:      u64 = 57;
pub const PR_GET_IO_FLUSHER:      u64 = 58;
pub const PR_SET_SYSCALL_USER_DISPATCH: u64 = 59;
pub const PR_PAC_SET_ENABLED_KEYS: u64 = 60;
pub const PR_PAC_GET_ENABLED_KEYS: u64 = 61;
pub const PR_SET_MDWE:             u64 = 65;
pub const PR_GET_MDWE:             u64 = 66;
pub const PR_SET_VMA:             u64 = 0x5356_4d41;
pub const PR_GET_AUXV:            u64 = 0x4155_5856;
pub const PR_TIMER_CREATE_RESTORE_IDS: u64 = 77;
pub const PR_FUTEX_HASH:          u64 = 78;
pub const PR_RSEQ_SLICE_EXTENSION: u64 = 79;

/// `PR_SET_SYSCALL_USER_DISPATCH` modes (arg2).
pub const PR_SYS_DISPATCH_OFF:           u64 = 0;
pub const PR_SYS_DISPATCH_EXCLUSIVE_ON:  u64 = 1;
pub const PR_SYS_DISPATCH_INCLUSIVE_ON:  u64 = 2;

/// Selector byte values userspace stores at the registered selector address.
pub const SYSCALL_DISPATCH_FILTER_ALLOW: u8 = 0;
pub const SYSCALL_DISPATCH_FILTER_BLOCK: u8 = 1;

/// `PR_TIMER_CREATE_RESTORE_IDS` sub-commands (arg2).
pub const PR_TIMER_CREATE_RESTORE_IDS_OFF: u64 = 0;
pub const PR_TIMER_CREATE_RESTORE_IDS_ON:  u64 = 1;
pub const PR_TIMER_CREATE_RESTORE_IDS_GET: u64 = 2;

/// `PR_FUTEX_HASH` sub-commands (arg2).
pub const PR_FUTEX_HASH_SET_SLOTS: u64 = 1;
pub const PR_FUTEX_HASH_GET_SLOTS: u64 = 2;

/// `PR_RSEQ_SLICE_EXTENSION` sub-commands (arg2) and its one control bit (arg3).
pub const PR_RSEQ_SLICE_EXTENSION_GET: u64 = 1;
pub const PR_RSEQ_SLICE_EXTENSION_SET: u64 = 2;
pub const PR_RSEQ_SLICE_EXT_ENABLE:    u64 = 0x01;

/// `PR_SET_TAGGED_ADDR_CTRL` bits (arg2). `PR_TAGGED_ADDR_ENABLE` is the
/// tagged-address ABI itself; the `PR_MTE_*` bits ride the same word and are
/// only accepted on a CPU with memory tagging.
pub const PR_TAGGED_ADDR_ENABLE: u64 = 1 << 0;
pub const PR_MTE_TCF_NONE:  u64 = 0;
pub const PR_MTE_TCF_SYNC:  u64 = 1 << 1;
pub const PR_MTE_TCF_ASYNC: u64 = 1 << 2;
pub const PR_MTE_TCF_MASK:  u64 = PR_MTE_TCF_SYNC | PR_MTE_TCF_ASYNC;
/// `PR_MTE_TAG_MASK` — the 16-bit include-mask of tags the kernel may pick
/// for `PROT_MTE` pages, at `PR_MTE_TAG_SHIFT`.
pub const PR_MTE_TAG_SHIFT: u32 = 3;
pub const PR_MTE_TAG_MASK: u64 = 0xffff << PR_MTE_TAG_SHIFT;

/// `PR_SVE_SET_VL` / `PR_SME_SET_VL` argument layout: a vector length in the
/// low 16 bits plus flag bits above it.
pub const PR_SVE_VL_LEN_MASK: u64 = 0xffff;
pub const PR_SVE_VL_INHERIT:  u64 = 1 << 17;
pub const PR_SME_VL_LEN_MASK: u64 = 0xffff;
pub const PR_SME_VL_INHERIT:  u64 = 1 << 17;

/// `PR_PAC_RESET_KEYS` / `PR_PAC_{SET,GET}_ENABLED_KEYS` key selectors (arg2).
/// The four `APIA`..`APDB` keys authenticate ADDRESSES; `APGA` is the generic
/// key and is gated on a separate CPU feature.
pub const PR_PAC_APIAKEY: u64 = 1 << 0;
pub const PR_PAC_APIBKEY: u64 = 1 << 1;
pub const PR_PAC_APDAKEY: u64 = 1 << 2;
pub const PR_PAC_APDBKEY: u64 = 1 << 3;
pub const PR_PAC_APGAKEY: u64 = 1 << 4;
/// Address keys only — `PR_PAC_SET_ENABLED_KEYS` cannot enable/disable the
/// generic key, which has no `SCTLR_EL1` enable bit.
pub const PR_PAC_ENABLED_KEYS_MASK: u64 =
    PR_PAC_APIAKEY | PR_PAC_APIBKEY | PR_PAC_APDAKEY | PR_PAC_APDBKEY;

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

/// `PR_SET_MDWE` mask bits.
pub const PR_MDWE_REFUSE_EXEC_GAIN: u64 = 1 << 0;
pub const PR_MDWE_NO_INHERIT:       u64 = 1 << 1;

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
