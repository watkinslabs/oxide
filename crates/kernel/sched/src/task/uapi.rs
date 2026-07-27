// Task-scoped Linux UAPI constants. Ungated (unlike `prctl.rs`, which is
// kernel-only) because `Task` construction needs these defaults in hosted
// tests too.

/// `TASK_COMM_LEN` (`include/linux/sched.h`): fixed size of
/// `task_struct::comm`, NUL-padded. Governs `prctl(PR_SET_NAME/
/// PR_GET_NAME)`, `pthread_setname_np(3)`, `/proc/<pid>/comm`.
pub const TASK_COMM_LEN: usize = 16;

/// `SUID_DUMP_*` (`include/linux/sched/coredump.h`) — `prctl(PR_SET_DUMPABLE/
/// PR_GET_DUMPABLE)` values.
pub const SUID_DUMP_DISABLE: u8 = 0;
pub const SUID_DUMP_USER:    u8 = 1;
pub const SUID_DUMP_ROOT:    u8 = 2;

/// `prctl(PR_SET_THP_DISABLE)` state, encoding Linux's mutually exclusive
/// `MMF_DISABLE_THP_COMPLETELY` / `MMF_DISABLE_THP_EXCEPT_ADVISED` mm flags.
pub const THP_DISABLE_OFF:            u8 = 0;
pub const THP_DISABLE_COMPLETELY:     u8 = 1;
pub const THP_DISABLE_EXCEPT_ADVISED: u8 = 2;

/// `PF_MCE_PROCESS` / `PF_MCE_EARLY` (`include/linux/sched.h`) as set by
/// `prctl(PR_MCE_KILL)`.
pub const MCE_KILL_PROCESS: u8 = 1 << 0;
pub const MCE_KILL_EARLY:   u8 = 1 << 1;
