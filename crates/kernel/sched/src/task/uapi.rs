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
