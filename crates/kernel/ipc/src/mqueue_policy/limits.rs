//! Linux mqueue limits and ABI constants. Sourced from
//! `include/linux/ipc_namespace.h:118-126`, `include/uapi/linux/mqueue.h:24`
//! and `ipc/mqueue.c`; nothing here is derived from a man page.

/// `DFLT_QUEUESMAX` — initial `/proc/sys/fs/mqueue/queues_max`.
pub const DFLT_QUEUESMAX: u32 = 256;
/// `MIN_MSGMAX` — floor an admin may set `msg_max` to.
pub const MIN_MSGMAX: i64 = 1;
/// `DFLT_MSG` — initial `/proc/sys/fs/mqueue/msg_default`.
pub const DFLT_MSG: i64 = 10;
/// `DFLT_MSGMAX` — initial `/proc/sys/fs/mqueue/msg_max`.
pub const DFLT_MSGMAX: i64 = 10;
/// `HARD_MSGMAX` — ceiling `CAP_SYS_RESOURCE` still cannot pass.
pub const HARD_MSGMAX: i64 = 65_536;
/// `MIN_MSGSIZEMAX` — floor an admin may set `msgsize_max` to.
pub const MIN_MSGSIZEMAX: i64 = 128;
/// `DFLT_MSGSIZE` — initial `/proc/sys/fs/mqueue/msgsize_default`.
pub const DFLT_MSGSIZE: i64 = 8_192;
/// `DFLT_MSGSIZEMAX` — initial `/proc/sys/fs/mqueue/msgsize_max`.
pub const DFLT_MSGSIZEMAX: i64 = 8_192;
/// `HARD_MSGSIZEMAX` — ceiling `CAP_SYS_RESOURCE` still cannot pass.
pub const HARD_MSGSIZEMAX: i64 = 16 * 1024 * 1024;

/// `MQ_PRIO_MAX` (`include/uapi/linux/mqueue.h:24`): `mq_timedsend` demands
/// `msg_prio < MQ_PRIO_MAX` (`ipc/mqueue.c:1051`).
pub const MQ_PRIO_MAX: u32 = 32_768;

/// `NAME_MAX` — `simple_lookup` (`fs/libfs.c`) rejects a longer component.
pub const NAME_MAX: usize = 255;
/// `PATH_MAX` — `getname()` rejects a longer string (NUL included).
pub const PATH_MAX: usize = 4_096;

/// `NOTIFY_COOKIE_LEN` (`ipc/mqueue.c`) — the SIGEV_THREAD cookie length read
/// from `sigev_value.sival_ptr` and echoed on the notification socket.
pub const NOTIFY_COOKIE_LEN: usize = 32;
/// `NOTIFY_WOKENUP` — cookie byte stamped when the queue went non-empty.
pub const NOTIFY_WOKENUP: u8 = 1;
/// `NOTIFY_REMOVED` — cookie byte stamped when the registration is torn down.
pub const NOTIFY_REMOVED: u8 = 2;

/// `struct mq_attr`: `mq_flags`, `mq_maxmsg`, `mq_msgsize`, `mq_curmsgs` plus
/// four reserved longs. Identical on x86_64 and aarch64 (LP64 both).
pub const MQ_ATTR_BYTES: usize = 64;
/// Byte offset of `mq_maxmsg` within `struct mq_attr`.
pub const MQ_ATTR_MAXMSG_OFF: u64 = 8;
/// Byte offset of `mq_msgsize` within `struct mq_attr`.
pub const MQ_ATTR_MSGSIZE_OFF: u64 = 16;
/// Byte offset of `mq_curmsgs` within `struct mq_attr`.
pub const MQ_ATTR_CURMSGS_OFF: u64 = 24;

/// `struct sigevent` prefix `mq_notify` reads: `sigval_t sigev_value` (8),
/// `int sigev_signo` (4), `int sigev_notify` (4). Same on both LP64 arches.
pub const SIGEVENT_BYTES: usize = 16;
/// Byte offset of `sigev_signo` within `struct sigevent`.
pub const SIGEVENT_SIGNO_OFF: u64 = 8;
/// Byte offset of `sigev_notify` within `struct sigevent`.
pub const SIGEVENT_NOTIFY_OFF: u64 = 12;

/// Per-message overhead Linux charges against RLIMIT_MSGQUEUE —
/// `sizeof(struct msg_msg)` (`ipc/mqueue.c:364`). Kept at Linux's value so the
/// number of queues a given rlimit affords is the number Linux affords.
pub const MSG_MSG_BYTES: i64 = 48;
/// Per-priority-node overhead — `sizeof(struct posix_msg_tree_node)`
/// (`ipc/mqueue.c:366`).
pub const MSG_TREE_NODE_BYTES: i64 = 48;

/// `mqueue_fill_super` root-directory mode: sticky + `rwxrwxrwx`, so any user
/// may create a queue but only the owner may unlink one (`ipc/mqueue.c`,
/// `S_IFDIR | S_ISVTX | S_IRWXUGO`).
pub const MQ_ROOT_PERM: u16 = 0o1777;
