//! Linux mqueue limits and ABI constants, matched exactly so a given
//! RLIMIT_MSGQUEUE or sysctl setting admits the same queue count and sizes
//! as the reference kernel; nothing here is derived from a man page.

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

/// `MQ_PRIO_MAX`: `mq_timedsend` demands
/// `msg_prio < MQ_PRIO_MAX`.
pub const MQ_PRIO_MAX: u32 = 32_768;

/// `NAME_MAX` — the queue-name lookup rejects a longer component.
pub const NAME_MAX: usize = 255;
/// `PATH_MAX` — `getname()` rejects a longer string (NUL included).
pub const PATH_MAX: usize = 4_096;

/// `NOTIFY_COOKIE_LEN` — the SIGEV_THREAD cookie length read
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

/// Per-message overhead charged against RLIMIT_MSGQUEUE —
/// the size of one message-tree entry. Kept at the reference kernel's value so the
/// number of queues a given rlimit affords is the number that kernel affords.
pub const MSG_MSG_BYTES: i64 = 48;
/// Per-priority-node overhead — the size of one priority tree node.
pub const MSG_TREE_NODE_BYTES: i64 = 48;

/// mqueuefs root-directory mode: sticky + `rwxrwxrwx`, so any user
/// may create a queue but only the owner may unlink one
/// (`S_IFDIR | S_ISVTX | S_IRWXUGO`).
pub const MQ_ROOT_PERM: u16 = 0o1777;
