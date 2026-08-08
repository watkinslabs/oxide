// NETLINK_AUDIT ABI numbers. Values only — no policy, no state. Every number
// is fixed by the audit netlink contract userspace (`auditd`, `auditctl`,
// `libaudit`) compiles against; the tests in `tests/uapi.rs` are the durable
// provenance for them.

// ---- control message types ------------------------------------------------

pub const AUDIT_GET: u16 = 1000;
pub const AUDIT_SET: u16 = 1001;
/// The three deprecated syscall-rule operations. A kernel that speaks the
/// current rule format answers them with EOPNOTSUPP rather than EINVAL, so
/// `auditctl` can tell "old interface" from "bad request".
pub const AUDIT_LIST: u16 = 1002;
pub const AUDIT_ADD:  u16 = 1003;
pub const AUDIT_DEL:  u16 = 1004;
pub const AUDIT_USER: u16 = 1005;
pub const AUDIT_LOGIN: u16 = 1006;
pub const AUDIT_SIGNAL_INFO: u16 = 1010;
pub const AUDIT_ADD_RULE: u16 = 1011;
pub const AUDIT_DEL_RULE: u16 = 1012;
pub const AUDIT_LIST_RULES: u16 = 1013;
pub const AUDIT_TRIM: u16 = 1014;
pub const AUDIT_MAKE_EQUIV: u16 = 1015;
pub const AUDIT_TTY_GET: u16 = 1016;
pub const AUDIT_TTY_SET: u16 = 1017;
pub const AUDIT_SET_FEATURE: u16 = 1018;
pub const AUDIT_GET_FEATURE: u16 = 1019;

/// The two user-message ranges a `CAP_AUDIT_WRITE` holder may inject.
pub const AUDIT_FIRST_USER_MSG:  u16 = 1100;
pub const AUDIT_USER_AVC:        u16 = 1107;
pub const AUDIT_USER_TTY:        u16 = 1124;
pub const AUDIT_LAST_USER_MSG:   u16 = 1199;
pub const AUDIT_FIRST_USER_MSG2: u16 = 2100;
pub const AUDIT_LAST_USER_MSG2:  u16 = 2999;

// ---- kernel-generated record types ---------------------------------------

pub const AUDIT_CONFIG_CHANGE:   u16 = 1305;
pub const AUDIT_SECCOMP:         u16 = 1326;
pub const AUDIT_FEATURE_CHANGE:  u16 = 1328;
pub const AUDIT_FANOTIFY:        u16 = 1331;
pub const AUDIT_EVENT_LISTENER:  u16 = 1335;
pub const AUDIT_LANDLOCK_ACCESS: u16 = 1423;
pub const AUDIT_LANDLOCK_DOMAIN: u16 = 1424;

// ---- `struct audit_status` -----------------------------------------------

/// `struct audit_status` — eleven `u32` in wire order: mask, enabled, failure,
/// pid, rate_limit, backlog_limit, lost, backlog, the version/feature_bitmap
/// union, backlog_wait_time, backlog_wait_time_actual.
pub const AUDIT_STATUS_LEN: usize = 44;
/// `struct audit_features` — vers, mask, features, lock.
pub const AUDIT_FEATURES_LEN: usize = 16;

pub const AUDIT_STATUS_ENABLED:            u32 = 0x0001;
pub const AUDIT_STATUS_FAILURE:            u32 = 0x0002;
pub const AUDIT_STATUS_PID:                u32 = 0x0004;
pub const AUDIT_STATUS_RATE_LIMIT:         u32 = 0x0008;
pub const AUDIT_STATUS_BACKLOG_LIMIT:      u32 = 0x0010;
pub const AUDIT_STATUS_BACKLOG_WAIT_TIME:  u32 = 0x0020;
pub const AUDIT_STATUS_LOST:               u32 = 0x0040;
pub const AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL: u32 = 0x0080;

pub const AUDIT_STATUS_ALL: u32 = AUDIT_STATUS_ENABLED | AUDIT_STATUS_FAILURE
    | AUDIT_STATUS_PID | AUDIT_STATUS_RATE_LIMIT | AUDIT_STATUS_BACKLOG_LIMIT
    | AUDIT_STATUS_BACKLOG_WAIT_TIME | AUDIT_STATUS_LOST
    | AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL;

// ---- feature bitmap -------------------------------------------------------

pub const AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT:     u32 = 0x0000_0001;
pub const AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME: u32 = 0x0000_0002;
pub const AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH:   u32 = 0x0000_0004;
pub const AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND:    u32 = 0x0000_0008;
pub const AUDIT_FEATURE_BITMAP_SESSIONID_FILTER:  u32 = 0x0000_0010;
pub const AUDIT_FEATURE_BITMAP_LOST_RESET:        u32 = 0x0000_0020;
pub const AUDIT_FEATURE_BITMAP_FILTER_FS:         u32 = 0x0000_0040;

pub const AUDIT_FEATURE_BITMAP_ALL: u32 = AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT
    | AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME | AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH
    | AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND | AUDIT_FEATURE_BITMAP_SESSIONID_FILTER
    | AUDIT_FEATURE_BITMAP_LOST_RESET | AUDIT_FEATURE_BITMAP_FILTER_FS;

// ---- toggleable features (`struct audit_features`) ------------------------

pub const AUDIT_FEATURE_VERSION: u32 = 1;
pub const AUDIT_FEATURE_ONLY_UNSET_LOGINUID: u32 = 0;
pub const AUDIT_FEATURE_LOGINUID_IMMUTABLE:  u32 = 1;
pub const AUDIT_LAST_FEATURE: u32 = AUDIT_FEATURE_LOGINUID_IMMUTABLE;

/// `AUDIT_FEATURE_TO_MASK`. # C: O(1)
pub const fn feature_to_mask(feature: u32) -> u32 { 1 << (feature & 31) }

// ---- failure-to-log actions ----------------------------------------------

pub const AUDIT_FAIL_SILENT: u32 = 0;
pub const AUDIT_FAIL_PRINTK: u32 = 1;
pub const AUDIT_FAIL_PANIC:  u32 = 2;

// ---- enable states --------------------------------------------------------

pub const AUDIT_OFF:    u32 = 0;
pub const AUDIT_ON:     u32 = 1;
/// Configuration is frozen: every later change is refused with EPERM.
pub const AUDIT_LOCKED: u32 = 2;

// ---- defaults -------------------------------------------------------------

/// Outstanding records allowed before new ones are dropped and counted lost.
/// Zero means unlimited.
pub const AUDIT_BACKLOG_LIMIT_DEFAULT: u32 = 64;
/// `AUDIT_BACKLOG_WAIT_TIME` — 60 seconds expressed in ticks, the unit the
/// `backlog_wait_time` field carries.
pub const AUDIT_BACKLOG_WAIT_TIME: u32 = 60 * HZ;
/// Largest accepted `backlog_wait_time`.
pub const AUDIT_BACKLOG_WAIT_TIME_MAX: u32 = 10 * AUDIT_BACKLOG_WAIT_TIME;
/// Scheduler tick rate; `backlog_wait_time` is a tick count on the wire.
pub const HZ: u32 = 1000;

/// Longest user-supplied message body copied into a record.
pub const AUDIT_MESSAGE_TEXT_MAX: usize = 8560;
