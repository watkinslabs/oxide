// Landlock user-space ABI constants (`docs/27`). Numbers only — no policy.
// Every value is fixed by the Linux landlock(7) contract and is verified by
// the tests in `tests/uapi.rs`, which are the durable provenance for them.

/// `landlock_create_ruleset` / rule / domain access mask word.
pub type AccessMask = u64;

// ---- LANDLOCK_ACCESS_FS_* -------------------------------------------------

pub const ACCESS_FS_EXECUTE:      AccessMask = 1 << 0;
pub const ACCESS_FS_WRITE_FILE:   AccessMask = 1 << 1;
pub const ACCESS_FS_READ_FILE:    AccessMask = 1 << 2;
pub const ACCESS_FS_READ_DIR:     AccessMask = 1 << 3;
pub const ACCESS_FS_REMOVE_DIR:   AccessMask = 1 << 4;
pub const ACCESS_FS_REMOVE_FILE:  AccessMask = 1 << 5;
pub const ACCESS_FS_MAKE_CHAR:    AccessMask = 1 << 6;
pub const ACCESS_FS_MAKE_DIR:     AccessMask = 1 << 7;
pub const ACCESS_FS_MAKE_REG:     AccessMask = 1 << 8;
pub const ACCESS_FS_MAKE_SOCK:    AccessMask = 1 << 9;
pub const ACCESS_FS_MAKE_FIFO:    AccessMask = 1 << 10;
pub const ACCESS_FS_MAKE_BLOCK:   AccessMask = 1 << 11;
pub const ACCESS_FS_MAKE_SYM:     AccessMask = 1 << 12;
pub const ACCESS_FS_REFER:        AccessMask = 1 << 13;
pub const ACCESS_FS_TRUNCATE:     AccessMask = 1 << 14;
pub const ACCESS_FS_IOCTL_DEV:    AccessMask = 1 << 15;

/// Highest filesystem right this kernel enforces; the mask is every bit up to
/// it. A right defined at a later ABI level is deliberately absent: accepting
/// a right that nothing enforces would hand a caller a sandbox that is not one.
pub const LAST_ACCESS_FS: AccessMask = ACCESS_FS_IOCTL_DEV;
pub const MASK_ACCESS_FS: AccessMask = (LAST_ACCESS_FS << 1) - 1;

/// Rights meaningful on a non-directory rule target. A rule whose parent fd is
/// not a directory may only carry these.
pub const ACCESS_FILE: AccessMask = ACCESS_FS_EXECUTE
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_READ_FILE
    | ACCESS_FS_TRUNCATE
    | ACCESS_FS_IOCTL_DEV;

/// Rights a ruleset handles even when the caller did not list them. Reparenting
/// is denied by default so that an ABI-1 policy cannot be escaped by moving a
/// hierarchy; the bit must still be listed in `handled_access_fs` before a rule
/// is allowed to grant it.
pub const ACCESS_FS_INITIALLY_DENIED: AccessMask = ACCESS_FS_REFER;

// ---- LANDLOCK_ACCESS_NET_* ------------------------------------------------

pub const ACCESS_NET_BIND_TCP:    AccessMask = 1 << 0;
pub const ACCESS_NET_CONNECT_TCP: AccessMask = 1 << 1;

/// Datagram rights belong to a later ABI level and are not accepted here.
pub const LAST_ACCESS_NET: AccessMask = ACCESS_NET_CONNECT_TCP;
pub const MASK_ACCESS_NET: AccessMask = (LAST_ACCESS_NET << 1) - 1;

// ---- LANDLOCK_SCOPE_* -----------------------------------------------------

pub const SCOPE_ABSTRACT_UNIX_SOCKET: AccessMask = 1 << 0;
pub const SCOPE_SIGNAL:               AccessMask = 1 << 1;

/// Highest defined scope; the mask is every bit up to it. Both scopes are
/// enforced: signalling through the signal-permission check, abstract sockets
/// through the AF_UNIX connect and datagram-send paths.
pub const LAST_SCOPE: AccessMask = SCOPE_SIGNAL;
pub const MASK_SCOPE: AccessMask = (LAST_SCOPE << 1) - 1;

// ---- syscall flags --------------------------------------------------------

pub const CREATE_RULESET_VERSION: u32 = 1 << 0;
pub const CREATE_RULESET_ERRATA:  u32 = 1 << 1;

/// `landlock_add_rule` defines no flag at this ABI level.
pub const MASK_ADD_RULE: u32 = 0;

// `landlock_restrict_self` flags.
//
// The three logging flags select which denials reach the audit log. This
// kernel has no audit subsystem, so they are validated, carried, and record
// nothing — the same shape a kernel built without audit support has, and they
// never change an access decision.
pub const RESTRICT_SELF_LOG_SAME_EXEC_OFF:  u32 = 1 << 0;
pub const RESTRICT_SELF_LOG_NEW_EXEC_ON:    u32 = 1 << 1;
pub const RESTRICT_SELF_LOG_SUBDOMAINS_OFF: u32 = 1 << 2;
/// Apply the result to every thread of the calling process at once.
pub const RESTRICT_SELF_TSYNC:              u32 = 1 << 3;

pub const LAST_RESTRICT_SELF: u32 = RESTRICT_SELF_TSYNC;
pub const MASK_RESTRICT_SELF: u32 = (LAST_RESTRICT_SELF << 1) - 1;

// ---- rule types -----------------------------------------------------------

pub const RULE_PATH_BENEATH: u64 = 1;
pub const RULE_NET_PORT:     u64 = 2;

// ---- ABI negotiation ------------------------------------------------------

/// Value reported for `LANDLOCK_CREATE_RULESET_VERSION`. Every right, scope and
/// flag defined at this level is enforced; feature-detecting programs use this
/// number to decide which rights to request, so it may only rise once the
/// corresponding enforcement exists. Raising it past what is enforced is the
/// one failure mode that silently turns a working sandbox into no sandbox.
///
/// Every right, scope and flag of every level up to this one is enforced.
pub const ABI_VERSION: i64 = 8;

/// Value reported for `LANDLOCK_CREATE_RULESET_ERRATA`: a bitmask of fixed
/// issues for the current ABI version. No erratum applies to this implementation.
pub const ERRATA: i64 = 0;

// ---- limits and struct sizes ---------------------------------------------

/// Maximum number of stacked policy layers per thread.
pub const MAX_NUM_LAYERS: usize = 16;

/// `sizeof(struct landlock_ruleset_attr)` at the current ABI level: the
/// filesystem, network and scope masks.
pub const RULESET_ATTR_SIZE: usize = 24;
/// Smallest accepted `size` for `landlock_create_ruleset`: through
/// `handled_access_fs`, the only member ABI 1 defined.
pub const RULESET_ATTR_MIN_SIZE: usize = 8;
/// `sizeof(struct landlock_path_beneath_attr)` — packed, u64 + s32.
pub const PATH_BENEATH_ATTR_SIZE: usize = 12;
/// `sizeof(struct landlock_net_port_attr)`.
pub const NET_PORT_ATTR_SIZE: usize = 16;
/// Upper bound on a user-supplied attr size.
pub const ATTR_MAX_SIZE: usize = 4096;

/// Highest port number a net rule may name.
pub const PORT_MAX: u64 = 65535;
