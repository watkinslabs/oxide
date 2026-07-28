// Per-op cores for `add_key`/`request_key`/`keyctl`. Each takes an explicit
// [`Ctx`] (caller ids + monotonic clock + whether the caller holds
// `CAP_SYS_ADMIN`) instead of reading `sched::current()` — hosted tests drive
// these directly to prove enforcement for an arbitrary caller identity, and
// `keyctl.rs` / `keyring.rs` are thin wrappers that parse args, resolve the
// live caller, marshal user memory, and call these. This is the ONLY place
// each op's logic runs — no duplicate copy in the syscall entry points.
//
// Module manifest:
// - rings: keyring lifecycle — JOIN_SESSION, GET_KEYRING_ID, GET_PERSISTENT,
//          SET_REQKEY_KEYRING, SESSION_TO_PARENT, fork inheritance.
// - keys:  single-key ops — add_key, UPDATE, REVOKE, INVALIDATE, CHOWN,
//          SETPERM, SET_TIMEOUT, READ, DESCRIBE, GET_SECURITY.
// - links: keyring membership and search — LINK, UNLINK, MOVE, CLEAR,
//          RESTRICT_KEYRING, SEARCH, request_key.

use super::store::TaskIds;

mod keys;
mod links;
mod rings;

pub use keys::{add_key_core, chown_core, describe_core, get_security_core, invalidate_core,
    read_core, revoke_core, set_timeout_core, setperm_core, update_core};
pub use links::{clear_core, link_core, members_of, move_core, request_key_core, restrict_core,
    search_core, unlink_core};
pub use rings::{get_keyring_id, get_persistent, inherit_session, join_session,
    session_to_parent, set_reqkey_keyring, ParentInfo};

/// Everything an op needs about its caller. `now_ns` is read once by the
/// syscall entry so the cores stay clock-free and hosted-testable;
/// `sys_admin` is resolved once for the same reason.
pub struct Ctx {
    pub t: TaskIds,
    /// Monotonic nanoseconds, for `key_validate`'s expiry test.
    pub now_ns: u64,
    /// `capable(CAP_SYS_ADMIN)` — consulted ONLY by `KEYCTL_SETPERM` and
    /// `KEYCTL_CHOWN`, as the second gate Linux applies after the
    /// `KEY_NEED_SETATTR` permission check has already passed.
    pub sys_admin: bool,
}

impl Ctx {
    /// # C: O(1)
    pub fn new(t: TaskIds, now_ns: u64, sys_admin: bool) -> Self { Self { t, now_ns, sys_admin } }
}

/// Negated errno, ready to return from a syscall entry point. # C: O(1)
pub(crate) fn e(err: syscall::errno::Errno) -> i64 { -(err.as_i32() as i64) }
