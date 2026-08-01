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
//          SET_REQKEY_KEYRING, SESSION_TO_PARENT.
// - keys:  single-key ops — add_key, UPDATE, REVOKE, INVALIDATE, CHOWN,
//          SETPERM, SET_TIMEOUT, READ, DESCRIBE, GET_SECURITY.
// - links: keyring membership — LINK, UNLINK, MOVE, CLEAR, RESTRICT_KEYRING.
// - search: `keyring_search_rcu` — the walk KEYCTL_SEARCH and request_key
//          share, including why a search failed, which decides whether
//          request_key upcalls.
// - instantiate: INSTANTIATE, INSTANTIATE_IOV, NEGATE, REJECT,
//          ASSUME_AUTHORITY — the family gated on the authorisation token.
// - pkey:  the PKEY_* family — the information string, the key it reads, the
//          per-command length rules, and the errno each public-key failure
//          surfaces as. Owns the fact that the family is implemented, which is
//          where the reported capability bit comes from.
// - watch: WATCH_KEY — the watchpoint-id rule and the add/remove bookkeeping
//          on a key's watch list. Owns the fact that key notifications are
//          implemented, which is where the reported capability bit comes from.
// - dh:    DH_COMPUTE — the three key payloads it reads, the parameter
//          admission rules, the modular exponentiation and the counter-mode
//          derivation. Owns the fact that the command is implemented at all,
//          which is where the reported capability bit comes from.

use super::store::TaskIds;

pub mod dh;
mod instantiate;
mod keys;
mod links;
pub mod pkey;
mod rings;
pub mod watch;
pub(super) mod search;

pub use keys::{add_key_core, chown_core, describe_core, get_security_core, invalidate_core,
    read_core, revoke_core, set_timeout_core, setperm_core, update_core};
pub use instantiate::{assume_authority_core, instantiate_core, reject_core, vet_iov_count};
pub use links::{clear_core, link_core, move_core, request_key_core, restrict_core,
    search_core, unlink_core};
// Keyring-membership readback has no kernel-side caller — `keyctl` walks the
// store directly; the hosted tests are what assert link/unlink membership.
#[cfg(test)]
pub use links::members_of;
pub use rings::{get_keyring_id, get_persistent, join_session, session_to_parent,
    set_reqkey_keyring, vet_session_name, ParentInfo};

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
    /// `ns_capable(ns, CAP_SETUID)` — what `KEYCTL_GET_PERSISTENT` checks
    /// before handing over ANOTHER uid's persistent keyring. It is deliberately
    /// not `CAP_SYS_ADMIN`: reaching into another user's cached credentials is
    /// an identity operation, and a process trusted to change uid is exactly
    /// the one Linux lets do it.
    pub set_uid: bool,
}

impl Ctx {
    /// A caller holding neither capability. # C: O(1)
    pub fn new(t: TaskIds, now_ns: u64, sys_admin: bool) -> Self {
        Self { t, now_ns, sys_admin, set_uid: false }
    }

    /// Both capabilities resolved explicitly. They are separate gates on
    /// separate commands, so deriving one from the other would silently hand
    /// `KEYCTL_GET_PERSISTENT` to every `CAP_SYS_ADMIN` holder — or withhold it
    /// from a `CAP_SETUID` one that Linux allows. # C: O(1)
    pub fn with_caps(t: TaskIds, now_ns: u64, sys_admin: bool, set_uid: bool) -> Self {
        Self { t, now_ns, sys_admin, set_uid }
    }
}

/// Negated errno, ready to return from a syscall entry point. # C: O(1)
pub(crate) fn e(err: syscall::errno::Errno) -> i64 { -(err.as_i32() as i64) }
