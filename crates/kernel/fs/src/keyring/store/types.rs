// `struct key` and the identities/records it is made of: the caller ids every
// permission decision reads, the quota-charge mode, the per-uid charge, the key
// itself, and the `.request_key_auth` payload. State only — no policy.

use alloc::string::String;
use alloc::vec::Vec;

use super::super::types::KeyType;
use super::super::uapi::*;

/// Caller identity every op resolves special keyrings against and that
/// `perm::key_task_permission` checks ownership against. Linux keys are
/// owned by and checked against the FILESYSTEM ids (`cred->fsuid` /
/// `cred->fsgid` in `key_alloc` and `key_task_permission`), not the effective
/// ids — a process under `setfsuid()` sees a different key world.
#[derive(Clone, Debug, Default)]
pub struct TaskIds {
    pub tid: u32,
    pub tgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    /// `cred->group_info`, walked by `groups_search` when the key's gid is
    /// not the caller's fsgid.
    pub groups: Vec<u32>,
}

impl TaskIds {
    /// Does the caller subscribe to `gid` — `gid_eq(gid, cred->fsgid) ||
    /// groups_search(cred->group_info, gid)` (Linux `in_group_p`). # C: O(groups)
    pub fn in_group(&self, gid: u32) -> bool {
        gid != GID_INVALID && (gid == self.fsgid || self.groups.contains(&gid))
    }
}

/// How a mint interacts with the owner's `key_user` quota.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Quota {
    /// `KEY_ALLOC_IN_QUOTA`: charge, and refuse with EDQUOT when the charge
    /// would exceed the owner's key-count or byte limit.
    InQuota,
    /// `KEY_ALLOC_QUOTA_OVERRUN`: charge, but never refuse. The implicit
    /// thread / process / anonymous-session keyrings use this — a task that has
    /// exhausted its quota must still be able to have keyrings installed for
    /// it, or it could not be given any credentials at all.
    Overrun,
}

/// Per-uid `struct key_user` quota accounting.
#[derive(Clone, Copy, Default, Debug)]
pub struct KeyUser {
    /// `qnkeys` — keys currently charged to this uid.
    pub nkeys: u64,
    /// `qnbytes` — bytes currently charged to this uid.
    pub nbytes: u64,
}

/// One `struct key`. A keyring is a key of type `keyring` whose `members`
/// holds the linked child serials.
pub struct Key {
    pub serial: i32,
    pub key_type: &'static KeyType,
    pub description: String,
    pub payload: Vec<u8>,
    pub perm: u32,
    pub uid: u32,
    pub gid: u32,
    /// `key->quotalen` — the byte charge this key currently holds against
    /// `key->user`. `key_payload_reserve` moves it by the payload delta on
    /// every update, and the whole charge is refunded when the key dies.
    pub quotalen: u64,
    /// `KEY_FLAG_IN_QUOTA` — false only for a key allocated outside the quota
    /// system, whose death refunds nothing.
    pub in_quota: bool,
    /// `key->expiry` in monotonic ns; 0 = never (Linux `TIME64_MAX`/0 sentinel).
    pub expiry_ns: u64,
    /// `KEY_FLAG_REVOKED` — `key_validate` turns this into EKEYREVOKED.
    pub revoked: bool,
    /// `KEY_FLAG_INVALIDATED` — `key_validate` turns this into ENOKEY, and
    /// the gc unlinks it from every keyring.
    pub invalidated: bool,
    /// Keyring only: linked member serials.
    pub members: Vec<i32>,
    /// Keyring only: `key->restrict_link == restrict_link_reject`, installed
    /// by `KEYCTL_RESTRICT_KEYRING` with a NULL type. Every subsequent link
    /// into this ring is EPERM.
    pub restrict_reject: bool,
    /// `key->state`: [`KEY_IS_UNINSTANTIATED`], [`KEY_IS_POSITIVE`], or a
    /// negative `-errno` for a key that was negated or rejected. Every full
    /// lookup reads this BEFORE `key_validate`, so a negative key hands its
    /// stored errno back rather than looking merely expired.
    pub state: i32,
    /// `KEY_FLAG_USER_CONSTRUCT` — an upcall is in flight for this key.
    pub under_construction: bool,
    /// The `.request_key_auth` payload, present only on a key of that type.
    /// Linux keeps it in `key->payload.data[0]` as a `struct request_key_auth`;
    /// it is the type's payload, not a parallel registry.
    pub auth: Option<AuthData>,
}

impl Key {
    /// # C: O(1)
    pub fn is_keyring(&self) -> bool { self.key_type.is_keyring }
    /// `key_read_state`. # C: O(1)
    pub fn read_state(&self) -> i32 { self.state }
    /// `key_is_negative`. # C: O(1)
    pub fn is_negative(&self) -> bool { self.state < 0 }
}

/// `struct request_key_auth` — the authorisation token's payload. It names the
/// key under construction, where the constructed key should be cached, and the
/// identity of the task that asked, so a helper acting under the token
/// instantiates into the REQUESTER's world rather than its own.
#[derive(Clone, Debug)]
pub struct AuthData {
    /// `rka->target_key`.
    pub target: i32,
    /// `rka->dest_keyring` — 0 when the request named none.
    pub dest_keyring: i32,
    /// `rka->cred` reduced to the ids every permission decision reads.
    pub requester: TaskIds,
    /// `rka->pid`.
    pub pid: u32,
    /// `rka->op` (`char op[8]`). The callout info is not held here: it is the
    /// token's readable PAYLOAD, which is where the type's read method looks
    /// when the helper asks what it was called for.
    pub op: String,
}
