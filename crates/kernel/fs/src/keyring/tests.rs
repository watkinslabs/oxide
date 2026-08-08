// Hosted tests for the real keyring hierarchy. These drive the `ops::*_core`
// functions directly — no user memory, no `current()`. The STORE is a
// process-global static shared across tests, so each test uses a UNIQUE
// tid/uid so the per-task/per-uid keyring maps never collide between tests.
//
// Module manifest:
// - rings: keyring lifecycle + SET_REQKEY_KEYRING + fork inheritance.
// - keys:  add_key semantics, UPDATE/REVOKE/INVALIDATE/CHOWN/SETPERM/
//          SET_TIMEOUT/READ/DESCRIBE.
// - links: LINK/UNLINK/MOVE/CLEAR/RESTRICT and the SEARCH / request_key scope.
// - perm:  the `key_task_permission` chokepoint itself.
// - pkey:  the PKEY_* family — asymmetric key admission, the information
//          string, the query, and known-answer sign/verify/encrypt.
// - payload: per-type payload contracts and the type table's read/update methods.
// - quota: the per-uid `key_user` key/byte quota, EDQUOT and the gc refund.
// - watch: WATCH_KEY and the records a watcher receives from the real ops.
// - dh:    DH_COMPUTE — input-key admission, parameter vetting, and the
//          known-answer exponentiation and key derivation.

use super::*;
use super::ops::Ctx;
use super::store::{TaskIds, STORE};

mod dh;
mod keys;
mod namespace;
mod links;
mod payload;
mod perm;
mod pkey;
mod quota;
mod rings;
mod watch;

/// A caller with fsuid == fsgid == `uid` and no supplementary groups.
fn ctx(tid: u32, uid: u32) -> Ctx {
    Ctx::with_caps(TaskIds { tid, tgid: tid, fsuid: uid, fsgid: uid, groups: Vec::new(), ..TaskIds::default() }, 0, false, false)
}

/// The same caller in a non-initial user namespace whose uid map is `map`.
/// A namespace with an EMPTY map can name no uid at all, which is the state a
/// freshly created one is in until `uid_map` is written.
fn ns_ctx(tid: u32, uid: u32, user_ns: u64, map: &[::user_namespace::IdMapExtent]) -> Ctx {
    let mut c = ctx(tid, uid);
    c.t.user_ns = user_ns;
    c.t.uid_map = map.to_vec();
    c
}

/// The same caller in network namespace `net_ns`, which only a network-scoped
/// key type reads.
fn net_ctx(tid: u32, uid: u32, net_ns: u64) -> Ctx {
    let mut c = ctx(tid, uid);
    c.t.net_ns = net_ns;
    c
}

/// An identity map covering `count` uids from zero — what a user namespace that
/// has written a full-range `uid_map` looks like.
fn identity_map(count: u32) -> [::user_namespace::IdMapExtent; 1] {
    [::user_namespace::IdMapExtent { ns_id: 0, host_id: 0, count }]
}

/// The same caller holding `CAP_SYS_ADMIN`.
/// The same caller holding both `CAP_SYS_ADMIN` and `CAP_SETUID`.
fn admin_ctx(tid: u32, uid: u32) -> Ctx {
    let mut c = ctx(tid, uid);
    c.sys_admin = true;
    c.set_uid = true;
    c
}

fn eacces() -> i64 { err(Errno::Eacces) }
fn enokey() -> i64 { err(Errno::Enokey) }
fn einval() -> i64 { err(Errno::Einval) }
fn eperm()  -> i64 { err(Errno::Eperm) }

/// Widen a key's perm bytes so a test can hand access to an unrelated caller,
/// without going through `setperm_core`'s own gates.
fn force_perm(serial: i32, perm: u32) {
    STORE.lock().keys.get_mut(&serial).expect("key exists").perm = perm;
}
