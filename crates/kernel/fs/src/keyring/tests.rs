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

use super::*;
use super::ops::Ctx;
use super::store::{TaskIds, STORE};

mod keys;
mod links;
mod perm;
mod rings;

/// A caller with fsuid == fsgid == `uid` and no supplementary groups.
fn ctx(tid: u32, uid: u32) -> Ctx {
    Ctx::new(TaskIds { tid, tgid: tid, fsuid: uid, fsgid: uid, groups: Vec::new() }, 0, false)
}

/// The same caller holding `CAP_SYS_ADMIN`.
fn admin_ctx(tid: u32, uid: u32) -> Ctx {
    let mut c = ctx(tid, uid);
    c.sys_admin = true;
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
