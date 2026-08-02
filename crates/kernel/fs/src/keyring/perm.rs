// Permission + validity chokepoint for `add_key`/`request_key`/`keyctl`.
// Mirrors Linux `key_task_permission` and `key_validate`
// (`security/keys/permission.c`): a key's `perm: u32` packs four 6-bit
// need-masks — possessor(31:24) / user(23:16) / group(15:8) / other(7:0) —
// each tested against the `KEY_NEED_*` bit the op requires. `check_perm` is
// the ONE call every op site makes before touching a key; no op reads `perm`
// or `uid`/`gid` directly.

use syscall::errno::Errno;

use super::store::{Key, Store, TaskIds};
use super::uapi::*;

/// Linux `key_task_permission`: pick the user/group/other perm byte, then OR
/// in the possessor byte if `t` possesses `key`.
///
/// Two details Linux gets right that a naive port does not:
///   * ownership is `cred->fsuid`, not euid — `setfsuid()` changes which keys
///     a task owns.
///   * the group byte is only consulted when the key HAS group bits
///     (`key->perm & KEY_GRP_ALL`) and a valid gid; otherwise the caller falls
///     through to the other byte, which may well be more permissive. Group
///     membership is the full supplementary list (`groups_search`), not just
///     the fsgid.
/// # C: O(members + groups) via possession search
pub(super) fn key_task_permission(g: &Store, key: &Key, t: &TaskIds, need: u32, now_ns: u64)
    -> Result<(), Errno>
{
    let mut kperm = if key.uid == t.fsuid {
        (key.perm >> KEY_PERM_USR_SHIFT) & KEY_PERM_BYTE_MASK
    } else if key.gid != GID_INVALID && key.perm & KEY_GRP_ALL != 0 && t.in_group(key.gid) {
        (key.perm >> KEY_PERM_GRP_SHIFT) & KEY_PERM_BYTE_MASK
    } else {
        (key.perm >> KEY_PERM_OTH_SHIFT) & KEY_PERM_BYTE_MASK
    };
    if is_possessed(g, key.serial, t, now_ns) { kperm |= (key.perm >> KEY_PERM_POS_SHIFT) & KEY_PERM_BYTE_MASK; }
    if kperm & need == need { Ok(()) } else { Err(Errno::Eacces) }
}

/// Does `t` possess `target` — reachable from one of `t`'s own thread/process/
/// session/user/user-session keyrings, transitively through nested keyrings?
/// Linux `is_key_possessed`.
///
/// And, when `t` is servicing an upcall, from the REQUESTER's keyrings too:
/// `lookup_user_key` decides possession by running `search_process_keyrings`
/// for the key itself, which follows the assumed token into the requesting
/// task's keyrings. Without that half a helper cannot write the answer into the
/// keyring it was TOLD to cache it in — a session keyring grants its owner
/// View and Read through the user byte and Write only through the possessor
/// byte, so `KEYCTL_INSTANTIATE <key> <payload> %S` is EACCES and no real
/// construction can complete.
///
/// A token is excluded for the same reason it is excluded from the search:
/// authority is handed over, never found.
///
/// Peeks the per-task maps (no lazy-create side effect); cycle-safe via
/// `visited`. # C: O(members)
pub(super) fn is_possessed(g: &Store, target: i32, t: &TaskIds, now_ns: u64) -> bool {
    if reachable(g, g.possession_roots(t), target) { return true; }
    if g.keys.get(&target).map(|k| k.key_type.name == REQKEY_AUTH_TYPE).unwrap_or(false) {
        return false;
    }
    match super::auth::assumed_requester(g, t, now_ns) {
        Some(rq) => reachable(g, g.possession_roots(&rq), target),
        None => false,
    }
}

/// Is `target` one of `roots`, or reachable from one through nested keyrings?
/// # C: O(members)
fn reachable(g: &Store, roots: alloc::vec::Vec<i32>, target: i32) -> bool {
    if roots.contains(&target) { return true; }
    let mut visited: alloc::vec::Vec<i32> = alloc::vec::Vec::new();
    let mut stack = roots;
    while let Some(cur) = stack.pop() {
        if visited.contains(&cur) { continue; }
        visited.push(cur);
        if let Some(k) = g.keys.get(&cur) {
            if k.members.contains(&target) { return true; }
            for &m in &k.members {
                if g.keys.get(&m).map(|kk| kk.is_keyring()).unwrap_or(false) { stack.push(m); }
            }
        }
    }
    false
}

/// Linux `key_validate` (`security/keys/permission.c`), verbatim:
/// invalidated → ENOKEY, revoked or dead → EKEYREVOKED, past its expiry →
/// EKEYEXPIRED. Every non-`KEY_LOOKUP_PARTIAL` lookup runs this, which is what
/// makes `KEYCTL_SET_TIMEOUT` and `KEYCTL_REVOKE` actually take effect rather
/// than being recorded and ignored. # C: O(1)
pub(crate) fn key_validate(key: &Key, now_ns: u64) -> Result<(), Errno> {
    if key.invalidated { return Err(Errno::Enokey); }
    if key.revoked { return Err(Errno::Ekeyrevoked); }
    if key.expiry_ns != 0 && now_ns >= key.expiry_ns { return Err(Errno::Ekeyexpired); }
    Ok(())
}

/// Whether a lookup runs `key_validate` — Linux `KEY_LOOKUP_PARTIAL` skips it
/// so a key under construction (or already revoked) can still be described,
/// have its perms set, or be given a timeout.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// `lookup_user_key(..., 0, need)` — validate.
    Full,
    /// `lookup_user_key(..., KEY_LOOKUP_PARTIAL, need)` — skip validation.
    Partial,
}

/// THE choke-point: every op site resolves a serial then calls this before
/// reading/mutating the key. `ENOKEY` if the serial names no key; the
/// `key_validate` errno if it is revoked/invalidated/expired and `mode` is
/// [`Lookup::Full`]; `EACCES` if it exists but `need` is denied.
///
/// There is deliberately no `CAP_SYS_ADMIN` bypass here. Linux's
/// `lookup_user_key` grants none for `KEY_NEED_*`: `keyctl_setperm_key` and
/// `keyctl_chown_key` consult `capable(CAP_SYS_ADMIN)` only AFTER this check
/// has already passed, as a second owner-or-sysadmin gate on the mutation
/// itself. Folding the capability in here let a privileged process rewrite the
/// perms of a key it had no `KEY_NEED_SETATTR` on at all.
/// Returns the already-negated errno ready to hand back from a syscall entry.
/// # C: O(members)
pub(crate) fn check_perm(g: &Store, serial: i32, t: &TaskIds, need: u32, mode: Lookup, now_ns: u64)
    -> Result<(), i64>
{
    let key = g.keys.get(&serial).ok_or(-(Errno::Enokey.as_i32() as i64))?;
    if mode == Lookup::Full {
        key_validate(key, now_ns).map_err(|e| -(e.as_i32() as i64))?;
    }
    key_task_permission(g, key, t, need, now_ns).map_err(|e| -(e.as_i32() as i64))
}

/// How a call site decides whether the possessor perm byte applies —
/// `make_key_ref(key, possessed)`'s second argument, which is NOT always
/// computed by reachability.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum Possess {
    /// Possessed by construction. A persistent keyring lives in the
    /// kernel-wide `.persistent_register`, which is in nobody's keyrings, so
    /// computed possession is always false and its user byte grants only
    /// View/Read — the caller could never link the ring it just asked for.
    /// Being handed the keyring IS the possession.
    Yes,
    /// NOT possessed, whatever the caller can reach.
    /// `find_keyring_by_name` passes `possessed = 0`, so joining a named
    /// session keyring turns on its user/group/other bytes alone. The default
    /// mask a named keyring is created with grants View/Read/Link and NOT
    /// Search, so a second task joins one only if its owner widened the perms
    /// with `KEYCTL_SETPERM` first.
    No,
}

/// `key_task_permission` with the possession rule stated by the call site.
/// # C: O(members)
pub(crate) fn check_perm_with(g: &Store, serial: i32, t: &TaskIds, need: u32, now_ns: u64,
    possess: Possess) -> Result<(), i64>
{
    let key = g.keys.get(&serial).ok_or(-(Errno::Enokey.as_i32() as i64))?;
    key_validate(key, now_ns).map_err(|e| -(e.as_i32() as i64))?;
    let mut kperm = if key.uid == t.fsuid {
        (key.perm >> KEY_PERM_USR_SHIFT) & KEY_PERM_BYTE_MASK
    } else if key.gid != GID_INVALID && key.perm & KEY_GRP_ALL != 0 && t.in_group(key.gid) {
        (key.perm >> KEY_PERM_GRP_SHIFT) & KEY_PERM_BYTE_MASK
    } else {
        (key.perm >> KEY_PERM_OTH_SHIFT) & KEY_PERM_BYTE_MASK
    };
    let possessed = match possess {
        Possess::Yes => true,
        Possess::No => false,
    };
    if possessed { kperm |= (key.perm >> KEY_PERM_POS_SHIFT) & KEY_PERM_BYTE_MASK; }
    if kperm & need == need { Ok(()) } else { Err(-(Errno::Eacces.as_i32() as i64)) }
}
