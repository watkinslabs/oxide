// The instantiation authorisation token — `.request_key_auth`.
//
// This is the object the whole instantiation family turns on. When the kernel
// cannot find a key and asks userspace to build one, it mints a token naming
// the key under construction, the keyring the answer should be cached in, and
// the identity of the task that asked. `/sbin/request-key` gets the token in
// its session keyring; `KEYCTL_ASSUME_AUTHORITY` picks it up; and
// `KEYCTL_INSTANTIATE`/`NEGATE`/`REJECT` are permitted only while it is held.
//
// The token is what makes those commands safe: without it any process could
// fill in any uninstantiated key. With it, the right to instantiate is granted
// to exactly one target key, handed to exactly the helper that was asked to
// build it, and destroyed the moment the key is answered.

use alloc::string::String;
use alloc::vec::Vec;
use syscall::errno::Errno;

use super::ops::search::{self, Expired};
use super::perm::key_validate;
use super::store::{AuthData, KeyNs, Store, TaskIds};
use super::types;
use super::uapi::*;

/// `request_key_auth_new`. The description is the target's serial in hex —
/// `key_get_instantiation_authkey` finds the token by searching for exactly
/// that name, which is how a helper's `KEYCTL_ASSUME_AUTHORITY(<serial>)`
/// locates its own token and no one else's.
///
/// Allocated with `KEY_ALLOC_NOT_IN_QUOTA`: servicing somebody else's request
/// must not consume the helper's key quota, or a busy helper would stop being
/// able to accept work.
///
/// A helper that is itself already servicing a request passes the ORIGINAL
/// requester's identity down instead of its own, so a chain of upcalls all
/// instantiate on behalf of the task at the head of it.
/// # C: O(log N)
pub fn request_key_auth_new(g: &mut Store, target: i32, op: &str, callout: &[u8],
    dest_keyring: i32, caller: &TaskIds) -> Result<i32, Errno>
{
    let (requester, pid) = match g.authkey.get(&caller.tid).copied() {
        Some(held) => {
            let k = g.keys.get(&held).ok_or(Errno::Enokey)?;
            // A revoked token means the key it covered has already been
            // answered; the authority it granted is spent.
            if k.revoked { return Err(Errno::Ekeyrevoked); }
            let a = k.auth.as_ref().ok_or(Errno::Ekeyrevoked)?;
            (a.requester.clone(), a.pid)
        }
        None => (caller.clone(), caller.tgid),
    };
    let desc = alloc::format!("{target:x}");
    let ty = types::auth_type();
    let serial = g.mint_not_in_quota(ty, &desc, caller.fsuid, caller.fsgid,
        REQKEY_AUTH_PERM, KeyNs::of(caller, ty))?;
    let k = g.keys.get_mut(&serial).expect("just minted under the held lock");
    // The callout info IS the token's readable payload — the helper reads it
    // back with `KEYCTL_READ` to learn what it was asked for. One copy, in the
    // place the type's read method looks.
    k.payload = callout.to_vec();
    k.auth = Some(AuthData {
        target, dest_keyring, requester, pid,
        op: truncate_op(op),
    });
    Ok(serial)
}

/// `strscpy(rka->op, op, sizeof(rka->op))` — `char op[8]`, so seven characters
/// plus the terminator. # C: O(1)
fn truncate_op(op: &str) -> String {
    let n = op.char_indices().nth(REQKEY_OP_MAX).map(|(i, _)| i).unwrap_or(op.len());
    String::from(&op[..n])
}

/// `key_get_instantiation_authkey`: find the token for `target` among the
/// caller's OWN keyrings. Searching rather than accepting a serial is the
/// point — a task can only assume authority over a key it was actually handed
/// the token for.
///
/// `-EAGAIN` from the search (nothing there) becomes ENOKEY; a revoked token is
/// EKEYREVOKED, because the key it covered has already been answered.
/// # C: O(N)
pub fn get_instantiation_authkey(g: &Store, target: i32, t: &TaskIds, now_ns: u64)
    -> Result<i32, Errno>
{
    let desc = alloc::format!("{target:x}");
    match search::search_process(g, t, REQKEY_AUTH_TYPE, &desc, now_ns, Expired::Report) {
        Ok(s) => {
            let k = g.keys.get(&s).ok_or(Errno::Enokey)?;
            if k.revoked { return Err(Errno::Ekeyrevoked); }
            Ok(s)
        }
        Err(e) if e == search::NO_MATCH => Err(Errno::Enokey),
        Err(e) if e == Errno::Eacces.as_i32() => Err(Errno::Eacces),
        Err(_) => Err(Errno::Enokey),
    }
}

/// `keyctl_change_reqkey_auth`: install (or, with `None`, divest) the token the
/// caller acts under. # C: O(log N)
pub fn change_reqkey_auth(g: &mut Store, tid: u32, authkey: Option<i32>) {
    match authkey {
        Some(a) => { g.authkey.insert(tid, a); }
        None => { g.authkey.remove(&tid); }
    }
}

/// The token the caller currently holds, and its record — the state
/// `KEYCTL_INSTANTIATE`/`NEGATE`/`REJECT` all open by fetching.
///
/// `request_key_auth_get` distinguishes the two failures Linux distinguishes:
/// holding NO token at all is EPERM (the caller was never granted authority),
/// while holding a REVOKED one is EKEYREVOKED (it was, but the key has since
/// been answered). Collapsing them would tell a helper it was never authorised
/// when in fact it raced itself.
/// # C: O(log N)
pub fn held_auth(g: &Store, t: &TaskIds) -> Result<(i32, AuthData), Errno> {
    let a = g.authkey.get(&t.tid).copied().ok_or(Errno::Eperm)?;
    let k = g.keys.get(&a).ok_or(Errno::Ekeyrevoked)?;
    if k.revoked { return Err(Errno::Ekeyrevoked); }
    let data = k.auth.clone().ok_or(Errno::Ekeyrevoked)?;
    Ok((a, data))
}

/// `key_revoke(authkey)` for a token: drop the record, so any further attempt
/// to act under it is EKEYREVOKED rather than a second instantiation.
/// # C: O(log N)
pub fn revoke_auth(g: &mut Store, authkey: i32) {
    if let Some(k) = g.keys.get_mut(&authkey) {
        k.revoked = true;
        k.auth = None;
        k.payload = Vec::new();
    }
}

/// `key_invalidate(authkey)` — what `key_instantiate_and_link` and
/// `key_reject_and_link` do to the token once the key is answered: it is
/// unlinked from every keyring and collected, so the authority cannot be
/// re-assumed. # C: O(N)
pub fn invalidate_auth(g: &mut Store, authkey: i32) {
    if let Some(k) = g.keys.get_mut(&authkey) {
        k.invalidated = true;
        k.auth = None;
        k.payload = Vec::new();
    }
    for k in g.keys.values_mut() { k.members.retain(|&m| m != authkey); }
    let holders: Vec<u32> = g.authkey.iter().filter(|(_, &v)| v == authkey).map(|(&k, _)| k).collect();
    for tid in holders { g.authkey.remove(&tid); }
    g.collect();
}

/// `get_instantiation_keyring`: where an instantiated key gets cached.
///
///   * `0` — nowhere;
///   * a real serial — that keyring, which needs `KEY_NEED_WRITE`;
///   * `KEY_SPEC_REQKEY_AUTH_KEY` (`-7`) — EINVAL, a token is not a keyring;
///   * any other special id down to `-8` — the destination recorded in the
///     TOKEN, not one of the helper's own. This is what makes the answer land
///     in the requester's keyring rather than the helper's, and it is why the
///     helper needs no permission on it: the requester already proved that.
///   * below `-8` — ENOKEY.
/// # C: O(N)
pub fn instantiation_keyring(g: &mut Store, ringid: i32, a: &AuthData, t: &TaskIds, now_ns: u64)
    -> Result<Option<i32>, i64>
{
    use super::perm::{check_perm, Lookup};
    if ringid == 0 { return Ok(None); }
    if ringid > 0 {
        let d = g.resolve(ringid, t).map_err(|e| -(e.as_i32() as i64))?;
        check_perm(g, d, t, KEY_NEED_WRITE, Lookup::Full, now_ns)?;
        return Ok(Some(d));
    }
    if ringid == KEY_SPEC_REQKEY_AUTH_KEY { return Err(-(Errno::Einval.as_i32() as i64)); }
    if ringid >= KEY_SPEC_REQUESTOR_KEYRING {
        return Ok(if a.dest_keyring == 0 { None } else { Some(a.dest_keyring) });
    }
    Err(-(Errno::Enokey.as_i32() as i64))
}

/// The identity recorded in the live token the caller has assumed — `rka->cred`
/// — whose keyrings both the process-keyrings search and the possession test
/// fall back to. `None` when the caller is servicing no upcall, which is the
/// state that keeps that reach exactly as wide as the authority. # C: O(log N)
pub(super) fn assumed_requester(g: &Store, t: &TaskIds, now_ns: u64) -> Option<TaskIds> {
    let a = *g.authkey.get(&t.tid)?;
    if !auth_is_live(g, a, now_ns) { return None; }
    g.keys.get(&a)?.auth.as_ref().map(|d| d.requester.clone())
}

/// The token's own validity, for the paths that must not act under an expired
/// or invalidated one. # C: O(1)
pub fn auth_is_live(g: &Store, authkey: i32, now_ns: u64) -> bool {
    g.keys.get(&authkey).map(|k| key_validate(k, now_ns).is_ok() && k.auth.is_some()).unwrap_or(false)
}
