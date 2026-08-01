// Key construction — the `request_key(2)` upcall to `/sbin/request-key`.
//
// When a search misses and the caller supplied callout info, the kernel does
// NOT just answer ENOKEY. It allocates the key in an uninstantiated state,
// mints an authorisation token for it, and runs the userspace helper that
// knows how to build that kind of key (fetch a Kerberos ticket, resolve an AFS
// cell, unlock a dm-crypt volume). The helper fills the key in with
// `KEYCTL_INSTANTIATE`, or declines with `KEYCTL_NEGATE`/`KEYCTL_REJECT`.
//
// The helper's exit status is deliberately NOT the answer: what counts is
// whether the key ended up instantiated. A helper that succeeds but forgets to
// instantiate has failed, and one that exits non-zero after instantiating has
// succeeded. Anything the helper leaves unanswered is negated for
// `KEY_NEGATIVE_TIMEOUT` seconds, so a name that cannot be resolved does not
// re-run the helper on every request.
//
// Module manifest:
// - `construct_key_and_link` — the whole flow, called from `request_key_core`.
// - `instantiate` / `reject`  — `key_instantiate_and_link` and
//   `key_reject_and_link`, the two ways an under-construction key is answered.
//   Both are also what `KEYCTL_INSTANTIATE`/`NEGATE`/`REJECT` call.
// - `actor`                   — the upcall itself, indirected the way Linux
//   indirects it through `key_type->request_key`.

use alloc::string::String;
use alloc::vec::Vec;
use syscall::errno::Errno;

use super::auth;
use super::ops::Ctx;
use super::perm::{check_perm, Lookup};
use super::store::{Quota, Store, TaskIds, STORE};
use super::types::{self, KeyType};
use super::uapi::*;

mod upcall;

#[cfg(test)] pub use upcall::{set_actor_for_test, Upcall};

const NS_PER_SEC: u64 = 1_000_000_000;

/// `construct_get_dest_keyring`: where a constructed key gets cached when the
/// caller named no destination. The cascade FALLS THROUGH — Linux tries each
/// in turn and takes the first that exists — so the effective default is
/// "the innermost keyring the task actually has".
///
/// `KEY_REQKEY_DEFL_DEFAULT` and `..._REQUESTOR_KEYRING` first try the
/// destination recorded in a token the caller holds, which is what lets
/// `/sbin/request-key` itself call `request_key` and have the result land in
/// the ORIGINAL requester's keyring. That one case skips the Write check,
/// because the requester already proved it could write there; every other case
/// requires `KEY_NEED_WRITE`, since the default may be the session keyring and
/// joining one of those needs only Search.
/// # C: O(N)
fn dest_keyring(g: &mut Store, c: &Ctx, given: i32) -> Result<Option<i32>, i64> {
    if given != 0 {
        // A caller-supplied destination was already permission-checked by the
        // syscall entry, exactly as Linux takes it without re-checking.
        return Ok(Some(given));
    }
    let jit = *g.jit.get(&c.t.tid).unwrap_or(&KEY_REQKEY_DEFL_THREAD_KEYRING);
    let mut check = true;
    let mut ring = None;
    // The fallthrough is expressed as an ordered list of the candidates each
    // starting point admits; taking the first that EXISTS is the fallthrough.
    let from = match jit {
        KEY_REQKEY_DEFL_DEFAULT | KEY_REQKEY_DEFL_REQUESTOR_KEYRING => {
            if let Ok((_, a)) = auth::held_auth(g, &c.t) {
                if a.dest_keyring != 0 { ring = Some(a.dest_keyring); check = false; }
            }
            0
        }
        KEY_REQKEY_DEFL_THREAD_KEYRING => 0,
        KEY_REQKEY_DEFL_PROCESS_KEYRING => 1,
        KEY_REQKEY_DEFL_SESSION_KEYRING => 2,
        KEY_REQKEY_DEFL_USER_SESSION_KEYRING => 3,
        // The user keyring is not part of the fallthrough: it is reachable
        // only by naming it, so a task whose thread keyring is missing never
        // silently caches into the uid-wide ring.
        KEY_REQKEY_DEFL_USER_KEYRING => {
            let r = g.resolve(KEY_SPEC_USER_KEYRING, &c.t).map_err(|e| -(e.as_i32() as i64))?;
            ring = Some(r);
            4
        }
        // Group keyrings were never implemented, and neither is any id outside
        // the defined range.
        _ => return Err(-(Errno::Einval.as_i32() as i64)),
    };
    if ring.is_none() {
        if from <= 0 { ring = g.thread.get(&c.t.tid).copied(); }
        if ring.is_none() && from <= 1 { ring = g.process.get(&c.t.tgid).copied(); }
        if ring.is_none() && from <= 2 { ring = g.session.get(&c.t.tid).copied(); }
        if ring.is_none() && from <= 3 {
            // The user-session keyring is the end of the cascade and is CREATED
            // if absent, so the fallthrough always terminates somewhere.
            ring = Some(g.resolve(KEY_SPEC_USER_SESSION_KEYRING, &c.t)
                .map_err(|e| -(e.as_i32() as i64))?);
        }
    }
    if let (Some(r), true) = (ring, check) {
        check_perm(g, r, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns)?;
    }
    Ok(ring)
}

/// `construct_alloc_key`'s perm mask — the same `KEY_PERM_UNDEF` computation
/// `add_key` uses, so a key built by a helper is no more accessible than one
/// the caller added itself. # C: O(1)
fn construct_perm(ty: &KeyType) -> u32 { types::default_perm(ty) }

/// `construct_key_and_link`: allocate the key under construction, mint its
/// authorisation token, run the actor, and make sure the key ends up ANSWERED
/// either way.
///
/// Returns the key's serial. The caller then reads its state: a helper that
/// instantiated it gets a live key, one that negated or rejected it gets that
/// error, and one that did neither gets the ENOKEY negation applied here.
/// # C: O(N)
pub fn construct_key_and_link(c: &Ctx, ty: &'static KeyType, desc: &str, callout: &[u8],
    given_dest: i32) -> Result<i32, i64>
{
    // A keyring can never be built by an upcall: there is nothing for a helper
    // to fill in, and `keyring_instantiate` would have no payload to take.
    if ty.is_keyring { return Err(-(Errno::Eperm.as_i32() as i64)); }
    let (key, authkey, dest, args) = {
        let mut g = STORE.lock();
        let dest = dest_keyring(&mut g, c, given_dest)?;
        let quota = types::payload_quota(ty, 0);
        let key = g.mint_uninstantiated(ty, desc, c.t.fsuid, c.t.fsgid, construct_perm(ty), quota)
            .map_err(|e| -(e.as_i32() as i64))?;
        if let Some(d) = dest {
            if let Err(e) = g.link(d, key) { g.destroy(key); return Err(-(e.as_i32() as i64)); }
        }
        let authkey = match auth::request_key_auth_new(&mut g, key, REQKEY_OP_CREATE, callout,
            dest.unwrap_or(0), &c.t)
        {
            Ok(a) => a,
            Err(e) => { g.destroy(key); return Err(-(e.as_i32() as i64)); }
        };
        let args = upcall::HelperArgs::build(&mut g, c, key, authkey)
            .map_err(|e| -(e.as_i32() as i64))?;
        (key, authkey, dest, args)
    };
    // The upcall runs with the store UNLOCKED: it forks a task, execs a
    // binary and waits for it to exit, and that helper's own keyctl calls take
    // this same lock. Holding it across the wait would deadlock the helper
    // against the requester waiting for it.
    let rc = upcall::run(&args);
    let mut g = STORE.lock();
    // `call_sbin_request_key`: the helper's status is only consulted to detect
    // that it could not be run at all. What decides the outcome is whether the
    // key is still under construction.
    let rc = if rc >= 0 {
        let still_open = g.keys.get(&key).map(|k| k.under_construction).unwrap_or(true);
        let invalid = g.keys.get(&key)
            .map(|k| super::perm::key_validate(k, c.now_ns).is_err()).unwrap_or(true);
        if still_open || invalid { -(Errno::Enokey.as_i32() as i64) } else { 0 }
    } else { rc };
    // `complete_request_key`: a failed construction negates the key and burns
    // the token; a successful one only burns the token. Either way the token
    // is gone, so the authority cannot be replayed.
    if rc < 0 {
        reject(&mut g, key, KEY_NEGATIVE_TIMEOUT, Errno::Enokey.as_i32(), None, Some(authkey), c.now_ns)?;
    } else {
        auth::revoke_auth(&mut g, authkey);
    }
    upcall::teardown(&mut g, &args);
    let _ = dest;
    g.collect();
    Ok(key)
}

/// `__key_instantiate_and_link`: fill in an under-construction key, wake
/// whoever is waiting for it, cache it in `keyring`, and burn the token.
///
/// A key that is not [`KEY_IS_UNINSTANTIATED`] is EBUSY — instantiating twice
/// would let a second helper overwrite the first's answer.
/// # C: O(N)
pub fn instantiate(g: &mut Store, key: i32, payload: Vec<u8>, keyring: Option<i32>,
    authkey: Option<i32>) -> Result<(), i64>
{
    let e = |x: Errno| -(x.as_i32() as i64);
    let k = g.keys.get(&key).ok_or(e(Errno::Enokey))?;
    if k.read_state() != KEY_IS_UNINSTANTIATED { return Err(e(Errno::Ebusy)); }
    let ty = k.key_type;
    // The type's preparse runs here, not at the syscall boundary: an
    // instantiation must satisfy the same payload contract `add_key` does.
    types::vet_payload(ty, payload.len() as u64, true).map_err(e)?;
    let quota = types::payload_quota(ty, payload.len() as u64);
    g.payload_reserve(key, quota).map_err(e)?;
    let k = g.keys.get_mut(&key).expect("presence proved under the same held lock");
    k.payload = payload;
    k.state = KEY_IS_POSITIVE;
    k.under_construction = false;
    super::notify::instantiated(g, key, 0);
    if let Some(r) = keyring { g.link(r, key).map_err(e)?; super::notify::linked(g, r, key); }
    if let Some(a) = authkey { auth::invalidate_auth(g, a); }
    Ok(())
}

/// `key_reject_and_link` — and `key_negate_and_link`, which is this with
/// `ENOKEY`. The key is marked with `-error`, which every later lookup hands
/// back, and given `timeout` seconds to live.
///
/// Note the timeout rule differs from `KEYCTL_SET_TIMEOUT`'s: here `0` means
/// "expires now", not "never". A negative key with no expiry would poison the
/// name permanently.
///
/// A restricted destination keyring refuses a negative key outright (EPERM): a
/// keyring whose contents are vetted must not be handed an unvetted failure.
/// # C: O(N)
pub fn reject(g: &mut Store, key: i32, timeout: u64, error: i32, keyring: Option<i32>,
    authkey: Option<i32>, now_ns: u64) -> Result<(), i64>
{
    let e = |x: Errno| -(x.as_i32() as i64);
    if let Some(r) = keyring {
        if g.keys.get(&r).map(|k| k.restrict_reject).unwrap_or(false) { return Err(e(Errno::Eperm)); }
    }
    let k = g.keys.get(&key).ok_or(e(Errno::Enokey))?;
    if k.read_state() != KEY_IS_UNINSTANTIATED { return Err(e(Errno::Ebusy)); }
    let k = g.keys.get_mut(&key).expect("presence proved under the same held lock");
    k.state = -error;
    k.under_construction = false;
    k.expiry_ns = now_ns.saturating_add(timeout.saturating_mul(NS_PER_SEC)).max(1);
    // A watcher of a rejected key is told the request was answered AND with
    // what error, so it need not re-look-up the key to find out.
    super::notify::instantiated(g, key, error as u32);
    if let Some(r) = keyring { g.link(r, key).map_err(e)?; super::notify::linked(g, r, key); }
    if let Some(a) = authkey { auth::invalidate_auth(g, a); }
    Ok(())
}

/// `wait_for_key_construction`: the answer a requester gets for a key it just
/// asked to be built. State first, validity second — a negative key that has
/// also expired still reports the error userspace chose for it, rather than
/// looking merely stale. A key nobody ever answered is EIO.
/// # C: O(1)
pub fn construction_result(g: &Store, key: i32, now_ns: u64) -> Result<(), i64> {
    let k = match g.keys.get(&key) { Some(k) => k, None => return Err(-(Errno::Enokey.as_i32() as i64)) };
    let state = k.read_state();
    if state < 0 { return Err(state as i64); }
    super::perm::key_validate(k, now_ns).map_err(|x| -(x.as_i32() as i64))?;
    if state == KEY_IS_UNINSTANTIATED { return Err(-(Errno::Eio.as_i32() as i64)); }
    Ok(())
}

/// A helper's per-request session keyring is named after the key it is
/// building, so a `/proc/keys` reader can tell which request a live helper is
/// servicing. # C: O(1)
pub fn helper_keyring_name(key: i32) -> String { alloc::format!("_req.{key}") }

/// Mint that keyring. `KEY_ALLOC_QUOTA_OVERRUN`: a helper must be launchable
/// even for a uid that has exhausted its quota, or a user could lock itself out
/// of ever obtaining another credential. # C: O(log N)
pub fn new_helper_keyring(g: &mut Store, key: i32, t: &TaskIds) -> Result<i32, Errno> {
    let name = helper_keyring_name(key);
    g.new_keyring(&name, t.fsuid, t.fsgid, REQKEY_HELPER_KEYRING_PERM, Quota::Overrun)
}

#[cfg(test)] mod tests;
