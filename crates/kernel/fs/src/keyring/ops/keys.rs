// Single-key ops: add_key(2) and the keyctl commands that address one key —
// UPDATE, REVOKE, INVALIDATE, CHOWN, SETPERM, SET_TIMEOUT, READ, DESCRIBE,
// GET_SECURITY.

use alloc::string::String;
use alloc::vec::Vec;
use syscall::errno::Errno;

use super::{e, Ctx};
use super::super::notify;
use super::super::perm::{check_perm, Lookup};
use super::super::store::{Store, STORE};
use super::super::types;
use super::super::uapi::*;

/// `add_key(2)` core — Linux `key_create_or_update`, in ITS order:
///   1. the type must be registered, else ENODEV;
///   2. an empty/absent description is EINVAL;
///   3. the destination must be a keyring (ENOTDIR);
///   4. the type's `preparse` vets the payload — a `keyring` takes none, a
///      `user`/`logon` payload is 1..=32767 bytes, a `big_key` up to 1 MiB, and
///      a NULL payload pointer is EINVAL rather than an empty payload;
///   5. the destination keyring needs `KEY_NEED_WRITE`;
///   6. **if a key of the same type+description is already in that keyring and
///      the type is updatable, the payload is written into THAT key and its
///      existing serial returned** — `add_key` is create-OR-UPDATE, so a daemon
///      re-adding its key does not accumulate duplicates. A `keyring` has no
///      update method, so adding one twice mints two distinct keyrings;
///   7. `key_alloc` vets a `logon` description and charges the owner's quota,
///      which is where EDQUOT comes from.
///
/// The `.`-prefixed `keyring` EPERM and the payload length ceiling are applied
/// by the syscall entry, ahead of all of this. # C: O(N)
pub fn add_key_core(c: &Ctx, key_type: &str, desc: &str, payload: Vec<u8>, have_payload_ptr: bool,
    dest: i32) -> i64
{
    let ty = match types::lookup(key_type) { Some(t) => t, None => return e(Errno::Enodev) };
    // A key must be named. Only a type whose payload can propose a name for
    // itself may be added without one, and even then the proposal has to
    // materialise — see below.
    if desc.is_empty() && !ty.describes_itself { return e(Errno::Einval); }
    let mut g = STORE.lock();
    // The destination keyring is MANDATORY: an id of 0 is not shorthand for
    // the session keyring, it is EINVAL out of the id resolver. Treating it as
    // the session keyring turns a caller's uninitialised keyring argument into
    // a silently successful key insertion.
    let ring = match g.resolve(dest, &c.t) { Ok(r) => r, Err(err) => return e(err) };
    if g.keys.get(&ring).map(|k| !k.is_keyring()).unwrap_or(true) { return e(Errno::Enotdir); }
    if let Err(err) = types::vet_payload(ty, payload.len() as u64, have_payload_ptr) { return e(err); }
    // The type's parser runs BEFORE the destination keyring is checked for
    // write access, so a malformed payload is reported as malformed rather
    // than as a permission problem on a keyring the caller never got to use.
    let parsed = match types::preparse_blob(ty, &payload) { Ok(d) => d, Err(err) => return e(err) };
    let named: String = if !desc.is_empty() { String::from(desc) } else {
        match parsed.description.as_ref() { Some(d) => d.clone(), None => return e(Errno::Einval) }
    };
    let desc: &str = &named;
    if let Err(rv) = check_perm(&g, ring, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
    let quota = types::payload_quota(ty, payload.len() as u64);
    if ty.updatable {
        let existing = g.keys[&ring].members.iter().copied().find(|s| {
            g.keys.get(s).map(|k| core::ptr::eq(k.key_type, ty) && k.description == desc
                && !k.revoked && !k.invalidated).unwrap_or(false)
        });
        if let Some(s) = existing {
            if let Err(rv) = check_perm(&g, s, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
            if let Err(err) = g.payload_reserve(s, quota) { return e(err); }
            g.keys.get_mut(&s).expect("membership proved existence under the held lock").payload = payload;
            notify::updated(&g, s);
            return s as i64;
        }
    }
    if let Err(err) = types::vet_description(ty, desc) { return e(err); }
    let serial = match g.mint(ty, desc, payload, c.t.fsuid, c.t.fsgid, quota) {
        Ok(s) => s, Err(err) => return e(err),
    };
    let key = g.keys.get_mut(&serial).expect("just minted under the held store lock");
    key.asymmetric_ids = parsed.asymmetric_ids;
    key.asymmetric_name_id = parsed.asymmetric_name_id;
    match g.link(ring, serial) {
        Ok(()) => serial as i64,
        Err(err) => { g.destroy(serial); e(err) }
    }
}

/// `KEYCTL_UPDATE` core — Linux `key_update`: `KEY_NEED_WRITE` on the key, then
/// EOPNOTSUPP if the type has no `update` method (a `keyring` has none), then
/// the type's `preparse` payload contract, then the quota delta, which is where
/// a growing payload can EDQUOT. # C: O(payload)
pub fn update_core(c: &Ctx, serial: i32, payload: Vec<u8>, have_payload_ptr: bool) -> i64 {
    let mut g = STORE.lock();
    let serial = match user_key(&mut g, serial, c) { Ok(s) => s, Err(err) => return e(err) };
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
    let ty = g.keys.get(&serial).expect("check_perm proved existence under the same held lock").key_type;
    if !ty.updatable { return e(Errno::Eopnotsupp); }
    if let Err(err) = types::vet_payload(ty, payload.len() as u64, have_payload_ptr) { return e(err); }
    if let Err(err) = g.payload_reserve(serial, types::payload_quota(ty, payload.len() as u64)) {
        return e(err);
    }
    g.keys.get_mut(&serial).expect("presence proved under the same held lock").payload = payload;
    notify::updated(&g, serial);
    0
}

/// `KEYCTL_REVOKE` core — Linux `keyctl_revoke_key`. Two details a plain
/// `KEY_NEED_WRITE` check gets wrong:
///
///   * the lookup is FULL, so an already-revoked or expired key answers
///     EKEYREVOKED/EKEYEXPIRED from `key_validate` BEFORE the permission check
///     — a caller re-revoking a key learns it is already revoked rather than
///     being told it lacks access;
///   * on EACCES the lookup is retried with `KEY_NEED_SETATTR`. Revocation is
///     an attribute change as much as a write, and a key whose perm grants
///     Setattr but not Write is still revocable by its holder. Only EACCES is
///     retried; every other error stands.
/// # C: O(log N)
pub fn revoke_core(c: &Ctx, serial: i32) -> i64 {
    let mut g = STORE.lock();
    let serial = match user_key(&mut g, serial, c) { Ok(s) => s, Err(err) => return e(err) };
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) {
        if rv != e(Errno::Eacces) { return rv; }
        if let Err(rv2) = check_perm(&g, serial, &c.t, KEY_NEED_SETATTR, Lookup::Full, c.now_ns) {
            return rv2;
        }
    }
    // `key_revoke` is idempotent; the full lookup above is what turns a second
    // revoke into EKEYREVOKED, so reaching here means the key was live.
    g.keys.get_mut(&serial).expect("check_perm proved existence under the same held lock").revoked = true;
    notify::revoked(&g, serial);
    0
}

/// `KEYCTL_INVALIDATE` core — Linux `keyctl_invalidate_key`: needs
/// `KEY_NEED_SEARCH`, then marks the key invalidated and unlinks it from every
/// keyring (Linux hands it to the gc, which does exactly that). A subsequent
/// lookup is ENOKEY, not EKEYREVOKED. # C: O(N)
pub fn invalidate_core(c: &Ctx, serial: i32) -> i64 {
    let mut g = STORE.lock();
    let serial = match user_key(&mut g, serial, c) { Ok(s) => s, Err(err) => return e(err) };
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_SEARCH, Lookup::Full, c.now_ns) { return rv; }
    g.keys.get_mut(&serial).expect("check_perm proved existence under the same held lock").invalidated = true;
    notify::invalidated(&g, serial);
    for k in g.keys.values_mut() { k.members.retain(|&m| m != serial); }
    // Unlinked from everything, the key has no references left: the gc
    // collects it and hands its quota charge back to its owner.
    g.collect();
    0
}

/// `KEYCTL_CHOWN` core — Linux `keyctl_chown_key`. `(uid_t)-1` leaves that id
/// alone; both `-1` is a no-op success. After the `KEY_NEED_SETATTR` check,
/// a SECOND gate applies: giving the key to a different uid, or to a group the
/// caller does not subscribe to, requires `CAP_SYS_ADMIN`. # C: O(log N)
pub fn chown_core(c: &Ctx, serial: i32, uid: u32, gid: u32) -> i64 {
    const UNCHANGED: u32 = u32::MAX;
    if uid == UNCHANGED && gid == UNCHANGED { return 0; }
    let mut g = STORE.lock();
    let serial = match user_key(&mut g, serial, c) { Ok(s) => s, Err(err) => return e(err) };
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_SETATTR, Lookup::Partial, c.now_ns) { return rv; }
    let k = g.keys.get(&serial).expect("check_perm proved existence under the same held lock");
    let privileged = (uid != UNCHANGED && k.uid != uid)
        || (gid != UNCHANGED && k.gid != gid && !c.t.in_group(gid));
    if privileged && !c.sys_admin { return e(Errno::Eacces); }
    let k = g.keys.get_mut(&serial).expect("presence proved under the same held lock");
    if uid != UNCHANGED { k.uid = uid; }
    if gid != UNCHANGED { k.gid = gid; }
    notify::setattr(&g, serial);
    0
}

/// `KEYCTL_SETPERM` core — Linux `keyctl_setperm_key`:
///   1. reject any bit outside the four 6-bit bytes with EINVAL, BEFORE the
///      key is even looked up;
///   2. `KEY_NEED_SETATTR` on the key (PARTIAL lookup — perms may be set on a
///      revoked key);
///   3. then, and only then, `uid_eq(key->uid, current_fsuid()) ||
///      capable(CAP_SYS_ADMIN)`, else EACCES. Step 3 is a separate gate: a
///      privileged process still cannot set perms on a key it has no SETATTR
///      permission on.
/// # C: O(log N)
pub fn setperm_core(c: &Ctx, serial: i32, perm: u32) -> i64 {
    if perm & !KEY_PERM_VALID != 0 { return e(Errno::Einval); }
    let mut g = STORE.lock();
    let serial = match user_key(&mut g, serial, c) { Ok(s) => s, Err(err) => return e(err) };
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_SETATTR, Lookup::Partial, c.now_ns) { return rv; }
    let k = g.keys.get_mut(&serial).expect("check_perm proved existence under the same held lock");
    if k.uid != c.t.fsuid && !c.sys_admin { return e(Errno::Eacces); }
    k.perm = perm;
    notify::setattr(&g, serial);
    0
}

/// `KEYCTL_SET_TIMEOUT` core — Linux `keyctl_set_timeout`: `KEY_NEED_SETATTR`
/// on the key via a PARTIAL lookup (a key under construction can be given a
/// timeout), and `secs == 0` CLEARS the expiry — the opposite of
/// `KEYCTL_REJECT`'s timeout, where 0 means "expires immediately".
///
/// There is no `CAP_SYS_ADMIN` bypass. The one alternative path is holding the
/// key's instantiation authorisation token: a helper building a key must be
/// able to set its lifetime before it fills it in, and it has no permission on
/// a key it does not yet own. `now_ns` comes from [`Ctx`] so this core stays
/// clock-free. # C: O(N)
pub fn set_timeout_core(c: &Ctx, serial: i32, secs: u64) -> i64 {
    let mut g = STORE.lock();
    let serial = match user_key(&mut g, serial, c) { Ok(s) => s, Err(err) => return e(err) };
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_SETATTR, Lookup::Partial, c.now_ns) {
        if rv != e(Errno::Eacces) { return rv; }
        if super::super::auth::get_instantiation_authkey(&g, serial, &c.t, c.now_ns).is_err() {
            return rv;
        }
    }
    let k = g.keys.get_mut(&serial).expect("check_perm proved existence under the same held lock");
    k.expiry_ns = if secs == 0 { 0 } else { c.now_ns.saturating_add(secs.saturating_mul(NS_PER_SEC)) };
    notify::setattr(&g, serial);
    0
}

const NS_PER_SEC: u64 = 1_000_000_000;

/// `KEYCTL_READ` core — Linux `keyctl_read_key`. The type must have a `read`
/// method (`logon` deliberately does not, so its payload is write-only and
/// reading it is EOPNOTSUPP). `KEY_NEED_READ` grants access; failing that,
/// merely POSSESSING the key does too, which is Linux's documented fallback
/// (`if (!is_key_possessed(key_ref)) return -EACCES;`). Returns the raw bytes
/// (keyring: native-endian 4-byte member serials; else the payload).
/// # C: O(payload/members)
pub fn read_core(c: &Ctx, serial: i32, buflen: u64) -> Result<Vec<u8>, i64> {
    let mut g = STORE.lock();
    let serial = user_key(&mut g, serial, c).map_err(e)?;
    let g = g;
    // `keyctl_read_key` collapses EVERY lookup failure — no such serial, and
    // equally a revoked or expired key — to a flat ENOKEY, so READ is the one
    // command that never distinguishes them.
    let k = g.keys.get(&serial).ok_or(e(Errno::Enokey))?;
    super::super::perm::key_validate(k, c.now_ns).map_err(|_| e(Errno::Enokey))?;
    // Access is decided BEFORE the type is asked whether it can be read at
    // all, so a `logon` key the caller may not touch is EACCES, not the
    // EOPNOTSUPP that would leak that the payload is write-only.
    if check_perm(&g, serial, &c.t, KEY_NEED_READ, Lookup::Full, c.now_ns).is_err()
        && !super::super::perm::is_possessed(&g, serial, &c.t, c.now_ns)
    {
        return Err(e(Errno::Eacces));
    }
    let k = g.keys.get(&serial).expect("presence proved under the same held lock");
    if !k.key_type.readable { return Err(e(Errno::Eopnotsupp)); }
    // A keyring reads out as an array of 4-byte serials, so a buffer length
    // that cannot hold a whole number of them is EINVAL.
    if k.is_keyring() && buflen % KEY_SERIAL_SIZE != 0 { return Err(e(Errno::Einval)); }
    Ok(if k.is_keyring() {
        let mut v = Vec::with_capacity(k.members.len() * 4);
        for &m in &k.members { v.extend_from_slice(&m.to_ne_bytes()); }
        v
    } else { k.payload.clone() })
}

/// `KEYCTL_DESCRIBE` core — Linux `keyctl_describe_key`: `KEY_NEED_VIEW` via a
/// PARTIAL lookup (a revoked key can still be described), returning
/// `type;uid;gid;perm;desc` with a trailing NUL. # C: O(log N)
pub fn describe_core(c: &Ctx, serial: i32) -> Result<String, i64> {
    let mut g = STORE.lock();
    let serial = user_key(&mut g, serial, c).map_err(e)?;
    let g = g;
    check_perm(&g, serial, &c.t, KEY_NEED_VIEW, Lookup::Partial, c.now_ns)?;
    let k = g.keys.get(&serial).expect("check_perm proved existence under the same held lock");
    let mut s = alloc::format!("{};{};{};{:08x};{}",
        k.key_type.name, k.uid as i32, k.gid as i32, k.perm, k.description);
    s.push('\0');
    Ok(s)
}

/// `KEYCTL_GET_SECURITY` core — Linux `keyctl_get_security`: `KEY_NEED_VIEW`
/// via a PARTIAL lookup, then `security_key_getsecurity`. With no LSM stacked
/// that hook returns 0, and Linux answers userspace with a one-byte empty
/// string, so the returned length is 1. # C: O(log N)
pub fn get_security_core(c: &Ctx, serial: i32) -> Result<String, i64> {
    let mut g = STORE.lock();
    let serial = user_key(&mut g, serial, c).map_err(e)?;
    let g = g;
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_VIEW, Lookup::Partial, c.now_ns) {
        // Same authorisation-token override as `KEYCTL_SET_TIMEOUT`: a helper
        // servicing a request may inspect the key it was asked to build.
        if rv != e(Errno::Eacces) { return Err(rv); }
        if super::super::auth::get_instantiation_authkey(&g, serial, &c.t, c.now_ns).is_err() {
            return Err(rv);
        }
    }
    Ok(String::from("\0"))
}

/// `lookup_user_key`: the key id a keyctl command was handed, turned into a
/// real serial. A command that names a KEY takes the same id shape as one that
/// names a keyring — a positive serial, or a special id — so both go through
/// the one resolution rather than only the keyring-taking commands doing it.
///
/// The id that matters most is `@a`: a helper servicing an upcall reads the
/// authorisation token to learn what it was asked to build. Without the
/// resolution that id reaches the store as a literal negative number, matches
/// no key, and comes back ENOKEY — which the helper cannot tell from holding no
/// authority at all, so it gives up before answering anything.
/// # C: O(log N)
fn user_key(g: &mut Store, id: i32, c: &Ctx) -> Result<i32, Errno> {
    g.resolve(id, &c.t)
}
