// Single-key ops: add_key(2) and the keyctl commands that address one key —
// UPDATE, REVOKE, INVALIDATE, CHOWN, SETPERM, SET_TIMEOUT, READ, DESCRIBE,
// GET_SECURITY.

use alloc::string::String;
use alloc::vec::Vec;
use syscall::errno::Errno;

use super::{e, Ctx};
use super::super::perm::{check_perm, Lookup};
use super::super::store::STORE;
use super::super::types;
use super::super::uapi::*;

/// `add_key(2)` core — Linux `key_create_or_update`:
///   * the type must be registered, else ENODEV;
///   * a `logon` description must have `subsystem:key` form
///     (`logon_vet_description`);
///   * an empty description is EINVAL, and a `keyring` whose description
///     starts with `.` is EPERM (reserved for kernel-internal keyrings);
///   * the destination keyring needs `KEY_NEED_WRITE`, checked BEFORE the key
///     is minted;
///   * **if a key of the same type+description is already in that keyring and
///     the type is updatable, the payload is written into THAT key and its
///     existing serial returned** — `add_key` is create-OR-UPDATE, so a daemon
///     re-adding its key does not accumulate duplicates.
/// # C: O(N)
pub fn add_key_core(c: &Ctx, key_type: &str, desc: &str, payload: Vec<u8>, dest: i32) -> i64 {
    let ty = match types::lookup(key_type) { Some(t) => t, None => return e(Errno::Enodev) };
    if desc.is_empty() { return e(Errno::Einval); }
    if ty.is_keyring && desc.starts_with('.') { return e(Errno::Eperm); }
    if let Err(err) = types::vet_description(ty, desc) { return e(err); }
    let mut g = STORE.lock();
    let ring_id = if dest == 0 { KEY_SPEC_SESSION_KEYRING } else { dest };
    let ring = match g.resolve(ring_id, &c.t) { Some(r) => r, None => return e(Errno::Enokey) };
    if let Err(rv) = check_perm(&g, ring, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
    if g.keys.get(&ring).map(|k| !k.is_keyring()).unwrap_or(true) { return e(Errno::Enotdir); }
    if ty.updatable {
        let existing = g.keys[&ring].members.iter().copied().find(|s| {
            g.keys.get(s).map(|k| core::ptr::eq(k.key_type, ty) && k.description == desc
                && !k.revoked && !k.invalidated).unwrap_or(false)
        });
        if let Some(s) = existing {
            if let Err(rv) = check_perm(&g, s, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
            g.keys.get_mut(&s).expect("membership proved existence under the held lock").payload = payload;
            return s as i64;
        }
    }
    let serial = g.mint(ty, desc, payload, c.t.fsuid, c.t.fsgid);
    match g.link(ring, serial) {
        Ok(()) => serial as i64,
        Err(err) => { g.keys.remove(&serial); e(err) }
    }
}

/// `KEYCTL_UPDATE` core: `KEY_NEED_WRITE` on the key, and the type must have
/// an `update` method (Linux returns EOPNOTSUPP when it does not).
/// # C: O(payload)
pub fn update_core(c: &Ctx, serial: i32, payload: Vec<u8>) -> i64 {
    let mut g = STORE.lock();
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
    let k = g.keys.get_mut(&serial).expect("check_perm proved existence under the same held lock");
    if !k.key_type.updatable { return e(Errno::Eopnotsupp); }
    k.payload = payload;
    0
}

/// `KEYCTL_REVOKE` core: `KEY_NEED_WRITE` on the key, with a PARTIAL lookup so
/// an already-revoked key answers EKEYREVOKED from `key_revoke` rather than
/// being invisible. # C: O(log N)
pub fn revoke_core(c: &Ctx, serial: i32) -> i64 {
    let mut g = STORE.lock();
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_WRITE, Lookup::Partial, c.now_ns) { return rv; }
    let k = g.keys.get_mut(&serial).expect("check_perm proved existence under the same held lock");
    if k.invalidated { return e(Errno::Enokey); }
    if k.revoked { return e(Errno::Ekeyrevoked); }
    k.revoked = true;
    0
}

/// `KEYCTL_INVALIDATE` core — Linux `keyctl_invalidate_key`: needs
/// `KEY_NEED_SEARCH`, then marks the key invalidated and unlinks it from every
/// keyring (Linux hands it to the gc, which does exactly that). A subsequent
/// lookup is ENOKEY, not EKEYREVOKED. # C: O(N)
pub fn invalidate_core(c: &Ctx, serial: i32) -> i64 {
    let mut g = STORE.lock();
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_SEARCH, Lookup::Full, c.now_ns) { return rv; }
    g.keys.get_mut(&serial).expect("check_perm proved existence under the same held lock").invalidated = true;
    for k in g.keys.values_mut() { k.members.retain(|&m| m != serial); }
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
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_SETATTR, Lookup::Partial, c.now_ns) { return rv; }
    let k = g.keys.get(&serial).expect("check_perm proved existence under the same held lock");
    let privileged = (uid != UNCHANGED && k.uid != uid)
        || (gid != UNCHANGED && k.gid != gid && !c.t.in_group(gid));
    if privileged && !c.sys_admin { return e(Errno::Eacces); }
    let k = g.keys.get_mut(&serial).expect("presence proved under the same held lock");
    if uid != UNCHANGED { k.uid = uid; }
    if gid != UNCHANGED { k.gid = gid; }
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
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_SETATTR, Lookup::Partial, c.now_ns) { return rv; }
    let k = g.keys.get_mut(&serial).expect("check_perm proved existence under the same held lock");
    if k.uid != c.t.fsuid && !c.sys_admin { return e(Errno::Eacces); }
    k.perm = perm;
    0
}

/// `KEYCTL_SET_TIMEOUT` core — Linux `keyctl_set_timeout`: `KEY_NEED_SETATTR`
/// on the key via a PARTIAL lookup, `secs == 0` clears the expiry. There is no
/// `CAP_SYS_ADMIN` bypass; the only alternative path Linux offers is holding
/// the key's instantiation authorisation token, which requires a `request_key`
/// upcall to be in flight. `now_ns` comes from [`Ctx`] so this core stays
/// clock-free. # C: O(log N)
pub fn set_timeout_core(c: &Ctx, serial: i32, secs: u64) -> i64 {
    let mut g = STORE.lock();
    if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_SETATTR, Lookup::Partial, c.now_ns) { return rv; }
    let k = g.keys.get_mut(&serial).expect("check_perm proved existence under the same held lock");
    k.expiry_ns = if secs == 0 { 0 } else { c.now_ns.saturating_add(secs.saturating_mul(NS_PER_SEC)) };
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
pub fn read_core(c: &Ctx, serial: i32) -> Result<Vec<u8>, i64> {
    let g = STORE.lock();
    let k = g.keys.get(&serial).ok_or(e(Errno::Enokey))?;
    super::super::perm::key_validate(k, c.now_ns).map_err(e)?;
    if !k.key_type.readable { return Err(e(Errno::Eopnotsupp)); }
    if check_perm(&g, serial, &c.t, KEY_NEED_READ, Lookup::Full, c.now_ns).is_err()
        && !super::super::perm::is_possessed(&g, serial, &c.t)
    {
        return Err(e(Errno::Eacces));
    }
    let k = g.keys.get(&serial).expect("presence proved under the same held lock");
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
    let g = STORE.lock();
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
    let g = STORE.lock();
    check_perm(&g, serial, &c.t, KEY_NEED_VIEW, Lookup::Partial, c.now_ns)?;
    Ok(String::from("\0"))
}
