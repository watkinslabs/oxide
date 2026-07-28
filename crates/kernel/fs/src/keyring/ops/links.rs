// Keyring membership and search ops: LINK, UNLINK, MOVE, CLEAR,
// RESTRICT_KEYRING, SEARCH, and the `request_key(2)` search.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::{e, Ctx};
use super::super::perm::{check_perm, visible_for_search, Lookup};
use super::super::store::{Store, TaskIds, STORE};
use super::super::types;
use super::super::uapi::*;

/// `KEYCTL_LINK` core — Linux `keyctl_keyring_link`: the child needs
/// `KEY_NEED_LINK`, the destination ring `KEY_NEED_WRITE`. Special ids on
/// either side are created on demand, mirroring `lookup_user_key(...,
/// KEY_LOOKUP_CREATE)`: pam_keyinit links the user keyring (`-4`) into the
/// session keyring (`-3`), and passing the raw special id `-4` as the child
/// made `link()` return ENOKEY (no key has serial `-4`), so gdm/PAM logged
/// "Failed to link user keyring into session keyring: Required key not
/// available". # C: O(N)
pub fn link_core(c: &Ctx, child: i32, ring: i32) -> i64 {
    let mut g = STORE.lock();
    let ch = match g.resolve(child, &c.t) { Some(x) => x, None => return e(Errno::Enokey) };
    let r  = match g.resolve(ring, &c.t)  { Some(x) => x, None => return e(Errno::Enokey) };
    if let Err(rv) = check_perm(&g, ch, &c.t, KEY_NEED_LINK, Lookup::Full, c.now_ns) { return rv; }
    if let Err(rv) = check_perm(&g, r, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
    match g.link(r, ch) { Ok(()) => 0, Err(err) => e(err) }
}

/// `KEYCTL_UNLINK` core — Linux `keyctl_keyring_unlink`: only the ring needs
/// `KEY_NEED_WRITE` (the key itself is looked up with `KEY_NEED_UNLINK`, which
/// `key_task_permission` passes straight through to the LSM without a perm-bit
/// test — you may always remove a link you can see). ENOENT if the child was
/// not a member, matching `key_unlink`. # C: O(members)
pub fn unlink_core(c: &Ctx, child: i32, ring: i32) -> i64 {
    let mut g = STORE.lock();
    let ch = match g.resolve(child, &c.t) { Some(x) => x, None => return e(Errno::Enokey) };
    let r  = match g.resolve(ring, &c.t)  { Some(x) => x, None => return e(Errno::Enokey) };
    if let Err(rv) = check_perm(&g, r, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
    match g.keys.get_mut(&r) {
        Some(k) if k.is_keyring() => {
            let before = k.members.len();
            k.members.retain(|&m| m != ch);
            if k.members.len() == before { e(Errno::Enoent) } else { 0 }
        }
        Some(_) => e(Errno::Enotdir),
        None => e(Errno::Enokey),
    }
}

/// `KEYCTL_MOVE` core — Linux `keyctl_keyring_move` + `key_move`: the key
/// needs `KEY_NEED_LINK`, the source ring `KEY_NEED_WRITE`, the destination
/// ring `KEY_NEED_WRITE`. `KEYCTL_MOVE_EXCL` makes an existing same-typed,
/// same-described member of the destination EEXIST instead of being replaced.
/// The unlink from the source happens only once the link into the destination
/// has succeeded. # C: O(N)
pub fn move_core(c: &Ctx, id: i32, from_ring: i32, to_ring: i32, flags: u32) -> i64 {
    if flags & !KEYCTL_MOVE_EXCL != 0 { return e(Errno::Einval); }
    let mut g = STORE.lock();
    let key = match g.resolve(id, &c.t) { Some(x) => x, None => return e(Errno::Enokey) };
    let from = match g.resolve(from_ring, &c.t) { Some(x) => x, None => return e(Errno::Enokey) };
    let to = match g.resolve(to_ring, &c.t) { Some(x) => x, None => return e(Errno::Enokey) };
    if let Err(rv) = check_perm(&g, key, &c.t, KEY_NEED_LINK, Lookup::Full, c.now_ns) { return rv; }
    if let Err(rv) = check_perm(&g, from, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
    if let Err(rv) = check_perm(&g, to, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
    if flags & KEYCTL_MOVE_EXCL != 0 && has_matching_member(&g, to, key) { return e(Errno::Eexist); }
    if let Err(err) = g.link(to, key) { return e(err); }
    if let Some(k) = g.keys.get_mut(&from) { k.members.retain(|&m| m != key); }
    0
}

/// Does `ring` already hold a DIFFERENT key with the same type+description as
/// `key` — the collision `KEYCTL_MOVE_EXCL` refuses. # C: O(members)
fn has_matching_member(g: &Store, ring: i32, key: i32) -> bool {
    let (ty, desc) = match g.keys.get(&key) { Some(k) => (k.key_type, &k.description), None => return false };
    g.keys.get(&ring).map(|r| r.members.iter().any(|m| {
        *m != key && g.keys.get(m).map(|k| core::ptr::eq(k.key_type, ty) && &k.description == desc).unwrap_or(false)
    })).unwrap_or(false)
}

/// `KEYCTL_CLEAR` core — Linux `keyctl_keyring_clear`: `KEY_NEED_WRITE` on the
/// resolved keyring, ENOTDIR if it is not one. # C: O(members)
pub fn clear_core(c: &Ctx, ring_id: i32) -> i64 {
    let mut g = STORE.lock();
    let r = match g.resolve(ring_id, &c.t) { Some(r) => r, None => return e(Errno::Enokey) };
    if let Err(rv) = check_perm(&g, r, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
    match g.keys.get_mut(&r) {
        Some(k) if k.is_keyring() => { k.members.clear(); 0 }
        Some(_) => e(Errno::Enotdir),
        None => e(Errno::Enokey),
    }
}

/// `KEYCTL_RESTRICT_KEYRING` core — Linux `keyctl_restrict_keyring` +
/// `keyring_restrict`: `KEY_NEED_SETATTR` on the ring; ENOTDIR if it is not a
/// keyring; EEXIST if a restriction is already installed. A NULL type installs
/// `restrict_link_reject`, refusing every further link with EPERM. A named
/// type is looked up (ENOKEY if unregistered) and then rejected with ENOENT
/// unless it provides a `lookup_restriction` method — no registered type here
/// does, matching a Linux built without `CONFIG_ASYMMETRIC_KEY_TYPE`.
/// # C: O(log N)
pub fn restrict_core(c: &Ctx, ring_id: i32, key_type: Option<&str>) -> i64 {
    let mut g = STORE.lock();
    let r = match g.resolve(ring_id, &c.t) { Some(r) => r, None => return e(Errno::Enokey) };
    if let Err(rv) = check_perm(&g, r, &c.t, KEY_NEED_SETATTR, Lookup::Full, c.now_ns) { return rv; }
    if g.keys.get(&r).map(|k| !k.is_keyring()).unwrap_or(true) { return e(Errno::Enotdir); }
    if let Some(name) = key_type {
        let ty = match types::lookup(name) { Some(t) => t, None => return e(Errno::Enokey) };
        if !ty.restrictable { return e(Errno::Enoent); }
    }
    let k = g.keys.get_mut(&r).expect("keyring presence proved under the same held lock");
    if k.restrict_reject { return e(Errno::Eexist); }
    k.restrict_reject = true;
    0
}

/// `KEYCTL_SEARCH` core — Linux `keyctl_keyring_search`: search starts at the
/// NAMED keyring (which needs `KEY_NEED_SEARCH`) and descends through nested
/// keyrings; on a hit, if `dest` is non-zero the key needs `KEY_NEED_LINK` and
/// is linked into `dest`, which needs `KEY_NEED_WRITE`.
///
/// Searching the whole global key store instead — as a flat scan does — makes
/// any key in any task's keyring findable by serial-free name lookup, which is
/// not a search at all. # C: O(N)
pub fn search_core(c: &Ctx, ring_id: i32, key_type: &str, description: &str, dest: i32) -> i64 {
    let ty = match types::lookup(key_type) { Some(t) => t, None => return e(Errno::Enokey) };
    let mut g = STORE.lock();
    let ring = match g.resolve(ring_id, &c.t) { Some(r) => r, None => return e(Errno::Enokey) };
    if let Err(rv) = check_perm(&g, ring, &c.t, KEY_NEED_SEARCH, Lookup::Full, c.now_ns) { return rv; }
    let dest_ring = if dest == 0 { None } else {
        let d = match g.resolve(dest, &c.t) { Some(d) => d, None => return e(Errno::Enokey) };
        if let Err(rv) = check_perm(&g, d, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
        Some(d)
    };
    let found = match search_from(&g, &[ring], &c.t, ty.name, description, c.now_ns) {
        Some(s) => s, None => return e(Errno::Enokey),
    };
    if let Some(d) = dest_ring {
        if let Err(rv) = check_perm(&g, found, &c.t, KEY_NEED_LINK, Lookup::Full, c.now_ns) { return rv; }
        if let Err(err) = g.link(d, found) { return e(err); }
    }
    found as i64
}

/// `request_key(2)` core — Linux `request_key_and_link` →
/// `search_process_keyrings_rcu` → `search_cred_keyrings_rcu`: the caller's
/// thread, then process, then session (or, absent a session keyring, the
/// user-session) keyring, each descended recursively.
///
/// A miss is ENOKEY. Linux would upcall `/sbin/request-key` when
/// `callout_info` is non-NULL and negate the key if the helper fails, which
/// still surfaces as ENOKEY to the caller; there is no upcall helper here, so
/// ENOKEY is the same answer by the same rule rather than a swallowed error.
/// A hit is linked into `dest` when one is given. # C: O(N)
pub fn request_key_core(c: &Ctx, key_type: &str, description: &str, dest: i32) -> i64 {
    let ty = match types::lookup(key_type) { Some(t) => t, None => return e(Errno::Enokey) };
    let mut g = STORE.lock();
    let dest_ring = if dest == 0 { None } else {
        let d = match g.resolve(dest, &c.t) { Some(d) => d, None => return e(Errno::Enokey) };
        if let Err(rv) = check_perm(&g, d, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
        Some(d)
    };
    let roots = g.cred_roots(&c.t);
    let found = match search_from(&g, &roots, &c.t, ty.name, description, c.now_ns) {
        Some(s) => s, None => return e(Errno::Enokey),
    };
    if let Some(d) = dest_ring {
        if let Err(rv) = check_perm(&g, found, &c.t, KEY_NEED_LINK, Lookup::Full, c.now_ns) { return rv; }
        if let Err(err) = g.link(d, found) { return e(err); }
    }
    found as i64
}

/// Depth-first walk of `roots` and every nested keyring the caller can
/// `KEY_NEED_SEARCH`, returning the first live, visible type+description
/// match. Linux `keyring_search_rcu` with `KEYRING_SEARCH_RECURSE`: an
/// unsearchable nested keyring is skipped rather than failing the whole
/// search, and a revoked/expired/invalidated key never matches. # C: O(N)
fn search_from(g: &Store, roots: &[i32], t: &TaskIds, key_type: &str, description: &str, now_ns: u64)
    -> Option<i32>
{
    let mut visited: Vec<i32> = Vec::new();
    let mut stack: Vec<i32> = roots.iter().rev().copied().collect();
    while let Some(cur) = stack.pop() {
        if visited.contains(&cur) { continue; }
        visited.push(cur);
        let ring = match g.keys.get(&cur) { Some(k) if k.is_keyring() => k, _ => continue };
        if !visible_for_search(g, ring, t, now_ns) { continue; }
        let mut nested: Vec<i32> = Vec::new();
        for &m in &ring.members {
            let k = match g.keys.get(&m) { Some(k) => k, None => continue };
            if k.key_type.name == key_type && k.description == description
                && visible_for_search(g, k, t, now_ns)
            {
                return Some(m);
            }
            if k.is_keyring() { nested.push(m); }
        }
        for m in nested.into_iter().rev() { stack.push(m); }
    }
    None
}

/// Snapshot a keyring's member serials (Linux `KEYCTL_READ` on a keyring, used
/// by tests). `None` if the serial isn't a keyring. # C: O(members)
pub fn members_of(serial: i32) -> Option<Vec<i32>> {
    let g = STORE.lock();
    g.keys.get(&serial).filter(|k| k.is_keyring()).map(|k| k.members.clone())
}
