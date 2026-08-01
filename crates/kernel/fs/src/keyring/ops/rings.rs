// Keyring lifecycle ops: JOIN_SESSION_KEYRING, GET_KEYRING_ID,
// GET_PERSISTENT, SET_REQKEY_KEYRING, SESSION_TO_PARENT, and the fork-time
// session inheritance Linux does in `copy_creds`.

use super::{e, Ctx};
use super::super::perm::{check_perm, check_perm_with, Lookup, Possess};
use super::super::store::{persistent_expiry, Quota, Store, TaskIds, STORE};
use super::super::types;
use super::super::uapi::*;
use syscall::errno::Errno;

/// `keyctl_join_session_keyring`'s name admission, applied before the keyring
/// is looked up or created. A leading `.` is EPERM: dot-prefixed names are the
/// kernel's own (`.persistent_register`, `.request_key_auth`), and letting a
/// caller join one by name would place it inside a keyring holding other
/// tasks' credentials. # C: O(1)
pub fn vet_session_name(name: Option<&str>) -> Result<(), Errno> {
    match name {
        Some(n) if n.starts_with('.') => Err(Errno::Eperm),
        _ => Ok(()),
    }
}

/// `KEYCTL_JOIN_SESSION_KEYRING`: `name==None` → mint a FRESH anonymous
/// session keyring; `Some(n)` → join the existing named session keyring or
/// mint it. Linux `keyctl_join_session_keyring` gives a named ring
/// `KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ | KEY_USR_LINK` and an anonymous
/// one the plain session perm; joining an existing named ring requires
/// `KEY_NEED_SEARCH` on it, so one user cannot hijack another's named session
/// keyring. Returns its serial. # C: O(N)
pub fn join_session(c: &Ctx, name: Option<&str>) -> i64 {
    let mut g = STORE.lock();
    // A task that already has a session keyring is charged IN_QUOTA for the
    // replacement (it can EDQUOT); the very first one is charged OVERRUN so a
    // task can always be given credentials.
    let mode = if g.session.contains_key(&c.t.tid) { Quota::InQuota } else { Quota::Overrun };
    let serial = match name {
        None => match g.new_keyring("_ses", c.t.fsuid, c.t.fsgid, SESSION_KEYRING_PERM, mode) {
            Ok(s) => s, Err(err) => return e(err),
        },
        Some(n) => {
            let found = g.keys.values()
                .find(|k| k.is_keyring() && k.description == n && !k.revoked && !k.invalidated)
                .map(|k| k.serial);
            match found {
                Some(s) => {
                    // `find_keyring_by_name` checks Search WITHOUT possession,
                    // so reaching the keyring through your own session does not
                    // let you back into it — only its user/group/other bytes
                    // count. A candidate that fails is SKIPPED, and a keyring of
                    // that name is created instead of the call being denied.
                    if check_perm_with(&g, s, &c.t, KEY_NEED_SEARCH, c.now_ns, Possess::No).is_err() {
                        return match g.new_keyring(n, c.t.fsuid, c.t.fsgid,
                            NAMED_SESSION_KEYRING_PERM, Quota::InQuota)
                        {
                            Ok(fresh) => { g.session.insert(c.t.tid, fresh); g.collect(); fresh as i64 }
                            Err(err) => e(err),
                        };
                    }
                    // Joining the keyring the caller is ALREADY in is a no-op
                    // that answers 0 rather than the serial — `pam_keyinit`
                    // re-runs on every session in a login and relies on the
                    // idempotent call not looking like a fresh join.
                    if g.session.get(&c.t.tid) == Some(&s) { return 0; }
                    s
                }
                // A named session keyring is always charged IN_QUOTA.
                None => match g.new_keyring(n, c.t.fsuid, c.t.fsgid, NAMED_SESSION_KEYRING_PERM, Quota::InQuota) {
                    Ok(s) => s, Err(err) => return e(err),
                },
            }
        }
    };
    g.session.insert(c.t.tid, serial);
    // The session keyring the task just left may now be unreferenced.
    g.collect();
    serial as i64
}

/// `KEYCTL_GET_KEYRING_ID(id, create)` core: resolve a special/real id.
/// `create==false` on a not-yet-present keyring → ENOKEY. A concrete serial
/// still has to pass `KEY_NEED_SEARCH` (Linux `lookup_user_key(id, …,
/// KEY_NEED_SEARCH)`), so this is not an oracle for other tasks' serials.
/// # C: O(N)
pub fn get_keyring_id(c: &Ctx, id: i32, create: bool) -> i64 {
    let mut g = STORE.lock();
    // Without `create`, a special keyring that does not exist yet is ENOKEY
    // rather than being minted. This only covers the ids that name a real
    // keyring; every other negative id keeps whatever the resolver says about
    // it (EINVAL for an undefined id, ENOKEY for the authorisation-key ids),
    // so an undefined id is not silently reported as a missing keyring.
    if !create {
        let t = &c.t;
        let present = match id {
            KEY_SPEC_THREAD_KEYRING       => Some(g.thread.contains_key(&t.tid)),
            KEY_SPEC_PROCESS_KEYRING      => Some(g.process.contains_key(&t.tgid)),
            KEY_SPEC_SESSION_KEYRING      => Some(g.session.contains_key(&t.tid)),
            KEY_SPEC_USER_KEYRING         => Some(g.user.contains_key(&t.fsuid)),
            KEY_SPEC_USER_SESSION_KEYRING => Some(g.usersess.contains_key(&t.fsuid)),
            _ => None,
        };
        if present == Some(false) { return e(Errno::Enokey); }
    }
    let serial = match g.resolve(id, &c.t) { Ok(s) => s, Err(err) => return e(err) };
    if id >= 0 {
        if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_SEARCH, Lookup::Full, c.now_ns) {
            return rv;
        }
    }
    serial as i64
}

/// `KEYCTL_GET_PERSISTENT` core — Linux `keyctl_get_persistent` +
/// `key_get_persistent`.
///
/// The persistent keyring is NOT the user keyring. It is a separate
/// `_persistent.<uid>` ring held in a kernel-wide `.persistent_register`, and
/// the difference is its whole purpose: the user keyring dies with the user's
/// last session, while the persistent one survives logout so a cron job or a
/// systemd unit can still find the credentials a login left behind. Aliasing
/// the two hands a caller a keyring with the wrong lifetime and the wrong
/// owner.
///
/// Order:
///   1. `uid == -1` means the caller's own, with no capability check; a
///      different uid needs `CAP_SETUID` — not `CAP_SYS_ADMIN`, because reading
///      another user's cached credentials is an identity operation;
///   2. a destination is MANDATORY (`destid == 0` is ENOKEY out of the id
///      resolver) and must be a keyring (ENOTDIR): the ring is useless to the
///      caller unless it is linked somewhere reachable;
///   3. the ring needs `KEY_NEED_LINK`, then it is linked and its expiry is
///      REFRESHED. That refresh is the "persistent" contract — the ring lives
///      three days from its last use, not three days from creation.
/// # C: O(N)
pub fn get_persistent(c: &Ctx, uid: i32, destid: i32) -> i64 {
    const SELF_UID: i32 = -1;
    let target = if uid == SELF_UID { c.t.fsuid } else {
        if uid < 0 { return e(Errno::Einval); }
        uid as u32
    };
    if target != c.t.fsuid && !c.set_uid { return e(Errno::Eperm); }
    let mut g = STORE.lock();
    let dest = match g.resolve(destid, &c.t) { Ok(d) => d, Err(err) => return e(err) };
    if let Err(rv) = check_perm(&g, dest, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
    if g.keys.get(&dest).map(|k| !k.is_keyring()).unwrap_or(true) { return e(Errno::Enotdir); }
    let ring = match persistent_keyring(&mut g, target, &c.t) { Ok(r) => r, Err(err) => return e(err) };
    // The persistent keyring is reachable from nothing the caller owns, so its
    // LINK check is made as its possessor — being handed the ring is what
    // possession means here.
    if let Err(rv) = check_perm_with(&g, ring, &c.t, KEY_NEED_LINK, c.now_ns, Possess::Yes) { return rv; }
    if let Err(err) = g.link(dest, ring) { return e(err); }
    let k = g.keys.get_mut(&ring).expect("presence proved under the same held lock");
    k.expiry_ns = c.now_ns.saturating_add(persistent_expiry().saturating_mul(NS_PER_SEC));
    ring as i64
}

const NS_PER_SEC: u64 = 1_000_000_000;

/// `key_get_persistent`: find or create `_persistent.<uid>` inside the
/// `.persistent_register`, creating the register itself on first use. Both are
/// allocated outside the quota — a user must not be unable to reach its own
/// persistent credentials because it is at its key limit. # C: O(N)
fn persistent_keyring(g: &mut Store, uid: u32, t: &TaskIds) -> Result<i32, Errno> {
    let register = match g.persistent_register {
        Some(r) => r,
        None => {
            // Owned by root, and dot-prefixed so no `KEYCTL_JOIN_SESSION_KEYRING`
            // can name it.
            let r = g.mint_not_in_quota(types::keyring_type(), PERSISTENT_REGISTER_NAME,
                ROOT_UID, ROOT_UID, PERSISTENT_KEYRING_PERM)?;
            g.persistent_register = Some(r);
            r
        }
    };
    let name = alloc::format!("{PERSISTENT_PREFIX}{uid}");
    let existing = g.keys.get(&register).map(|r| r.members.clone()).unwrap_or_default().into_iter()
        .find(|s| g.keys.get(s).map(|k| k.is_keyring() && k.description == name).unwrap_or(false));
    if let Some(s) = existing { return Ok(s); }
    let _ = t;
    let ring = g.mint_not_in_quota(types::keyring_type(), &name, uid, GID_INVALID,
        PERSISTENT_KEYRING_PERM)?;
    g.link(register, ring)?;
    Ok(ring)
}

/// `KEYCTL_SET_REQKEY_KEYRING` core — Linux `keyctl_set_reqkey_keyring`:
/// returns the PREVIOUS setting, installs the thread/process keyring when the
/// new setting names one, and rejects `KEY_REQKEY_DEFL_GROUP_KEYRING` (group
/// keyrings were never implemented) along with any out-of-range value.
/// `KEY_REQKEY_DEFL_NO_CHANGE` reads the setting without touching it.
/// Returning a bare 0 here — as an accept-and-ignore stub does — tells
/// `request-key` its setting took effect when it did not. # C: O(log N)
pub fn set_reqkey_keyring(c: &Ctx, reqkey_defl: i32) -> i64 {
    let mut g = STORE.lock();
    let old = *g.jit.get(&c.t.tid).unwrap_or(&KEY_REQKEY_DEFL_THREAD_KEYRING);
    if reqkey_defl == KEY_REQKEY_DEFL_NO_CHANGE { return old as i64; }
    match reqkey_defl {
        KEY_REQKEY_DEFL_THREAD_KEYRING  => { let _ = g.resolve(KEY_SPEC_THREAD_KEYRING, &c.t); }
        KEY_REQKEY_DEFL_PROCESS_KEYRING => { let _ = g.resolve(KEY_SPEC_PROCESS_KEYRING, &c.t); }
        KEY_REQKEY_DEFL_DEFAULT
        | KEY_REQKEY_DEFL_SESSION_KEYRING
        | KEY_REQKEY_DEFL_USER_KEYRING
        | KEY_REQKEY_DEFL_USER_SESSION_KEYRING
        | KEY_REQKEY_DEFL_REQUESTOR_KEYRING => {}
        _ => return e(Errno::Einval),
    }
    g.jit.insert(c.t.tid, reqkey_defl);
    old as i64
}

/// `KEYCTL_SESSION_TO_PARENT` core — Linux `keyctl_session_to_parent`. The
/// caller needs `KEY_NEED_LINK` on its own session keyring; the parent must
/// not be init or a kernel thread, must be single-threaded, must share the
/// caller's effective ownership, and both session keyrings must belong to the
/// caller's uid. Identical session keyrings are a no-op success; anything else
/// that fails those tests is EPERM. `parent` is `None` when the caller has no
/// eligible parent. # C: O(N)
pub fn session_to_parent(c: &Ctx, parent: Option<ParentInfo>) -> i64 {
    let mut g = STORE.lock();
    let mine = match g.resolve(KEY_SPEC_SESSION_KEYRING, &c.t) { Ok(s) => s, Err(err) => return e(err) };
    if let Err(rv) = check_perm(&g, mine, &c.t, KEY_NEED_LINK, Lookup::Full, c.now_ns) { return rv; }
    let p = match parent { Some(p) => p, None => return e(Errno::Eperm) };
    if p.vpid <= 1 || !p.has_mm || !p.single_threaded { return e(Errno::Eperm); }
    if p.uid != c.t.fsuid || p.euid != c.t.fsuid || p.suid != c.t.fsuid { return e(Errno::Eperm); }
    if p.gid != c.t.fsgid || p.egid != c.t.fsgid || p.sgid != c.t.fsgid { return e(Errno::Eperm); }
    if g.session.get(&p.tid) == Some(&mine) { return 0; }
    if let Some(&ps) = g.session.get(&p.tid) {
        if g.keys.get(&ps).map(|k| k.uid != c.t.fsuid).unwrap_or(false) { return e(Errno::Eperm); }
    }
    if g.keys.get(&mine).map(|k| k.uid != c.t.fsuid).unwrap_or(true) { return e(Errno::Eperm); }
    g.session.insert(p.tid, mine);
    0
}

/// The parent-task facts `session_to_parent` needs, snapshotted by the
/// syscall entry so the core stays free of `sched::current()`.
#[derive(Copy, Clone)]
pub struct ParentInfo {
    pub tid: u32,
    pub vpid: u32,
    pub has_mm: bool,
    pub single_threaded: bool,
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
}
