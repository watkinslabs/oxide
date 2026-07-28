// Keyring lifecycle ops: JOIN_SESSION_KEYRING, GET_KEYRING_ID,
// GET_PERSISTENT, SET_REQKEY_KEYRING, SESSION_TO_PARENT, and the fork-time
// session inheritance Linux does in `copy_creds`.

use super::{e, Ctx};
use super::super::perm::{check_perm, Lookup};
use super::super::store::STORE;
use super::super::uapi::*;
use syscall::errno::Errno;

/// `KEYCTL_JOIN_SESSION_KEYRING`: `name==None` → mint a FRESH anonymous
/// session keyring; `Some(n)` → join the existing named session keyring or
/// mint it. Linux `keyctl_join_session_keyring` gives a named ring
/// `KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ | KEY_USR_LINK` and an anonymous
/// one the plain session perm; joining an existing named ring requires
/// `KEY_NEED_SEARCH` on it, so one user cannot hijack another's named session
/// keyring. Returns its serial. # C: O(N)
pub fn join_session(c: &Ctx, name: Option<&str>) -> i64 {
    let mut g = STORE.lock();
    let serial = match name {
        None => g.new_keyring("_ses", c.t.fsuid, c.t.fsgid, SESSION_KEYRING_PERM),
        Some(n) => {
            let found = g.keys.values()
                .find(|k| k.is_keyring() && k.description == n && !k.revoked && !k.invalidated)
                .map(|k| k.serial);
            match found {
                Some(s) => {
                    if let Err(rv) = check_perm(&g, s, &c.t, KEY_NEED_SEARCH, Lookup::Full, c.now_ns) {
                        return rv;
                    }
                    s
                }
                None => g.new_keyring(n, c.t.fsuid, c.t.fsgid, NAMED_SESSION_KEYRING_PERM),
            }
        }
    };
    g.session.insert(c.t.tid, serial);
    serial as i64
}

/// `KEYCTL_GET_KEYRING_ID(id, create)` core: resolve a special/real id.
/// `create==false` on a not-yet-present keyring → ENOKEY. A concrete serial
/// still has to pass `KEY_NEED_SEARCH` (Linux `lookup_user_key(id, …,
/// KEY_NEED_SEARCH)`), so this is not an oracle for other tasks' serials.
/// # C: O(N)
pub fn get_keyring_id(c: &Ctx, id: i32, create: bool) -> i64 {
    let mut g = STORE.lock();
    if id < 0 && !create {
        let t = &c.t;
        let present = match id {
            KEY_SPEC_THREAD_KEYRING       => g.thread.contains_key(&t.tid),
            KEY_SPEC_PROCESS_KEYRING      => g.process.contains_key(&t.tgid),
            KEY_SPEC_SESSION_KEYRING      => g.session.contains_key(&t.tid),
            KEY_SPEC_USER_KEYRING         => g.user.contains_key(&t.fsuid),
            KEY_SPEC_USER_SESSION_KEYRING => g.usersess.contains_key(&t.fsuid),
            _ => false,
        };
        if !present { return e(Errno::Enokey); }
    }
    let serial = match g.resolve(id, &c.t) { Some(s) => s, None => return e(Errno::Enokey) };
    if id >= 0 {
        if let Err(rv) = check_perm(&g, serial, &c.t, KEY_NEED_SEARCH, Lookup::Full, c.now_ns) {
            return rv;
        }
    }
    serial as i64
}

/// `KEYCTL_GET_PERSISTENT` core: resolve (lazily create) the caller's
/// persistent keyring. Linux `keyctl_get_persistent` refuses a uid other than
/// the caller's own unless the caller holds `CAP_SETUID`
/// (`security/keys/persistent.c`), and links the ring into `destid`.
/// `uid == -1` means "my own". # C: O(N)
pub fn get_persistent(c: &Ctx, uid: i32, destid: i32) -> i64 {
    if uid != -1 && uid as u32 != c.t.fsuid && !c.sys_admin { return e(Errno::Eperm); }
    let mut g = STORE.lock();
    let ring = match g.resolve(KEY_SPEC_USER_KEYRING, &c.t) { Some(s) => s, None => return e(Errno::Enokey) };
    if destid != 0 {
        let dest = match g.resolve(destid, &c.t) { Some(d) => d, None => return e(Errno::Enokey) };
        if let Err(rv) = check_perm(&g, dest, &c.t, KEY_NEED_WRITE, Lookup::Full, c.now_ns) { return rv; }
        if let Err(err) = g.link(dest, ring) { return e(err); }
    }
    ring as i64
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
        KEY_REQKEY_DEFL_THREAD_KEYRING  => { g.resolve(KEY_SPEC_THREAD_KEYRING, &c.t); }
        KEY_REQKEY_DEFL_PROCESS_KEYRING => { g.resolve(KEY_SPEC_PROCESS_KEYRING, &c.t); }
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
    let mine = match g.resolve(KEY_SPEC_SESSION_KEYRING, &c.t) { Some(s) => s, None => return e(Errno::Enokey) };
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

/// Copy the parent's session keyring serial to a forked child (Linux shares
/// the session keyring across fork via `copy_creds`). # C: O(log N)
pub fn inherit_session(parent_tid: u32, child_tid: u32) {
    let mut g = STORE.lock();
    if let Some(&s) = g.session.get(&parent_tid) { g.session.insert(child_tid, s); }
}
