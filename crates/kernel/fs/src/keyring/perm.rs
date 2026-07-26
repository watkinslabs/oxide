// Permission enforcement chokepoint for `add_key`/`request_key`/`keyctl`.
// Mirrors Linux `key_task_permission` (`security/keys/permission.c`): a key's
// `perm: u32` packs four 6-bit need-masks — possessor(31:24) / user(23:16) /
// group(15:8) / other(7:0) — each tested against the `KEY_NEED_*` bit the op
// requires. `check_perm` is the ONE call every op site in `keyring.rs` makes
// before touching a key; no op reads `perm` or `uid`/`gid` directly.

use super::{Key, Store, TaskIds};
use syscall::errno::Errno;

// keyctl(2) need bits (uapi/linux/key.h `KEY_NEED_*`).
pub(crate) const KEY_NEED_VIEW:    u32 = 0x01;
pub(crate) const KEY_NEED_READ:    u32 = 0x02;
pub(crate) const KEY_NEED_WRITE:   u32 = 0x04;
pub(crate) const KEY_NEED_SEARCH:  u32 = 0x08;
pub(crate) const KEY_NEED_LINK:    u32 = 0x10;
pub(crate) const KEY_NEED_SETATTR: u32 = 0x20;

const KEY_PERM_BYTE_MASK: u32 = 0x3f;
const KEY_PERM_POS_SHIFT: u32 = 24;
const KEY_PERM_USR_SHIFT: u32 = 16;
const KEY_PERM_GRP_SHIFT: u32 = 8;
const KEY_PERM_OTH_SHIFT: u32 = 0;

/// Linux `key_task_permission`: pick the user/group/other perm byte by uid/gid
/// match (owner takes user byte, else gid match takes group byte, else other),
/// then OR in the possessor byte if `t` possesses `key`. Simplification vs
/// Linux: gid match is a single egid, not the full supplementary-group list
/// `groups_search` walks. # C: O(members) via possession search
fn key_permission(g: &Store, key: &Key, t: TaskIds, need: u32) -> Result<(), Errno> {
    let mut kperm = if key.uid == t.uid { (key.perm >> KEY_PERM_USR_SHIFT) & KEY_PERM_BYTE_MASK }
        else if key.gid == t.gid { (key.perm >> KEY_PERM_GRP_SHIFT) & KEY_PERM_BYTE_MASK }
        else { (key.perm >> KEY_PERM_OTH_SHIFT) & KEY_PERM_BYTE_MASK };
    if is_possessed(g, key.serial, t) { kperm |= (key.perm >> KEY_PERM_POS_SHIFT) & KEY_PERM_BYTE_MASK; }
    if kperm & need == need { Ok(()) } else { Err(Errno::Eacces) }
}

/// Does `t` possess `target` — reachable from one of `t`'s own thread/process/
/// session/user/user-session keyrings, transitively through nested keyrings?
/// Linux `is_key_possessed`. Peeks the per-task maps (no lazy-create side
/// effect); cycle-safe via `visited`. # C: O(members)
fn is_possessed(g: &Store, target: i32, t: TaskIds) -> bool {
    let mut roots: alloc::vec::Vec<i32> = alloc::vec::Vec::new();
    if let Some(&v) = g.thread.get(&t.tid) { roots.push(v); }
    if let Some(&v) = g.process.get(&t.tgid) { roots.push(v); }
    if let Some(&v) = g.session.get(&t.tid) { roots.push(v); }
    if let Some(&v) = g.user.get(&t.uid) { roots.push(v); }
    if let Some(&v) = g.usersess.get(&t.uid) { roots.push(v); }
    if roots.contains(&target) { return true; }
    let mut visited: alloc::vec::Vec<i32> = alloc::vec::Vec::new();
    let mut stack = roots;
    while let Some(cur) = stack.pop() {
        if visited.contains(&cur) { continue; }
        visited.push(cur);
        if let Some(k) = g.keys.get(&cur) {
            if k.members.contains(&target) { return true; }
            for &m in &k.members {
                if g.keys.get(&m).map(|kk| kk.key_type == "keyring").unwrap_or(false) { stack.push(m); }
            }
        }
    }
    false
}

/// THE choke-point: every `add_key`/`request_key`/`keyctl` op site resolves a
/// serial then calls this before reading/mutating the key. `ENOKEY` if the
/// serial names no key; `EACCES` if it exists but `need` is denied. A
/// `KEY_NEED_SETATTR` denial is bypassed when `admin` is set (Linux:
/// `capable(CAP_SYS_ADMIN)` short-circuits `keyctl_setperm_key`/
/// `keyctl_set_timeout` — irrelevant for any other `need` and ignored then).
/// `admin` is threaded in explicitly (not read from `current()` here) so this
/// stays a pure, hosted-testable function; callers resolve the real
/// capability once via `super::cur_is_sys_admin()`. Returns the
/// already-negated errno ready to hand back from a syscall entry point.
/// # C: O(members)
pub(crate) fn check_perm(g: &Store, serial: i32, t: TaskIds, need: u32, admin: bool) -> Result<(), i64> {
    let key = g.keys.get(&serial).ok_or(-(super::ENOKEY as i64))?;
    match key_permission(g, key, t, need) {
        Ok(()) => Ok(()),
        Err(_) if need == KEY_NEED_SETATTR && admin => Ok(()),
        Err(e) => Err(-(e.as_i32() as i64)),
    }
}

/// Search-path visibility check (`KEYCTL_SEARCH`/`request_key`): a key the
/// caller cannot `KEY_NEED_SEARCH` is invisible — no ENOKEY/EACCES split, it
/// just never matches, matching Linux hiding existence from keyring search.
/// # C: O(members)
pub(crate) fn visible_for_search(g: &Store, key: &Key, t: TaskIds) -> bool {
    key_permission(g, key, t, KEY_NEED_SEARCH).is_ok()
}
