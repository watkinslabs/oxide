// `/proc/keys` and `/proc/key-users` rendering.
//
// `/proc/keys` is per-reader, not a global dump: a key the reading task cannot
// `KEY_NEED_VIEW` is silently omitted, exactly as `proc_keys_show` returns 0
// without emitting a line. A file that listed every key in the system would
// hand any user the serial of every other user's keys, which is the one thing
// the permission model exists to prevent — and `keyctl show` would then print
// keys the caller cannot touch.
//
// Counts are derived from the key map rather than cached alongside it. Linux
// caches `nkeys`/`nikeys` in `struct key_user` for speed; a second copy that
// can drift from the map is a split source of truth, and the map is small.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::perm::key_task_permission;
use super::store::{Key, Store, TaskIds, STORE, max_bytes, max_keys};
use super::uapi::*;

const SECS_PER_MIN:  u64 = 60;
const SECS_PER_HOUR: u64 = 60 * 60;
const SECS_PER_DAY:  u64 = 60 * 60 * 24;
const SECS_PER_WEEK: u64 = 60 * 60 * 24 * 7;
const NS_PER_SEC:    u64 = 1_000_000_000;

/// The `%4s` timeout column: `perm` for a key with no expiry, `expd` for one
/// already past it, else the remaining time in the largest unit that fits.
/// # C: O(1)
fn timeout_field(k: &Key, now_ns: u64) -> String {
    if k.expiry_ns == 0 { return String::from("perm"); }
    if now_ns >= k.expiry_ns { return String::from("expd"); }
    let t = (k.expiry_ns - now_ns) / NS_PER_SEC;
    if t < SECS_PER_MIN { format!("{t}s") }
    else if t < SECS_PER_HOUR { format!("{}m", t / SECS_PER_MIN) }
    else if t < SECS_PER_DAY { format!("{}h", t / SECS_PER_HOUR) }
    else if t < SECS_PER_WEEK { format!("{}d", t / SECS_PER_DAY) }
    else { format!("{}w", t / SECS_PER_WEEK) }
}

/// The seven flag characters: instantiated, revoked, dead, in-quota,
/// under-construction, negative, invalidated. A cleared flag prints `-`.
/// # C: O(1)
fn flag_field(k: &Key) -> String {
    let f = |on: bool, c: char| if on { c } else { '-' };
    let mut s = String::new();
    s.push(f(k.read_state() != KEY_IS_UNINSTANTIATED, 'I'));
    s.push(f(k.revoked, 'R'));
    // `KEY_FLAG_DEAD` marks a key whose type was unregistered. Types here are
    // a static table that is never torn down, so no key is ever dead.
    s.push('-');
    s.push(f(k.in_quota, 'Q'));
    s.push(f(k.under_construction, 'U'));
    s.push(f(k.is_negative(), 'N'));
    s.push(f(k.invalidated, 'i'));
    s
}

/// The type's `describe` method — the tail of the line after the type name.
/// The keyring type reports its member count (or `empty`), the user-defined
/// types their payload length; both suppress the suffix while the key is not
/// positively instantiated, since there is nothing to count yet. # C: O(1)
fn describe_field(k: &Key) -> String {
    let positive = k.read_state() == KEY_IS_POSITIVE;
    let desc = if k.description.is_empty() { "[anon]" } else { k.description.as_str() };
    if !positive { return String::from(desc); }
    if k.is_keyring() {
        if k.members.is_empty() { format!("{desc}: empty") } else { format!("{desc}: {}", k.members.len()) }
    } else {
        format!("{desc}: {}", k.payload.len())
    }
}

/// How many references the key holds: one per keyring linking it, plus the
/// store's own. Linux prints a true refcount; every reference it counts that is
/// not a link is transient (a live lookup), so the link count is what a reader
/// between syscalls sees. # C: O(N)
fn usage_field(g: &Store, serial: i32) -> usize {
    g.keys.values().filter(|k| k.is_keyring() && k.members.contains(&serial)).count() + 1
}

/// `/proc/keys` for `t`. Every line is a key `t` may VIEW; possession is
/// computed the same way every other op computes it, so a key reachable only
/// through a keyring `t` possesses shows up with its possessor bits applied.
/// # C: O(N * members)
pub fn proc_keys(t: &TaskIds, now_ns: u64) -> String {
    let g = STORE.lock();
    let mut out = String::new();
    for k in g.keys.values() {
        if key_task_permission(&g, k, t, KEY_NEED_VIEW).is_err() { continue; }
        out.push_str(&format!("{:08x} {} {:5} {:>4} {:08x} {:5} {:5} {:<9.9} {}\n",
            k.serial, flag_field(k), usage_field(&g, k.serial), timeout_field(k, now_ns),
            k.perm, k.uid as i32, k.gid as i32, k.key_type.name, describe_field(k)));
    }
    out
}

/// `/proc/key-users`: one line per uid holding a charge —
/// `uid: usage nkeys/nikeys qnkeys/maxkeys qnbytes/maxbytes`. `nkeys` counts
/// every key the uid owns, `nikeys` only those actually instantiated, and the
/// `qn*` pair is the quota charge against that uid's ceiling. # C: O(N)
pub fn proc_key_users() -> String {
    let g = STORE.lock();
    let mut out = String::new();
    let mut uids: Vec<u32> = g.quota.keys().copied().collect();
    uids.sort_unstable();
    for uid in uids {
        let q = g.quota.get(&uid).copied().unwrap_or_default();
        let owned: Vec<&Key> = g.keys.values().filter(|k| k.uid == uid).collect();
        let nkeys = owned.len();
        let nikeys = owned.iter().filter(|k| k.read_state() != KEY_IS_UNINSTANTIATED).count();
        // Linux's `key_user` refcount is one per cred referencing the uid's
        // record; between syscalls that is one per key it still owns.
        out.push_str(&format!("{:5}: {:5} {}/{} {}/{} {}/{}\n",
            uid, nkeys, nkeys, nikeys, q.nkeys, max_keys(uid), q.nbytes, max_bytes(uid)));
    }
    out
}

#[cfg(test)] mod tests;
