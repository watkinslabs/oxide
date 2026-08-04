// `KEYCTL_WATCH_KEY` core: what may be watched, by which queue, under which
// watchpoint id.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::watch_queue::{WatchQueue, WATCH_ID_MAX, WATCH_ID_REMOVE};

use super::super::perm::{check_perm, Lookup};
use super::super::store::STORE;
use super::super::uapi::*;
use super::{e, Ctx};

/// This module IS the key-notification capability: the reported
/// `KEYCTL_CAPS1_NOTIFICATIONS` bit is read from here, so the bit and the
/// command cannot disagree.
pub const SUPPORTED: bool = true;

/// The watchpoint-id rule, applied before anything is looked up.
///
/// `-1` removes a watch; `0..=255` adds one under that id, which is stamped
/// into every record the watcher receives so one queue can tell its
/// watchpoints apart. Anything else is EINVAL — the id has only eight bits in
/// the record's `info` field, so a larger one could not be delivered.
/// # C: O(1)
pub fn vet_watch_id(watch_id: i32) -> Result<(), Errno> {
    if watch_id < WATCH_ID_REMOVE || watch_id > WATCH_ID_MAX { return Err(Errno::Einval); }
    Ok(())
}

/// `keyctl_watch_key` — add or remove `queue`'s watch on `serial`.
///
/// VIEW permission is what watching costs: a watcher learns that a key changed
/// and which key it was, which is what VIEW already grants. Removing a watch
/// that was never added is EBADSLT, and adding one a queue already holds is
/// EBUSY — neither is quietly treated as success, because a caller whose watch
/// bookkeeping disagrees with the kernel's has a bug it needs to see.
/// # C: O(log N + watches)
pub fn watch_key_core(c: &Ctx, serial: i32, queue: Arc<WatchQueue>, watch_id: i32) -> i64 {
    if let Err(err) = vet_watch_id(watch_id) { return e(err); }
    let mut g = STORE.lock();
    let real = match g.resolve(serial, &c.t) { Ok(s) => s, Err(err) => return e(err) };
    // The lookup is the CREATE form, so watching a special keyring that does
    // not exist yet brings it into being rather than failing — a caller cannot
    // otherwise watch its own session keyring before it has one.
    if let Err(rv) = check_perm(&g, real, &c.t, KEY_NEED_VIEW, Lookup::Full, c.now_ns) { return rv; }
    let k = g.keys.get_mut(&real).expect("the permission check proved existence under the same held lock");
    let r = if watch_id == WATCH_ID_REMOVE {
        k.watchers.remove(&queue, real as u64)
    } else {
        k.watchers.add(queue, real as u64, watch_id)
    };
    match r { Ok(()) => 0, Err(err) => e(err) }
}

/// Remove every key watch held by a queue whose notification pipe closed.
/// No later key event may be delivered into an unreachable queue.
/// # C: O(watches log N)
pub(crate) fn detach_queue(queue: &Arc<WatchQueue>) {
    let watched = queue.take_watched_keys();
    if watched.is_empty() { return; }
    let mut g = STORE.lock();
    for serial in watched {
        if let Some(key) = g.keys.get_mut(&serial) {
            key.watchers.detach_queue(queue, serial as u64);
        }
    }
}
