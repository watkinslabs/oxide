extern crate alloc;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::dentry::Dentry;

use super::alloc::{d_add, d_add_negative};
use super::lifecycle::d_drop;

// ---------------------------------------------------------------------------
// Global rename seqlock (`16§2`, Linux `rename_lock` in `fs/dcache.c`). A SINGLE
// process-wide seqcount the lock-free WHOLE-PATH walker brackets a multi-
// component read in: any `d_move` anywhere advances it, so a path walk that
// raced a rename detects it and retries — the per-dentry `d_seq` only guards the
// ONE renamed name, not the path's other components shifting under a concurrent
// directory rename. EVEN = no rename in flight, ODD = a `d_move` is rehoming.
// ---------------------------------------------------------------------------

static RENAME_LOCK: AtomicU32 = AtomicU32::new(0);

/// Begin a lock-free whole-path read (Linux `read_seqbegin(&rename_lock)`): spin
/// until the global rename seqcount is EVEN (no `d_move` in flight) and return
/// that snapshot. Pair with [`rename_lock_retry`] after reading the path's
/// dentries. # C: O(1) amortized
pub fn rename_lock_read_begin() -> u32 {
    loop {
        let s = RENAME_LOCK.load(Ordering::Acquire);
        if s & 1 == 0 { return s; }
        core::hint::spin_loop();
    }
}

/// Validate a lock-free whole-path read (Linux `read_seqretry(&rename_lock,…)`):
/// `true` ⇒ a `d_move` raced the walk (the global seqcount advanced or is mid-
/// write), so the caller must restart the path walk. # C: O(1)
pub fn rename_lock_retry(start: u32) -> bool {
    core::sync::atomic::fence(Ordering::Acquire);
    RENAME_LOCK.load(Ordering::Acquire) != start
}

/// Open the global rename window (Linux `write_seqlock(&rename_lock)` at the top
/// of `d_move`): advance `RENAME_LOCK` to ODD so every in-flight whole-path
/// reader fails `rename_lock_retry`. MUST be paired with [`rename_unlock`].
/// # C: O(1)
fn rename_lock() { RENAME_LOCK.fetch_add(1, Ordering::Release); }

/// Close the global rename window (Linux `write_sequnlock(&rename_lock)`):
/// advance back to EVEN — a new generation. # C: O(1)
fn rename_unlock() { RENAME_LOCK.fetch_add(1, Ordering::Release); }
/// Rename `old` to `(new_parent, new_name)` (Linux `d_move`). Unhashes
/// `old` from its current parent and rehomes its inode under the new
/// (parent,name) key, so `d_lookup(old_parent, old_name)` misses and
/// `d_lookup(new_parent, new_name)` hits. # C: O(1) expected
pub fn d_move(old: &Arc<Dentry>, new_parent: &Arc<Dentry>, new_name: &str) -> Arc<Dentry> {
    // Linux `__d_move` runs under `write_seqlock(&rename_lock)` (the GLOBAL
    // rename seqcount) AND brackets the rehome in `write_seqcount_begin/end(
    // &dentry->d_seq)` (the per-dentry one). The global lock invalidates any
    // in-flight WHOLE-PATH walk (a sibling component shifting under a directory
    // rename); the per-dentry `d_seq` lets a walker holding `old` detect the move
    // (`read_seqretry`) and re-look-up the new (parent,name). Take the global
    // first, then the per-dentry, mirroring Linux's nesting order.
    rename_lock();
    old.seq_write_begin();
    d_drop(old);
    let moved = match old.inode() {
        Some(inode) => d_add(new_parent, new_name, inode),
        None        => d_add_negative(new_parent, new_name),
    };
    old.seq_write_end();
    rename_unlock();
    moved
}
