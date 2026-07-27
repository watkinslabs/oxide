// Linux `posix_locks_deadlock` (`fs/locks.c:1101`): before a POSIX record
// lock sleeps, walk the "owner X is blocked on owner Y" chain starting at the
// prospective blocker. Reaching the caller's own owner is a cycle, and the
// request is EDEADLK instead of an unbounded sleep.
//
// Linux keeps the edges in `blocked_hash` under `blocked_lock_lock`; the same
// one-critical-section shape is what makes the check sound. Two owners that
// each check-then-insert under separate critical sections could both miss the
// other, so [`block_on`] does BOTH under one acquire.

extern crate alloc;

use alloc::vec::Vec;

use sync::{FileLockBlocked as BlockedClass, Spinlock};

use super::records::RecordOwner;

/// Linux `MAX_DEADLK_ITERATIONS` (`fs/locks.c:1083`): a broken owner graph —
/// Linux names threads sharing one descriptor table — can otherwise walk
/// forever, so the search gives up rather than hangs.
const MAX_DEADLK_ITERATIONS: usize = 10;

#[derive(Copy, Clone)]
struct Edge { waiter: RecordOwner, blocker: RecordOwner }

/// Linux `blocked_hash` guarded by `blocked_lock_lock`. Global, not per-inode:
/// a lock cycle spans inodes.
static BLOCKED: Spinlock<Vec<Edge>, BlockedClass> = Spinlock::new(Vec::new());

/// Linux `what_owner_is_waiting_for`: the lock `owner` is itself parked on.
/// # C: O(N_edges)
fn waiting_for(edges: &[Edge], owner: RecordOwner) -> Option<RecordOwner> {
    edges.iter().find(|e| e.waiter == owner).map(|e| e.blocker)
}

/// Record that `waiter` is about to sleep on `blocker`, unless doing so closes
/// a cycle. Returns `true` for the cycle — the caller's `F_SETLKW` is EDEADLK
/// and NO edge is published. Check and insert share one critical section
/// because Linux holds `blocked_lock_lock` across both.
///
/// OFD callers never reach here: Linux skips detection for `FL_OFDLCK`
/// (`fs/locks.c:1114`) since the owner is a file, not a thread of execution.
/// # C: O(N_edges * MAX_DEADLK_ITERATIONS)
pub fn block_on(waiter: RecordOwner, blocker: RecordOwner) -> bool {
    let mut edges = BLOCKED.lock();
    if waiter == blocker { return true; }
    let mut next = Some(blocker);
    let mut steps = 0;
    while let Some(owner) = next {
        if owner == waiter { return true; }
        steps += 1;
        if steps > MAX_DEADLK_ITERATIONS { break; }
        next = waiting_for(&edges, owner);
    }
    edges.retain(|e| e.waiter != waiter);
    edges.push(Edge { waiter, blocker });
    false
}

/// Linux `locks_delete_block`: the waiter stopped waiting — it acquired, was
/// interrupted, or hit EDEADLK — so its edge must go or a later walk sees a
/// phantom cycle. # C: O(N_edges)
pub fn unblock(waiter: RecordOwner) {
    BLOCKED.lock().retain(|e| e.waiter != waiter);
}
