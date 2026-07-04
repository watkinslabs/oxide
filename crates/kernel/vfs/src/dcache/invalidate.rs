extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::dentry::Dentry;

use super::lifecycle::d_drop;

/// Invalidate `d` and its whole subtree: unhash every node and detach mounts
/// covering any dentry in the subtree. # C: O(subtree)
pub fn d_invalidate(d: &Arc<Dentry>) {
    // Linux `d_invalidate` opens with `if (d_unhashed(dentry)) return;` — an
    // already-unhashed dentry was invalidated by a prior call (or never entered
    // the hash), so a re-entry must be a no-op: it must NOT re-detach mounts or
    // re-tear-down a subtree that is already disconnected (or one hanging off a
    // dentry that is not the cache's canonical name). This makes `d_invalidate`
    // idempotent and stops a parallel rmdir + revalidate racing two teardowns of
    // the same subtree.
    if d.is_unhashed() { return; }
    let mut stack: Vec<Arc<Dentry>> = alloc::vec![d.clone()];
    while let Some(cur) = stack.pop() {
        for kid in cur.children_snapshot() { stack.push(kid); }
        crate::mount::detach_mounts_on(&cur);
        d_drop(&cur);
    }
}
