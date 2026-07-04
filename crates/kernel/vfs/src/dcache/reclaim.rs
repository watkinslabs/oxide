extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Dentry as DentryClass, Spinlock};

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::superblock::SuperBlock;

use super::lifecycle::{d_drop, dentry_kill};

// ---------------------------------------------------------------------------
// dcache LRU (`16§98`). `dput`-to-zero pushes a `Weak` here; `shrink_dcache`
// evicts unused (d_count==0, unreferenced) entries — primarily the otherwise
// unbounded unused negatives.
// ---------------------------------------------------------------------------

static DENTRY_LRU: Spinlock<VecDeque<Weak<Dentry>>, DentryClass> = Spinlock::new(VecDeque::new());

pub(super) fn lru_add(d: &Arc<Dentry>) {
    if d.is_on_lru() { return; }
    d.set_on_lru(true);
    DENTRY_LRU.lock().push_back(Arc::downgrade(d));
}

/// Approximate count of dentries currently parked on the production LRU —
/// the shrinker `count_objects` hook (Linux `super_block::s_dentry_lru` count
/// reported to `do_shrink_slab`). The number a memory-pressure / periodic
/// reclaim caller scales its [`shrink_dcache_memory`] target against. O(1):
/// reports the raw deque length (includes not-yet-pruned dead `Weak`s, an upper
/// bound Linux's `list_lru_count` shares). # C: O(1)
pub fn dcache_lru_count() -> usize { DENTRY_LRU.lock().len() }

/// Memory-pressure / periodic shrinker ENTRY POINT for the dentry cache (Linux
/// `shrinker::scan_objects` → `prune_dcache_sb`, driven by `do_shrink_slab` under
/// reclaim). The production caller lives in mm/sched (cross-lane): a reclaim /
/// periodic-vmpressure path invokes this with the number of unused dentries it
/// wants returned to the slab allocator. Drains the SAME production-populated
/// [`DENTRY_LRU`] that every `File::drop` → `dput`-to-zero feeds (D10), via the
/// two-hand-clock [`shrink_dcache`]; referenced/in-use entries survive, unused
/// negatives + idle positives are evicted. Returns the count freed. # C: O(scanned)
pub fn shrink_dcache_memory(target: usize) -> usize { shrink_dcache(target) }

/// Reclaim up to `target` unused dentries from the LRU head. Referenced
/// entries rotate once; evictable entries are killed. # C: O(scanned)
pub fn shrink_dcache(target: usize) -> usize {
    let mut freed = 0;
    let mut scan = DENTRY_LRU.lock().len();
    while freed < target && scan > 0 {
        scan -= 1;
        let w = match DENTRY_LRU.lock().pop_front() { Some(w) => w, None => break };
        let d = match w.upgrade() { Some(d) => d, None => continue }; // already freed
        if d.d_count() > 0 { d.set_on_lru(false); continue; }         // back in use
        if d.is_referenced() {
            d.set_referenced(false);
            DENTRY_LRU.lock().push_back(Arc::downgrade(&d)); // rotate
            continue;
        }
        d.set_on_lru(false);
        dentry_kill(&d);
        freed += 1;
    }
    freed
}

/// Evict EVERY unused dentry belonging to `sb` from the LRU (Linux
/// `shrink_dcache_sb`, `fs/dcache.c`) — the per-superblock aggressive prune
/// driven by remount (`reconfigure_super`) and per-sb `drop_caches`. Unlike the
/// periodic [`shrink_dcache`] two-hand clock, this IGNORES the `D_REFERENCED`
/// bit: a matching UNUSED (`d_count == 0`) dentry is `d_drop`-ed in one pass
/// (Linux loops `list_lru_walk(&sb->s_dentry_lru, …)` until that sb's LRU
/// drains). In-use dentries (`d_count > 0`) and dentries of OTHER superblocks
/// are kept on the LRU untouched — sb identity is `Arc::ptr_eq` on `d_sb()`, so
/// an `sb`-less anon dentry never matches. Drains the LRU into a snapshot first
/// so the in-loop `d_drop` (which takes the hash-bucket + parent `d_subdirs`
/// locks) never reenters the LRU lock. Returns the count evicted. # C: O(LRU)
pub fn shrink_dcache_sb(sb: &Arc<SuperBlock>) -> usize {
    let snapshot: Vec<Weak<Dentry>> = DENTRY_LRU.lock().drain(..).collect();
    let mut freed = 0;
    for w in snapshot {
        let d = match w.upgrade() { Some(d) => d, None => continue }; // already freed
        let ours = d.d_sb().map(|s| Arc::ptr_eq(&s, sb)).unwrap_or(false);
        if ours && d.d_count() == 0 {
            d.set_on_lru(false);
            dentry_kill(&d);
            freed += 1;
        } else {
            DENTRY_LRU.lock().push_back(Arc::downgrade(&d)); // not ours / in use
        }
    }
    freed
}

/// Prune the UNUSED dentries in the subtree under `parent` (Linux
/// `shrink_dcache_parent`, `fs/dcache.c`) — the per-subtree counterpart of the
/// global `shrink_dcache`, used on remount / umount of a subtree / before a
/// populated-dir rmdir to reclaim its cached children. `parent` itself is never
/// pruned. A descendant is prunable only when it is UNUSED (`d_count == 0`) AND
/// has no surviving child, so an in-use leaf pins the whole path of ancestors up
/// to `parent` (Linux: the `dget` on each path component holds the chain); the
/// unused siblings/leaves around it are still reclaimed. Each prunable dentry is
/// `d_drop`-ed (unhash + drop inode alias + forget from its parent's
/// `d_subdirs`). Bounds stack depth via an explicit BFS collect; processes
/// deepest-first so a parent observes its children's survival. Returns the count
/// pruned. # C: O(subtree)
pub fn shrink_dcache_parent(parent: &Arc<Dentry>) -> usize {
    // BFS-collect the subtree (EXCLUDING `parent`); `order` is shallow→deep.
    let mut order: Vec<Arc<Dentry>> = parent.children_snapshot();
    let mut i = 0;
    while i < order.len() {
        for kid in order[i].children_snapshot() { order.push(kid); }
        i += 1;
    }
    // Deepest-first: by the time a node is visited every descendant has been
    // processed, so a `d_drop`-ed child is already gone from this node's
    // `d_subdirs` — an empty child set means "no survivor", the prune gate.
    let mut freed = 0;
    for d in order.iter().rev() {
        if d.d_count() == 0 && d.children_snapshot().is_empty() {
            dentry_kill(d);
            freed += 1;
        }
    }
    freed
}

/// FORCE-detach the ENTIRE dentry tree of `sb` on unmount (Linux
/// `shrink_dcache_for_umount` → `do_one_tree`, `fs/dcache.c`), run from
/// `generic_shutdown_super` once the mount is going away. Unlike the gentle
/// [`shrink_dcache_sb`] (which evicts only UNUSED `d_count == 0` dentries and
/// leaves in-use ones on the LRU), this tears down EVERY dentry rooted at
/// `sb->s_root` REGARDLESS of `d_count`: an in-use dentry (a holder still owns
/// an `Arc`) is `mark_dead`-stamped + `d_drop`-ed (unhashed, dropped from its
/// inode alias list, forgotten from its parent's `d_subdirs`) so it can never
/// be looked up again — its memory frees when the last holder's `dput` releases
/// the `Arc`. The whole subtree (root included) is detached deepest-first so a
/// parent is forgotten only after its children, and a node is stamped dead
/// before unhashing so a racing `d_lookup` mid-umount fails the not-dead gate
/// instead of resurrecting a doomed dentry (Linux marks under `d_lock` ahead of
/// `__d_drop`). An `s_root`-less sb (never fully mounted, or already torn down)
/// detaches nothing. Returns the count detached (an in-use remainder is the
/// "Busy inodes after unmount" leak the caller may WARN on). The strong `s_root`
/// owning ref is released separately by `put_super`. # C: O(tree)
pub fn shrink_dcache_for_umount(sb: &Arc<SuperBlock>) -> usize {
    let root = match sb.s_root() { Some(r) => r, None => return 0 };
    // BFS-collect the whole tree INCLUDING the root; `order` is shallow→deep.
    let mut order: Vec<Arc<Dentry>> = alloc::vec![root];
    let mut i = 0;
    while i < order.len() {
        for kid in order[i].children_snapshot() { order.push(kid); }
        i += 1;
    }
    // Deepest-first: detach each node (stamp dead, then unhash + forget from
    // parent) regardless of `d_count`, so an in-use child is gone from its
    // parent's `d_subdirs` before the parent itself is processed.
    for d in order.iter().rev() {
        d.mark_dead();
        d_drop(d);
    }
    order.len()
}

/// Prune every UNUSED dentry alias of `inode` (Linux `d_prune_aliases`,
/// `fs/dcache.c`) — drop the cached dentries naming an inode that an FS is
/// forcing out of cache (NFS post-`silly-rename` / `nfs_zap_caches`, FUSE
/// `fuse_reverse_inval_entry`, generic invalidation) WITHOUT requiring the
/// inode itself to be freed. An alias is prunable only when UNUSED
/// (`d_count == 0`; Linux skips `d_lockref.count != 0`); each is `d_drop`-ed —
/// unhash + forget from its parent's `d_subdirs` + remove from this inode's
/// `i_dentry` alias list — releasing the last `Arc` so the dentry frees. In-use
/// aliases (`d_count > 0`) are pinned by their holders and left intact, which
/// for a hard-linked file leaves only the open/CWD-held names cached. Iterates
/// a snapshot of `i_aliases` so the in-loop `i_drop_alias` mutation that
/// `d_drop` performs is race-free. An `i_sb()`-less inode tracks no aliases —
/// nothing to prune. Returns the count pruned. # C: O(N_aliases)
pub fn d_prune_aliases(inode: &InodeRef) -> usize {
    let sb = match inode.i_sb() { Some(sb) => sb, None => return 0 };
    let mut freed = 0;
    for alias in sb.i_aliases(inode.ino()) {
        if alias.d_count() == 0 { dentry_kill(&alias); freed += 1; }
    }
    freed
}
