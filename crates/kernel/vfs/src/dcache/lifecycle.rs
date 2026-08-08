extern crate alloc;
use alloc::sync::Arc;

use crate::dentry::Dentry;

use super::hash::DENTRY_HASHTABLE;
use super::reclaim::{d_prune_aliases, lru_add};

/// Take a reference (Linux `dget`): bump the VFS `d_count` lockref and clone
/// the `Arc`. # C: O(1)
pub fn dget(d: &Arc<Dentry>) -> Arc<Dentry> { d.inc_count(); Arc::clone(d) }

/// Drop a reference (Linux `dput`). Decrements `d_count`; at zero the dentry
/// is unused — `d_op->d_delete` may request immediate eviction (`d_drop`),
/// otherwise it joins the LRU for the shrinker. The `Arc` strong count, not
/// `d_count`, is the actual free trigger. # C: O(1)
pub fn dput(d: Arc<Dentry>) {
    if d.dec_count() == 0 {
        // A superblock ROOT is owned by its `sb` (via `s_root`) for the whole
        // mount lifetime and is reclaimed ONLY by `shrink_dcache_for_umount` at
        // umount — never by a transient `dput`-to-0 (Linux keeps the root's
        // lockref ≥1 through the `sb`'s ref, so it never reaches the kill path).
        // Killing it here would `mark_dead` a dentry the mount tree still points
        // at (`s_root`, `mnt_root`): every later mount-crossing open re-finds the
        // now-DEAD root and `mounts_in_ns`/path rendering fault dereferencing a
        // reclaimed dentry. Retain it unconditionally. # C: O(1)
        if d.is_root() { drop(d); return; }
        let delete = d.d_op().and_then(|o| o.d_delete).map(|f| f(&d)).unwrap_or(false);
        // Linux `retain_dentry`: only a HASHED (cacheable) dentry that is NOT
        // marked `DCACHE_DONTCACHE` is retained on the LRU for the shrinker. An
        // unhashed dentry — every anon-inode fd (pipe/eventfd/signalfd/socket/
        // memfd), or one already `d_drop`-ed by unlink — is killed at count 0
        // instead, so it never leaks a dangling `Weak` into the (currently
        // un-driven, D10) LRU. `d_delete` forces the same immediate eviction for
        // pseudo-fs that opt in; `DCACHE_DONTCACHE` (from an `I_DONTCACHE` inode)
        // forces it for a hashed dentry the fs wants evicted promptly.
        if delete || !d.is_hashed() || d.is_dontcache() { dentry_kill(&d); } else { lru_add(&d); }
    }
    drop(d);
}

/// Final kill of an UNUSED dentry: stamp
/// the lockref `LOCKREF_DEAD` sentinel BEFORE unhashing, so a concurrent
/// `d_lookup` whose `inc_count_not_dead` races the kill fails the not-dead gate
/// (dead is marked under the dentry lock ahead of the unhash) and re-walks the
/// slow path instead of resurrecting a dying
/// dentry. Routed to by every genuine eviction site — final `dput`, the LRU /
/// per-sb / subtree shrinkers, and `d_prune_aliases`. The non-kill unhash paths
/// keep the bare `d_drop`: `d_move` rehomes a live dentry, `d_invalidate`
/// disconnects a subtree whose nodes may still be in use, and a stale
/// `d_revalidate` miss re-walks without a refcount kill. # C: O(d_drop)
pub(super) fn dentry_kill(d: &Arc<Dentry>) {
    // Fire the pruning hook (gated by the presence bit) BEFORE unhashing, so
    // the fs can drop cache bookkeeping while
    // the dentry's name/parent binding is still intact.
    if d.d_has_op_prune() {
        if let Some(f) = d.d_op().and_then(|o| o.d_prune) { f(d); }
    }
    d.mark_dead();
    d_drop(d);
}

/// Unhash `d` from the global table and its parent's child list: a stale
/// positive dentry isn't reused after unlink/rmdir/rename.
/// Also drops `d` from its inode's alias list.
/// # C: O(bucket_len + log N_children)
pub fn d_drop(d: &Arc<Dentry>) {
    // Invariant: a dentry with a filesystem mounted on it stays hashed
    // and canonical — the unhash never touches a live mountpoint. Unhashing it
    // orphans the mount: a later lookup of the same (parent,name) mints a FRESH
    // dentry the mount is not keyed on (mount lookup keys on the dentry
    // pointer), so the mount is skipped and resolution falls through to the
    // underlay. This was the live-gnome greeter blocker: a sandbox setup
    // dropped the ext4 `/sys` dentry that sysfs was mounted on, so a re-lookup
    // of `/sys` produced an unmounted dentry → `/sys` = empty ext4 dir →
    // `/sys/dev/char/226:0` ENOENT → card0 never attached → no seat0 → no
    // greeter. Unmount clears the mounted flag BEFORE any drop, so
    // this guard never blocks a real teardown. # C: O(1)
    if d.is_mounted() { return; }
    DENTRY_HASHTABLE.remove(d);
    if let Some(inode) = d.inode() {
        if let Some(sb) = inode.i_sb() { sb.i_drop_alias(inode.ino(), d); }
    }
    if let Some(p) = d.parent() { p.forget_child(d.name()); }
}

/// Tell the dcache an inode behind `d` was unlinked: the FS calls this after
/// a successful `unlink`/`rmdir` so the
/// stale positive dentry isn't reused. Two outcomes:
///   * SOLE-USER, FS caches negatives — turn `d` NEGATIVE but keep it HASHED:
///     drop its inode alias and clear the inode,
///     leaving a cached miss so a later `d_lookup` of the now-absent name hits
///     the negative WITHOUT re-running the lookup op.
///   * SHARED (`d_count > 1`, another walker holds the positive view) OR the FS
///     opts out of caching negatives via its delete hook returning true
///     (e.g. a pseudo-fs that never wants stale names) —
///     UNHASH it (`d_drop`) so new lookups re-walk and the node is freed at the
///     last `dput`. A shared dentry can't be turned negative underneath its
///     other users, so it is dropped, not made negative. # C: O(d_drop)
pub fn d_delete(d: &Arc<Dentry>) {
    let want_drop = d.d_op().and_then(|o| o.d_delete).map(|f| f(d)).unwrap_or(false);
    if d.d_count() > 1 || want_drop {
        d_drop(d);
    } else {
        if let Some(inode) = d.inode() {
            if let Some(sb) = inode.i_sb() { sb.i_drop_alias(inode.ino(), d); }
        }
        d.set_inode(None);
    }
}

/// Unlink the name at `d` (dentry side of `unlink`/`rmdir`) — the D30
/// coupling between `Inode::i_nlink` and the per-inode dentry alias list.
///
/// AUTHORITY: the FILESYSTEM's unlink/rmdir op owns the in-memory
/// nlink decrement on the victim inode, and it runs BEFORE this — the unlink/
/// rmdir syscall handlers call the backend op first, then this. So by the time
/// `d_unlink` runs, `inode.i_nlink` ALREADY reflects the drop; this function
/// does NOT touch nlink (no double-decrement). It only tears down the dcache
/// side. Steps:
///   1. Read whether the backed-out name was the LAST (`inode.nlink() == 0`).
///   2. [`d_delete`] tears down THIS name: a sole-user dentry goes negative
///      (its alias dropped + inode detached via `dentry_iput`→`iput`), a shared
///      one is unhashed.
///   3. If that was the last name, [`d_prune_aliases`] drops every remaining
///      UNUSED sibling alias so no stale cached name resolves to the now-dead
///      inode, and the last
///      held reference's `iput` retires the inode through the EXISTING
///      `drop_inode`/`evict_inode` window. Eviction is driven solely by `iput`
///      (whose `drop_inode` default is `nlink == 0 && i_count == 0`) — this
///      function never frees the inode itself, so there is NO double-evict.
/// A negative `d` (no inode) is a no-op. Returns true iff the inode lost its
/// last name (caller may observe retirement once references drain).
/// # C: O(N_aliases)
pub fn d_unlink(d: &Arc<Dentry>) -> bool {
    let inode = match d.inode() { Some(i) => i, None => return false };
    // Backend `i_op->unlink`/`rmdir` already dropped the in-memory link.
    let last = inode.nlink() == 0;
    d_delete(d);
    // The delete-self notification fires once `i_nlink` reaches zero.
    // Firing here rather than from `unlink(2)` is what makes
    // `rmdir` report it at all, and what stops a file with remaining hardlinks
    // reporting it on the first name removed.
    if last {
        crate::file::fire_delete_self_hook(&inode);
        d_prune_aliases(&inode);
    }
    last
}
