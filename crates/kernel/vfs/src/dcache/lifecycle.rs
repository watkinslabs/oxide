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

/// Final kill of an UNUSED dentry (Linux `__dentry_kill`, `fs/dcache.c`): stamp
/// the lockref `LOCKREF_DEAD` sentinel BEFORE unhashing, so a concurrent
/// `d_lookup` whose `inc_count_not_dead` races the kill fails the not-dead gate
/// (Linux marks dead under `d_lock` at the top of `__dentry_kill`, ahead of
/// `__d_drop`) and re-walks the slow path instead of resurrecting a dying
/// dentry. Routed to by every genuine eviction site — final `dput`, the LRU /
/// per-sb / subtree shrinkers, and `d_prune_aliases`. The non-kill unhash paths
/// keep the bare `d_drop`: `d_move` rehomes a live dentry, `d_invalidate`
/// disconnects a subtree whose nodes may still be in use, and a stale
/// `d_revalidate` miss re-walks without a refcount kill. # C: O(d_drop)
pub(super) fn dentry_kill(d: &Arc<Dentry>) {
    // Linux `__dentry_kill`: fire `d_op->d_prune` (gated by the `DCACHE_OP_PRUNE`
    // presence bit) BEFORE unhashing, so the fs can drop cache bookkeeping while
    // the dentry's name/parent binding is still intact.
    if d.d_has_op_prune() {
        if let Some(f) = d.d_op().and_then(|o| o.d_prune) { f(d); }
    }
    d.mark_dead();
    d_drop(d);
}

/// Unhash `d` from the global table and its parent's `d_subdirs` (Linux
/// `d_drop`): a stale positive dentry isn't reused after unlink/rmdir/rename.
/// Also drops `d` from its inode's alias list (`inode->i_dentry`).
/// # C: O(bucket_len + log N_children)
pub fn d_drop(d: &Arc<Dentry>) {
    // Linux invariant: a dentry with a filesystem mounted on it stays hashed
    // and canonical — `__d_drop` never unhashes a live mountpoint. Unhashing it
    // orphans the mount: a later lookup of the same (parent,name) mints a FRESH
    // dentry the mount is not keyed on (`__lookup_mnt` keys on dentry pointer),
    // so the mount is skipped and resolution falls through to the underlay. This
    // is the live-gnome greeter blocker: systemd's sandbox setup d_drop'd the
    // ext4 `/sys` dentry that sysfs was mounted on, so logind's re-lookup of
    // `/sys` produced an unmounted dentry → `/sys` = empty ext4 dir →
    // `/sys/dev/char/226:0` ENOENT → card0 never attached → no seat0 → no
    // greeter. Unmount clears `D_MOUNTED` (`put_mountpoint`) BEFORE any drop, so
    // this guard never blocks a real teardown. # C: O(1)
    if d.is_mounted() { return; }
    DENTRY_HASHTABLE.remove(d);
    if let Some(inode) = d.inode() {
        if let Some(sb) = inode.i_sb() { sb.i_drop_alias(inode.ino(), d); }
    }
    if let Some(p) = d.parent() { p.forget_child(d.name()); }
}

/// Tell the dcache an inode behind `d` was unlinked (Linux `d_delete`,
/// `fs/dcache.c`): the FS calls this after a successful `unlink`/`rmdir` so the
/// stale positive dentry isn't reused. Two Linux-faithful outcomes:
///   * SOLE-USER, FS caches negatives — turn `d` NEGATIVE but keep it HASHED
///     (Linux `dentry_unlink_inode`): drop its inode alias and clear the inode,
///     leaving a cached miss so a later `d_lookup` of the now-absent name hits
///     the negative WITHOUT re-running `i_op->lookup`.
///   * SHARED (`d_count > 1`, another walker holds the positive view) OR the FS
///     opts out of caching negatives via `d_op->d_delete` returning true (Linux
///     `DCACHE_OP_DELETE`, e.g. a pseudo-fs that never wants stale names) —
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

/// Unlink the name at `d` (Linux `vfs_unlink` tail, dentry side) — the D30
/// coupling between `Inode::i_nlink` and the per-inode `i_dentry` alias list.
///
/// AUTHORITY: the FILESYSTEM's `i_op->unlink`/`rmdir` owns the in-memory
/// `drop_nlink` on the victim inode (Linux: `ext4_unlink`→`ext4_dec_count`,
/// `shmem`/`simple_unlink`→`drop_nlink`), and it runs BEFORE this — the unlink/
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
///      inode (Linux `d_prune_aliases` on the final unlink), and the last
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
    if last { d_prune_aliases(&inode); }
    last
}

