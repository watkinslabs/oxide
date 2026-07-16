extern crate alloc;
use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::superblock::SuperBlock;

use super::hash::{DENTRY_HASHTABLE, RcuProbe};
use super::lifecycle::d_drop;

/// Allocate the root dentry for `sb`, install it as `s_root`, and record the
/// inode alias. # C: O(1)
pub fn d_make_root(inode: InodeRef, sb: &Arc<SuperBlock>) -> Arc<Dentry> {
    let root = Dentry::new_root_in_sb(inode.clone(), sb);
    // Pin the root's `d_count` for the mount's lifetime (Linux `__d_alloc` seeds
    // `d_lockref.count = 1`; the mount owns that ref via `sb->s_root`). Without
    // it the root starts at 0, so the FIRST open (dget→1) + close (dput→0) drives
    // `dentry_kill` → `mark_dead`: the root is NOT a mountpoint (`D_MOUNTED` sits
    // on the mountpoint in the PARENT fs, not the mounted-fs root), so `d_drop`
    // unhashes it — yet `resolve_path` crossing the mount keeps returning the
    // SB-pinned `s_root` Arc, now DEAD, to every later open (get/put-on-dead) →
    // eventual mount-walk #PF. `shrink_dcache_for_umount` force-detaches the
    // root regardless of `d_count` at umount, consuming this pin.
    root.inc_count();
    sb.set_s_root(root.clone());
    if let Some(s) = inode.i_sb() { s.i_add_alias(&inode, &root); }
    root.grab_inode_hold(); // D3/D37: root dentry counts its inode hold
    root
}

/// Allocate a NEGATIVE child dentry under `parent` (d_inode == None),
/// inheriting `parent`'s superblock + d_op. NOT hashed (Linux `d_alloc` does
/// not hash). # C: O(name.len())
pub fn d_alloc(parent: &Arc<Dentry>, name: &str) -> Arc<Dentry> {
    Dentry::new_child(parent, name, None)
}

/// Allocate a PSEUDO dentry for an anonymous/internal inode (Linux
/// `d_alloc_pseudo`, `fs/dcache.c`) — the constructor pipefs/sockfs/anon-inodefs
/// and every `anon_inode_getfd` consumer (pipe, eventfd, signalfd, timerfd,
/// memfd, epoll, bpf, io_uring) use for an fd with no path. The dentry is
/// parentless, positive, UNHASHED (no (parent,name) key — it never enters the
/// global table or any `d_subdirs`), and carries `d_op` so `d_op->d_dname`
/// renders its displayed path dynamically (`pipe:[ino]`, `[eventfd]`). `name` is
/// the static fallback `d_name`. Records the inode alias when the inode has an
/// owning SB, mirroring the other instantiating builders. # C: O(name.len())
pub fn d_alloc_pseudo(name: &str, inode: InodeRef, d_op: &'static crate::dentry::DentryOps) -> Arc<Dentry> {
    let d = Dentry::new_pseudo(name, inode.clone(), d_op);
    if let Some(sb) = inode.i_sb() { sb.i_add_alias(&inode, &d); }
    d.grab_inode_hold(); // D3/D37: pseudo dentry counts its inode hold
    d
}

/// Cache read (Linux `d_lookup`): the child dentry for `name` under
/// `parent`, positive OR cached-negative, via the global hash table — RCU
/// (seqcount) read with a locked ref-walk fallback. Fires `d_op->d_revalidate`
/// on a hit and drops a stale dentry. `None` = not cached (caller must do the
/// slow `i_op->lookup`). The ordinary fast-path walk (`reval == false`);
/// `d_lookup_reval` threads Linux `LOOKUP_REVAL`. # C: O(1) expected
pub fn d_lookup(parent: &Arc<Dentry>, name: &str) -> Option<Arc<Dentry>> {
    d_lookup_reval(parent, name, false)
}

/// Drop one cached child under an already-resolved parent dentry. Callers that
/// already hold the Linux parent path must not render a string and re-walk
/// through a possibly different bind/root namespace. # C: O(1) expected
pub fn d_drop_child(parent: &Arc<Dentry>, name: &str) {
    match parent.cached_child(name).or_else(|| d_lookup(parent, name)) {
        Some(child) => d_drop(&child),
        None => parent.forget_child(name),
    }
}

/// `d_lookup` with the Linux `LOOKUP_REVAL` flag threaded to the
/// `d_op->d_revalidate` hook, so a forced-revalidation walk (`reval == true`,
/// the ESTALE retry) re-checks a cached dentry against its backing store
/// instead of trusting an attribute-cache timeout. # C: O(1) expected
pub fn d_lookup_reval(parent: &Arc<Dentry>, name: &str, reval: bool) -> Option<Arc<Dentry>> {
    let qhash = Dentry::compute_hash(Some(parent), name);
    let pptr = Arc::as_ptr(parent);
    let cand = match DENTRY_HASHTABLE.lookup_rcu(pptr, qhash, name) {
        RcuProbe::Done(c) => c,
        RcuProbe::Retry   => DENTRY_HASHTABLE.lookup_locked(pptr, qhash, name),
    };
    let d = cand?;
    // Linux `__d_lookup` lockref gate (`lockref_get_not_dead`): atomically
    // pin-unless-dead. `dentry_kill` stamps `LOCKREF_DEAD` BEFORE a dying dentry
    // leaves the hash table, so a probe that still found it in the bucket must
    // read it as a cache MISS and re-walk the slow `i_op->lookup`, never
    // resurrect a dentry mid-kill. The pin is released before returning: this
    // dcache hands the walker an `Arc` (which alone keeps the node alive — no
    // RCU grace period), not a counted dput-owed reference, so the bump is
    // purely the not-dead test; its `set_referenced` side effect doubles as the
    // two-hand-clock access stamp the shrinker honors.
    if !d.inc_count_not_dead() { return None; }
    if let Some(rev) = d.d_op().and_then(|o| o.d_revalidate) {
        if !rev(&d, reval) { d.dec_count(); d_drop(&d); return None; }
    }
    d.dec_count();
    Some(d)
}

/// One-shot WEAK revalidation of an already-resolved final dentry (Linux
/// `complete_walk` → `d_op->d_weak_revalidate`). The per-component `d_lookup`
/// fast path consults `d_revalidate`; this is the counterpart Linux fires ONCE,
/// on the LAST component, only when the walk reached it via a jump (`..` out of
/// the starting mount, a procfs magic symlink) and so skipped the ordinary
/// per-step revalidation. `true` ⇒ the result is valid; `false` ⇒ stale (the
/// caller returns `-ESTALE` and retries the walk with `LOOKUP_REVAL`, threaded
/// here as `reval`). UNLIKE [`d_lookup_reval`], a stale weak result does NOT
/// `d_drop` the dentry — it stays a valid cache node, only THIS resolution is
/// rejected (Linux `complete_walk` returns the error without unhashing). A
/// dentry without the `D_OP_WEAK_REVALIDATE` hook is always valid — the common
/// case, gated on the presence bit so no `d_op` deref happens for it.
/// # C: O(1) (+ the fs hook)
pub fn d_weak_revalidate(d: &Arc<Dentry>, reval: bool) -> bool {
    if !d.d_has_op_weak_revalidate() { return true; }
    match d.d_op().and_then(|o| o.d_weak_revalidate) {
        Some(f) => f(d, reval),
        None    => true,
    }
}

/// Attach `inode` to a negative `dentry`, making it positive (post
/// create / lookup success), and record the dentry as an alias of the inode
/// in the owning SB's icache (Linux `d_instantiate` → `inode->i_dentry`).
/// # C: O(1)
pub fn d_instantiate(dentry: &Arc<Dentry>, inode: InodeRef) {
    if let Some(sb) = inode.i_sb() { sb.i_add_alias(&inode, dentry); }
    dentry.set_inode(Some(inode));
    dentry.grab_inode_hold(); // D3/D37: positive dentry counts its inode hold
}

/// `d_alloc` + `d_instantiate` + hash-insert, race-safe: an existing
/// cached entry wins so all walkers share one dentry per (parent,name).
/// Inserts the (race-winning) dentry into the global hash table and records
/// it as an alias of `inode`. # C: O(1) expected
pub fn d_add(parent: &Arc<Dentry>, name: &str, inode: InodeRef) -> Arc<Dentry> {
    let child = Dentry::new_child(parent, name, Some(inode.clone()));
    let canon = parent.cache_child(name, child);
    // Convert a previously cached negative dentry in place, as Linux
    // d_instantiate does; leaving the negative node canonical makes later
    // lookups incorrectly return ENOENT.
    if canon.inode().is_none() { d_instantiate(&canon, inode); }
    DENTRY_HASHTABLE.insert(&canon);
    canon
}

/// Cache a confirmed miss as a negative dentry under `parent`, hashed so a
/// later `d_lookup` hit returns it WITHOUT re-invoking `i_op->lookup`.
/// # C: O(1) expected
pub fn d_add_negative(parent: &Arc<Dentry>, name: &str) -> Arc<Dentry> {
    let child = Dentry::new_child(parent, name, None);
    let canon = parent.cache_child(name, child);
    DENTRY_HASHTABLE.insert(&canon);
    canon
}
