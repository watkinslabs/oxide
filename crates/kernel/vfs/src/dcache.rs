// dcache primitives per `fs/dcache.c` — the (parent,name)-keyed dentry
// cache. NO global path→dentry map: every primitive reaches a child only
// through its parent + the global `dentry_hashtable` keyed by
// `(d_parent ptr, d_name.hash)`. The per-parent `d_subdirs` map is retained
// as the subtree-teardown / `d_invalidate` index, not as the lookup path.
//
// B3 layers (this file):
//   - `DentryHashTable`: fixed power-of-2 bucket array, `(parent,hash)`-keyed,
//     O(1) lookup (`16§96`). Buckets hold `Weak<Dentry>` so the table never
//     pins dentries — the shrinker / `dput`-to-zero frees them and the bucket
//     self-prunes dead weaks on probe.
//   - `__d_lookup_rcu` analog: per-bucket seqcount-gated read that does the
//     `Weak::upgrade` + `d_compare` lock-free, validated by the seqcount;
//     falls back to the locked ref-walk on a writer race (`16§124`).
//   - dcache LRU + `shrink_dcache` (`16§98`): unused negatives are the
//     unbounded-growth risk; the shrinker evicts them.
//   - `d_invalidate`: subtree drop via the `d_subdirs` index.
//
// Linux analogs:
//   d_make_root / d_alloc / d_lookup / d_instantiate / d_add / d_add_negative
//   dget / dput / d_drop / d_move / d_splice_alias / d_invalidate

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Dentry as DentryClass, Spinlock};

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::superblock::SuperBlock;

// ---------------------------------------------------------------------------
// Global dentry hash table (`16§96`). Power-of-2 buckets; index = low bits of
// the precomputed `full_name_hash` (parent already folded into the hash by
// `Dentry::compute_hash`, so bucketing on `hash` alone keys on (parent,name)).
// ---------------------------------------------------------------------------

const DHASH_BITS:     usize = 8;            // 256 buckets — hosted/test scale
const DHASH_NBUCKETS: usize = 1 << DHASH_BITS;
const DHASH_MASK:     u32   = (DHASH_NBUCKETS - 1) as u32;

/// One hash bucket: a seqcount (even = quiescent, odd = writer in progress)
/// + the spinlock-guarded `Weak` chain. The seqcount lets the read path
/// validate a lock-free probe (Linux `__d_lookup_rcu` seqcount).
struct Bucket {
    seq:     AtomicU32,
    entries: Spinlock<Vec<Weak<Dentry>>, DentryClass>,
}

pub struct DentryHashTable {
    buckets: [Bucket; DHASH_NBUCKETS],
}

/// Result of the lock-free (`rcu`) probe: `Ok` = authoritative (hit/miss),
/// `Err` = writer raced, retry under the bucket lock.
enum RcuProbe { Done(Option<Arc<Dentry>>), Retry }

impl DentryHashTable {
    const fn new() -> Self {
        DentryHashTable {
            buckets: [const { Bucket { seq: AtomicU32::new(0), entries: Spinlock::new(Vec::new()) } }; DHASH_NBUCKETS],
        }
    }

    fn bucket(&self, hash: u32) -> &Bucket { &self.buckets[(hash & DHASH_MASK) as usize] }

    /// Hash `d` into the table (idempotent by `Arc` identity) and prune any
    /// dead weaks sharing the bucket. Sets `D_HASHED`. # C: O(bucket_len)
    fn insert(&self, d: &Arc<Dentry>) {
        let b = self.bucket(d.d_hash());
        let dptr = Arc::as_ptr(d);
        let mut g = b.entries.lock();
        b.seq.fetch_add(1, Ordering::Release); // begin (odd)
        let mut present = false;
        g.retain(|w| match w.upgrade() {
            Some(e) => { if Arc::as_ptr(&e) == dptr { present = true; } true }
            None    => false,
        });
        if !present { g.push(Arc::downgrade(d)); }
        b.seq.fetch_add(1, Ordering::Release); // end (even)
        drop(g);
        d.set_hashed(true);
    }

    /// Unhash `d` (Linux `__d_drop`). Clears `D_HASHED`. # C: O(bucket_len)
    fn remove(&self, d: &Dentry) {
        let b = self.bucket(d.d_hash());
        let dptr = d as *const Dentry;
        let mut g = b.entries.lock();
        b.seq.fetch_add(1, Ordering::Release);
        g.retain(|w| match w.upgrade() { Some(e) => Arc::as_ptr(&e) != dptr, None => false });
        b.seq.fetch_add(1, Ordering::Release);
        drop(g);
        d.set_hashed(false);
    }

    /// Locked ref-walk (Linux `__d_lookup`). # C: O(bucket_len)
    fn lookup_locked(&self, parent: *const Dentry, qhash: u32, name: &str) -> Option<Arc<Dentry>> {
        let b = self.bucket(qhash);
        let g = b.entries.lock();
        for w in g.iter() {
            if let Some(e) = w.upgrade() {
                if e.key_matches(parent, qhash, name) { return Some(e); }
            }
        }
        None
    }

    /// Lock-free seqcount-gated probe (Linux `__d_lookup_rcu`). The bucket
    /// lock is held only to snapshot the `Weak` chain (cheap refcount bumps);
    /// the `upgrade` + `key_matches` walk runs lock-free and is validated by
    /// the seqcount — if a writer mutated the bucket meanwhile, retry under
    /// the lock. `Weak::upgrade` is the no_std substitute for `call_rcu`:
    /// `Arc`'s atomic strong count makes the deref safe without a grace
    /// period, and a concurrently-freed dentry simply fails to upgrade.
    /// # C: O(bucket_len)
    fn lookup_rcu(&self, parent: *const Dentry, qhash: u32, name: &str) -> RcuProbe {
        let b = self.bucket(qhash);
        let (s1, snap) = {
            let g = b.entries.lock();
            (b.seq.load(Ordering::Acquire), g.clone())
        };
        if s1 & 1 != 0 { return RcuProbe::Retry; } // snapshot taken mid-write
        let mut found = None;
        for w in snap.iter() {
            if let Some(e) = w.upgrade() {
                if e.key_matches(parent, qhash, name) { found = Some(e); break; }
            }
        }
        if b.seq.load(Ordering::Acquire) != s1 { return RcuProbe::Retry; }
        RcuProbe::Done(found)
    }
}

static DENTRY_HASHTABLE: DentryHashTable = DentryHashTable::new();

// ---------------------------------------------------------------------------
// dcache LRU (`16§98`). `dput`-to-zero pushes a `Weak` here; `shrink_dcache`
// evicts unused (d_count==0, unreferenced) entries — primarily the otherwise
// unbounded unused negatives.
// ---------------------------------------------------------------------------

static DENTRY_LRU: Spinlock<VecDeque<Weak<Dentry>>, DentryClass> = Spinlock::new(VecDeque::new());

fn lru_add(d: &Arc<Dentry>) {
    if d.is_on_lru() { return; }
    d.set_on_lru(true);
    DENTRY_LRU.lock().push_back(Arc::downgrade(d));
}

/// Reclaim up to `target` unused dentries from the LRU head (Linux
/// `shrink_dcache_sb` / `prune_dcache`). Referenced entries get their bit
/// cleared and rotate to the tail (two-hand clock); entries that regained a
/// ref (`d_count>0`) leave the LRU; evictable entries are `d_drop`-ed (unhash
/// + forget child + drop alias), which releases the last `Arc` for unused
/// negatives and frees them. Returns the count evicted. # C: O(scanned)
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

// ---------------------------------------------------------------------------
// Primitives.
// ---------------------------------------------------------------------------

/// Allocate the root dentry for `sb` (no parent, empty name, positive)
/// and install it as `sb->s_root`. Records the root dentry as an alias of the
/// root inode (Linux `d_make_root` → `d_instantiate`). # C: O(1)
pub fn d_make_root(inode: InodeRef, sb: &Arc<SuperBlock>) -> Arc<Dentry> {
    let root = Dentry::new_root_in_sb(inode.clone(), sb);
    sb.set_s_root(root.clone());
    if let Some(s) = inode.i_sb() { s.i_add_alias(&inode, &root); }
    root
}

/// Allocate a NEGATIVE child dentry under `parent` (d_inode == None),
/// inheriting `parent`'s superblock + d_op. NOT hashed (Linux `d_alloc` does
/// not hash). # C: O(name.len())
pub fn d_alloc(parent: &Arc<Dentry>, name: &str) -> Arc<Dentry> {
    Dentry::new_child(parent, name, None)
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

/// Attach `inode` to a negative `dentry`, making it positive (post
/// create / lookup success), and record the dentry as an alias of the inode
/// in the owning SB's icache (Linux `d_instantiate` → `inode->i_dentry`).
/// # C: O(1)
pub fn d_instantiate(dentry: &Arc<Dentry>, inode: InodeRef) {
    if let Some(sb) = inode.i_sb() { sb.i_add_alias(&inode, dentry); }
    dentry.set_inode(Some(inode));
}

/// `d_alloc` + `d_instantiate` + hash-insert, race-safe: an existing
/// cached entry wins so all walkers share one dentry per (parent,name).
/// Inserts the (race-winning) dentry into the global hash table and records
/// it as an alias of `inode`. # C: O(1) expected
pub fn d_add(parent: &Arc<Dentry>, name: &str, inode: InodeRef) -> Arc<Dentry> {
    let child = Dentry::new_child(parent, name, Some(inode.clone()));
    let canon = parent.cache_child(name, child);
    if let Some(sb) = inode.i_sb() { sb.i_add_alias(&inode, &canon); }
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
        // Linux `retain_dentry`: only a HASHED (cacheable) dentry is retained on
        // the LRU for the shrinker. An unhashed dentry — every anon-inode fd
        // (pipe/eventfd/signalfd/socket/memfd), or one already `d_drop`-ed by
        // unlink — is killed at count 0 instead, so it never leaks a dangling
        // `Weak` into the (currently un-driven, D10) LRU. `d_delete` forces the
        // same immediate eviction for pseudo-fs that opt in.
        if delete || !d.is_hashed() { dentry_kill(&d); } else { lru_add(&d); }
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
fn dentry_kill(d: &Arc<Dentry>) {
    d.mark_dead();
    d_drop(d);
}

/// Unhash `d` from the global table and its parent's `d_subdirs` (Linux
/// `d_drop`): a stale positive dentry isn't reused after unlink/rmdir/rename.
/// Also drops `d` from its inode's alias list (`inode->i_dentry`).
/// # C: O(bucket_len + log N_children)
pub fn d_drop(d: &Arc<Dentry>) {
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

/// Rename `old` to `(new_parent, new_name)` (Linux `d_move`). Unhashes
/// `old` from its current parent and rehomes its inode under the new
/// (parent,name) key, so `d_lookup(old_parent, old_name)` misses and
/// `d_lookup(new_parent, new_name)` hits. # C: O(1) expected
pub fn d_move(old: &Arc<Dentry>, new_parent: &Arc<Dentry>, new_name: &str) -> Arc<Dentry> {
    d_drop(old);
    match old.inode() {
        Some(inode) => d_add(new_parent, new_name, inode),
        None        => d_add_negative(new_parent, new_name),
    }
}

/// Obtain a dentry referring to `inode` WITHOUT a path/parent (Linux
/// `d_obtain_alias`, `fs/dcache.c`). Used by exportfs / `open_by_handle_at`
/// and by `d_splice_alias`'s disconnected-reattach. REUSE first: if `inode`
/// already has a live alias, return it — mandatory for DIRECTORIES, which have
/// at most one dentry (a second dir dentry would split the dcache subtree).
/// Else allocate a NEW anonymous dentry: parentless, `D_DISCONNECTED`,
/// instantiated with `inode` and recorded on its `i_dentry` alias list via the
/// SAME `i_add_alias` path the other builders use. NOT hashed into the global
/// `dentry_hashtable` — a disconnected dentry has no (parent,name) key; Linux
/// keeps it on `s_anon`, not the main hash. An `i_sb()`-less inode still gets a
/// valid anon dentry (the alias just can't be recorded). # C: O(N_aliases)
pub fn d_obtain_alias(inode: InodeRef) -> Arc<Dentry> {
    if let Some(sb) = inode.i_sb() {
        if let Some(existing) = sb.i_aliases(inode.ino()).into_iter().next() { return existing; }
    }
    let anon = Dentry::new_anon(inode.clone());
    if let Some(sb) = inode.i_sb() { sb.i_add_alias(&inode, &anon); }
    anon
}

/// Directory alias merge (Linux `d_splice_alias`): splice `inode` into the
/// negative dentry `d` at `(d.parent, d.name)` and return the now-positive
/// dentry. Enforces the directory single-dentry invariant: a directory inode
/// has at most ONE dentry, so if `inode` already carries a `D_DISCONNECTED`
/// anonymous alias (from `d_obtain_alias` / exportfs `open_by_handle_at`),
/// that anon alias IS the directory's real dentry — reattach it to
/// `(d.parent, d.name)` and return that, instead of instantiating `d` (a
/// second positive dir dentry would split the dcache subtree). Linux
/// `__d_find_alias` + `__d_move`. Non-directories, and dirs with no prior
/// alias, take the common negative→positive splice. # C: O(N_aliases)
pub fn d_splice_alias(inode: InodeRef, d: &Arc<Dentry>) -> Arc<Dentry> {
    if inode.file_type() == crate::types::FileType::Directory {
        if let (Some(sb), Some(parent)) = (inode.i_sb(), d.parent()) {
            let anon = sb.i_aliases(inode.ino()).into_iter()
                .find(|a| a.is_disconnected() && !Arc::ptr_eq(a, d));
            if let Some(alias) = anon {
                // Reattach the disconnected dir alias under (parent, d.name):
                // d_move unhashes/forgets `alias`, then re-keys `inode` at the
                // new (parent,name) so it is the sole connected dir dentry.
                return d_move(&alias, parent, d.name());
            }
        }
    }
    d_instantiate(d, inode);
    if !d.is_hashed() { DENTRY_HASHTABLE.insert(d); }
    d.clone()
}

/// Invalidate `d` and its whole subtree (Linux `d_invalidate`): unhash every
/// node so live descendants become disconnected and re-lookup re-walks the
/// FS, AND detach any mount(s) covering a dentry in the subtree (Linux
/// `detach_mounts(child)`) in every namespace — the subtree is going away, so
/// overmounts must go with it. Iterative over the `d_subdirs` index to bound
/// stack depth. Used on remount / staleness and rmdir of a populated-but-
/// invalidated dir. # C: O(subtree)
pub fn d_invalidate(d: &Arc<Dentry>) {
    let mut stack: Vec<Arc<Dentry>> = alloc::vec![d.clone()];
    while let Some(cur) = stack.pop() {
        for kid in cur.children_snapshot() { stack.push(kid); }
        crate::mount::detach_mounts_on(&cur);
        d_drop(&cur);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dentry::{DentryOps, D_HASHED, D_NEGATIVE};
    use crate::inode::Inode;
    use crate::types::{FileType, KResult, VfsError};
    use alloc::string::String;
    use alloc::format;

    // Minimal directory inode for positive-dentry tests. `i_sb()` defaults to
    // None so no superblock/alias machinery is needed.
    struct Dir { ino: u64 }
    impl Inode for Dir {
        fn ino(&self) -> u64 { self.ino }
        fn file_type(&self) -> FileType { FileType::Directory }
        fn size(&self) -> u64 { 0 }
        fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
    }
    fn dir(ino: u64) -> InodeRef { Arc::new(Dir { ino }) }

    fn root() -> Arc<Dentry> { Dentry::new_root(dir(1)) }

    // hashed == tree: every (parent,name) added is found by the global table
    // and the table returns the SAME Arc as the per-parent d_subdirs index.
    #[test]
    fn global_hash_agrees_with_tree() {
        let r = root();
        let mut names: Vec<String> = Vec::new();
        for i in 0..200u32 { names.push(format!("child{i}")); }
        for (i, n) in names.iter().enumerate() {
            if i % 2 == 0 { d_add(&r, n, dir(100 + i as u64)); } else { d_add_negative(&r, n); }
        }
        for n in &names {
            let via_table = d_lookup(&r, n).expect("table hit");
            let via_tree  = r.cached_child(n).expect("tree hit");
            assert!(Arc::ptr_eq(&via_table, &via_tree), "table != tree for {n}");
            assert!(via_table.is_hashed());
        }
        // Uncached name misses.
        assert!(d_lookup(&r, "absent").is_none());
    }

    // The locked walk and the rcu (seqcount) probe return the same dentry.
    #[test]
    fn rcu_path_agrees_with_locked() {
        let r = root();
        for i in 0..64u32 { d_add(&r, &format!("f{i}"), dir(200 + i as u64)); }
        for i in 0..64u32 {
            let n = format!("f{i}");
            let qhash = Dentry::compute_hash(Some(&r), &n);
            let pptr = Arc::as_ptr(&r);
            let locked = DENTRY_HASHTABLE.lookup_locked(pptr, qhash, &n).unwrap();
            let rcu = match DENTRY_HASHTABLE.lookup_rcu(pptr, qhash, &n) {
                RcuProbe::Done(c) => c.unwrap(),
                RcuProbe::Retry   => DENTRY_HASHTABLE.lookup_locked(pptr, qhash, &n).unwrap(),
            };
            assert!(Arc::ptr_eq(&locked, &rcu));
        }
    }

    // O(1): with 256 buckets and 256 random keys, no bucket should hold more
    // than a small constant chain (uniform hash ⇒ bounded chain length).
    #[test]
    fn lookup_is_o1_bounded_chains() {
        let r = root();
        for i in 0..256u32 { d_add_negative(&r, &format!("e{i}")); }
        let max = DENTRY_HASHTABLE.buckets.iter()
            .map(|b| b.entries.lock().iter().filter(|w| w.upgrade().is_some()).count())
            .max().unwrap_or(0);
        assert!(max <= 12, "max chain {max} too long — not O(1)");
    }

    // d_compare / d_hash hook: case-insensitive lookup hits a lower-case entry.
    static CI_OPS: DentryOps = DentryOps {
        d_hash:    Some(|name| {
            let mut h: u64 = 0xcbf29ce484222325;
            for b in name.bytes() { h = (h ^ (b.to_ascii_lowercase() as u64)).wrapping_mul(0x100000001B3); }
            (h ^ (h >> 32)) as u32
        }),
        d_compare: Some(|name, cand| name.eq_ignore_ascii_case(cand.name())),
        d_revalidate: None, d_delete: None, d_release: None, d_iput: None,
    };
    #[test]
    fn d_compare_case_insensitive() {
        let r = Dentry::new_root(dir(1)).set_d_op(&CI_OPS);
        d_add(&r, "foo", dir(7));
        let hit = d_lookup(&r, "FOO").expect("case-insensitive hit");
        assert_eq!(hit.name(), "foo");
        let hit2 = d_lookup(&r, "FoO").expect("case-insensitive hit2");
        assert!(Arc::ptr_eq(&hit, &hit2));
    }

    // d_revalidate: a stale dentry is dropped on lookup.
    static STALE_OPS: DentryOps = DentryOps {
        d_revalidate: Some(|_d, _reval| false), // everything is stale
        d_hash: None, d_compare: None, d_delete: None, d_release: None, d_iput: None,
    };
    #[test]
    fn d_revalidate_drops_stale() {
        let r = Dentry::new_root(dir(1)).set_d_op(&STALE_OPS);
        d_add_negative(&r, "x");
        assert!(d_lookup(&r, "x").is_none(), "stale dentry must be dropped");
        // and it was unhashed
        let qhash = Dentry::compute_hash(Some(&r), "x");
        assert!(DENTRY_HASHTABLE.lookup_locked(Arc::as_ptr(&r), qhash, "x").is_none());
    }

    // lockref d_count: dget/dput balance; at 0 the dentry joins the LRU.
    #[test]
    fn lockref_count_and_lru() {
        let r = root();
        let c = d_add_negative(&r, "n");
        assert_eq!(c.d_count(), 0);
        let g = dget(&c);
        assert_eq!(c.d_count(), 1);
        assert!(!c.is_on_lru());
        dput(g);
        assert_eq!(c.d_count(), 0);
        assert!(c.is_on_lru(), "unused dentry must be on the LRU");
    }

    // shrink_dcache evicts unused negatives; referenced/in-use survive.
    #[test]
    fn shrink_evicts_unused_negatives() {
        let r = root();
        // 100 unused negatives -> all eligible after dput-to-0.
        let mut kids = Vec::new();
        for i in 0..100u32 {
            let c = d_add_negative(&r, &format!("neg{i}"));
            let g = dget(&c);  // count 1
            dput(g);           // back to 0 -> LRU, referenced bit set by dget
            kids.push(c);
        }
        // First shrink pass: all are referenced (dget set the bit) -> rotated,
        // bit cleared, nothing freed.
        let first = shrink_dcache(100);
        assert_eq!(first, 0);
        // One in-use dentry must never be evicted.
        let pinned = d_add_negative(&r, "pinned");
        let _hold = dget(&pinned); // count 1
        // Second pass: bits cleared -> evict unused negatives.
        let freed = shrink_dcache(200);
        assert!(freed >= 90, "expected most negatives evicted, got {freed}");
        // Evicted ones are unhashed + forgotten by the parent.
        let mut gone = 0;
        for (i, _c) in kids.iter().enumerate() {
            if r.cached_child(&format!("neg{i}")).is_none() { gone += 1; }
        }
        assert!(gone >= 90);
        assert!(pinned.d_count() > 0);
        assert!(r.cached_child("pinned").is_some(), "in-use dentry survived");
    }

    // d_invalidate unhashes a whole subtree.
    #[test]
    fn d_invalidate_subtree() {
        let r = root();
        let a = d_add(&r, "a", dir(10));
        let b = d_add(&a, "b", dir(11));
        let _c = d_add(&b, "c", dir(12));
        assert!(d_lookup(&r, "a").is_some());
        assert!(d_lookup(&a, "b").is_some());
        assert!(d_lookup(&b, "c").is_some());
        d_invalidate(&a);
        assert!(d_lookup(&r, "a").is_none());
        assert!(d_lookup(&a, "b").is_none());
        assert!(d_lookup(&b, "c").is_none());
        assert_eq!(a.flags() & D_HASHED, 0);
    }

    // d_move rehomes under a new (parent,name) key.
    #[test]
    fn d_move_rehomes() {
        let r = root();
        let p2 = d_add(&r, "dst", dir(20));
        d_add(&r, "old", dir(21));
        assert!(d_lookup(&r, "old").is_some());
        let moved = d_move(&d_lookup(&r, "old").unwrap(), &p2, "new");
        assert!(d_lookup(&r, "old").is_none());
        let hit = d_lookup(&p2, "new").unwrap();
        assert!(Arc::ptr_eq(&hit, &moved));
    }

    // shrink_dcache_parent prunes the unused subtree but pins the path to an
    // in-use descendant.
    #[test]
    fn shrink_dcache_parent_prunes_unused_pins_in_use() {
        let r = root();
        let a = d_add(&r, "a", dir(10));
        let b = d_add(&a, "b", dir(11));
        let c = d_add(&b, "c", dir(12));
        let _d = d_add(&a, "d", dir(13));
        // Nothing held -> whole subtree under `a` pruned, `a` survives.
        let r2 = root();
        let a2 = d_add(&r2, "a", dir(20));
        let b2 = d_add(&a2, "b", dir(21));
        let _c2 = d_add(&b2, "c", dir(22));
        assert_eq!(shrink_dcache_parent(&a2), 2);
        assert!(a2.children_snapshot().is_empty());
        assert!(d_lookup(&r2, "a").is_some());
        // Pin `c` -> `b` survives, sibling `d` pruned.
        let hold = dget(&c);
        let freed = shrink_dcache_parent(&a);
        assert_eq!(freed, 1, "only unused sibling d");
        assert!(a.cached_child("b").is_some());
        assert!(b.cached_child("c").is_some());
        assert!(a.cached_child("d").is_none());
        dput(hold);
    }

    // set_inode flips D_NEGATIVE and fires d_iput on disassociation.
    #[test]
    fn negative_to_positive_flags() {
        let r = root();
        let c = d_add_negative(&r, "z");
        assert_ne!(c.flags() & D_NEGATIVE, 0);
        c.set_inode(Some(dir(30)));
        assert_eq!(c.flags() & D_NEGATIVE, 0);
        assert!(!c.is_negative());
    }
}
