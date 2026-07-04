extern crate alloc;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use crate::dentry::Dentry;
use crate::inode::{InodeRef, I_CLEAR, I_DIRTY, I_FREEING, I_NEW, I_WILL_FREE};
use crate::types::Ino;
use super::{IcacheEntry, SuperBlock};

impl SuperBlock {
    /// `ilookup` — hit the inode cache. `None` if absent, reclaimed, or dying.
    /// # C: O(log N_ino)
pub fn ilookup(&self, ino: Ino) -> Option<InodeRef> {
        let i = self.icache_upgrade(ino)?;
        if i.is_freeing() { return None; }
        Some(i)
    }

    /// Upgrade the icache `Weak` for `ino` UNCONDITIONALLY (dying slots too) —
    /// the raw accessor behind the per-ino `i_state`/`i_nlink` helpers. # C: O(log N_ino)
    fn icache_upgrade(&self, ino: Ino) -> Option<InodeRef> {
        self.icache.lock().get(&ino).and_then(|e| e.inode.upgrade())
    }

    /// `iget` — cache hit (SAME `Arc`, `igrab` bumps `i_count`), else `build()`
    /// a fresh `Arc<Inode>` (born `i_count == 1`) and cache a `Weak`. The
    /// build-miss inode is published with `I_NEW` then cleared (Linux
    /// `unlock_new_inode`); a concurrent `ilookup` upgrades the built `Arc` and
    /// wins. A stale/dying slot (`I_FREEING`/`I_WILL_FREE`) is rebuilt over.
    /// # C: O(log N_ino)
    pub fn iget(&self, ino: Ino, build: impl FnOnce() -> InodeRef) -> InodeRef {
        if let Some(i) = self.ilookup(ino) { i.igrab(); return i; }
        let inode = build();
        inode.set_state(I_NEW, 0);
        let mut c = self.icache.lock();
        if let Some(e) = c.get(&ino) {
            if let Some(existing) = e.inode.upgrade() {
                if !existing.is_freeing() { existing.igrab(); return existing; }
            }
        }
        // Preserve still-live aliases recorded while the inode was un-cached.
        let aliases = c.get(&ino).map(|e| {
            e.aliases.iter().filter(|w| w.upgrade().is_some()).cloned().collect::<Vec<_>>()
        }).unwrap_or_default();
        c.insert(ino, IcacheEntry { inode: Arc::downgrade(&inode), aliases });
        inode.set_state(0, I_NEW); // unlock_new_inode
        inode
    }

    /// `iput` (Linux `fs/inode.c`) — drop one `i_count` reference. On the LAST
    /// drop (1 → 0, `iput_final`) the `s_op->drop_inode` decision runs: when it
    /// says evict (default: `i_nlink == 0`), the inode goes through the pre-evict
    /// window — `I_WILL_FREE`, `s_op->write_inode` (flush dirty metadata),
    /// `I_FREEING`, `s_op->evict_inode` (default `clear_inode`) — then the
    /// writeback pin and icache `Weak` are dropped so a later `iget` rebuilds.
    /// When `drop_inode` declines (a still-linked inode), the inode is RETAINED
    /// cached for reuse (Linux leaves it on the LRU), exactly mirroring the
    /// kernel's keep-vs-evict split. # C: O(log N_ino)
    pub fn iput(&self, inode: InodeRef) {
        if inode.i_count_dec() != 1 { return; } // not the last reference
        // i_count is now 0 (iput_final). Consult the backend keep/evict policy.
        if !self.s_op.drop_inode(&inode) { return; } // retain cached for reuse
        let ino = inode.ino();
        inode.set_state(I_WILL_FREE, 0);
        let _ = self.s_op.write_inode(&inode, false); // flush dirty metadata
        inode.set_state(I_FREEING, I_WILL_FREE);
        self.s_op.evict_inode(&inode); // default: clear_inode (I_FREEING|I_CLEAR)
        self.wb_forget(ino); // dirty bits gone → drop the writeback pin
        self.icache.lock().remove(&ino);
    }

    /// `iput`/reclaim hook — drop a cache slot whose inode is gone.
    /// # C: O(log N_ino)
    pub fn iforget(&self, ino: Ino) { self.icache.lock().remove(&ino); }

    /// `s_inodes` (Linux `super_block.s_inodes`) — every LIVE inode resident on
    /// this superblock, in `ino` order (the icache is an `ino`-keyed `BTreeMap`,
    /// so iteration is naturally ordered). Slots whose `Weak` no longer upgrades
    /// (the inode's last `Arc` already dropped) are skipped — Linux's list holds
    /// only resident inodes. This is the set the per-sb sweeps walk
    /// ([`Self::evict_inodes`], [`Self::drop_caches`], writeback, quota,
    /// fsnotify). # C: O(N_ino)
    pub fn s_inodes(&self) -> Vec<InodeRef> {
        self.icache.lock().values().filter_map(|e| e.inode.upgrade()).collect()
    }

    /// Cached inode-slot count on this superblock (Linux per-sb `nr_inodes`).
    /// Counts every slot including a stale `Weak` not yet reclaimed, so it is the
    /// icache occupancy, not the live-inode count ([`Self::s_inodes`]`.len()`).
    /// # C: O(1)
    pub fn nr_cached_inodes(&self) -> usize { self.icache.lock().len() }

    /// Walk the `s_inodes` list applying `f` to every LIVE inode in `ino` order
    /// (Linux `inode_sb_list` walk behind quota/fsnotify/`sync` sweeps). Snapshots
    /// the live set FIRST and releases the icache lock before invoking `f`, so a
    /// callback may safely re-enter the SB (`iget`/`ilookup`) without
    /// self-deadlock — Linux's equivalent `igrab`s then drops `s_inode_list_lock`
    /// across the body. # C: O(N_ino)
    pub fn for_each_inode(&self, mut f: impl FnMut(&InodeRef)) {
        for i in self.s_inodes() { f(&i); }
    }

    /// `i_state` bits for `ino` (`I_NEW`/`I_DIRTY`/`I_FREEING`); `0` if not
    /// cached. # C: O(log N_ino)
    pub fn i_state(&self, ino: Ino) -> u32 {
        self.icache_upgrade(ino).map(|i| i.i_state()).unwrap_or(0)
    }

    /// Set/clear `i_state` bits for `ino` (no-op if uncached). After the change
    /// the writeback pin is reconciled ([`Self::wb_reconcile`]): a now-`I_DIRTY`
    /// inode is STRONG-pinned, a fully-clean one released. # C: O(log N_ino)
    pub fn i_set_state(&self, ino: Ino, set: u32, clear: u32) {
        if let Some(i) = self.icache_upgrade(ino) { i.set_state(set, clear); self.wb_reconcile(ino, &i); }
    }

    /// True iff `ino` is being evicted — Linux's pervasive
    /// `(i_state & (I_FREEING | I_WILL_FREE))` dying-inode predicate
    /// (`find_inode_fast`, `iput`, `evict`). A slot in this state is past
    /// resurrection: `ilookup` reports it as a miss and `iget` rebuilds over it.
    /// `false` for an uncached ino (`i_state` reads `0`). # C: O(log N_ino)
    pub fn i_is_freeing(&self, ino: Ino) -> bool {
        self.i_state(ino) & (I_FREEING | I_WILL_FREE) != 0
    }

    /// `inode->i_nlink` — the cached hard-link count for `ino`. `None` if the
    /// inode is not cached. The slot is seeded from `Inode::nlink()` when built,
    /// then maintained by [`Self::set_nlink`]/[`Self::inc_nlink`]/
    /// [`Self::drop_nlink`]. A `Some(0)` result is the Linux evict predicate
    /// (`i_nlink == 0`): the inode has no remaining names and is freed on its
    /// last `iput`. # C: O(log N_ino)
    pub fn i_nlink(&self, ino: Ino) -> Option<u32> {
        self.icache_upgrade(ino).map(|i| i.nlink())
    }

    /// True iff `ino` is an eviction candidate — cached with `i_nlink == 0`
    /// (Linux `iput_final` drops/evicts an inode whose last reference goes while
    /// `i_nlink == 0`). `false` for an uncached ino. # C: O(log N_ino)
    pub fn i_nlink_zero(&self, ino: Ino) -> bool {
        self.i_nlink(ino) == Some(0)
    }

    /// `set_nlink` (Linux fs/inode.c): set `ino`'s stored link count to `nlink`.
    /// `0` clears it to the dead state (Linux `clear_nlink`); a nonzero value
    /// directly installs the count, including the legitimate `0 → 1` revival some
    /// filesystems perform. No-op if uncached. # C: O(log N_ino)
    pub fn set_nlink(&self, ino: Ino, nlink: u32) {
        if let Some(i) = self.icache_upgrade(ino) { i.set_nlink(nlink); }
    }

    /// `inc_nlink` (Linux fs/inode.c): add one hard link to `ino`'s stored count,
    /// reviving a `0`-count inode (the O_TMPFILE `linkat` `I_LINKABLE` case). The
    /// count saturates rather than wrapping. No-op if uncached. # C: O(log N_ino)
    pub fn inc_nlink(&self, ino: Ino) {
        if let Some(i) = self.icache_upgrade(ino) { i.inc_nlink(); }
    }

    /// `drop_nlink` (Linux fs/inode.c): remove one hard link from `ino`'s stored
    /// count. Reaching `0` makes the inode an eviction candidate (observable via
    /// [`Self::i_nlink_zero`] / [`Self::i_nlink`]). Saturates at `0` rather than
    /// underflowing (Linux WARNs on a drop below zero; the count never wraps).
    /// No-op if uncached. # C: O(log N_ino)
    pub fn drop_nlink(&self, ino: Ino) {
        if let Some(i) = self.icache_upgrade(ino) { i.drop_nlink(); }
    }

    /// `mark_inode_dirty` (Linux `__mark_inode_dirty`): OR the requested
    /// `I_DIRTY_*` bits into `ino`'s state. `flags` is masked to `I_DIRTY` so a
    /// caller cannot smuggle a lifecycle bit (`I_NEW`/`I_FREEING`/…) through the
    /// dirtying path. No-op if uncached. # C: O(log N_ino)
    pub fn mark_inode_dirty(&self, ino: Ino, flags: u32) {
        self.i_set_state(ino, flags & I_DIRTY, 0);
    }

    /// `clear_inode` (Linux fs/inode.c): the terminal eviction state. Sets
    /// `I_FREEING | I_CLEAR` and drops every dirty bit — the inode's metadata is
    /// gone and no writeback will follow. # C: O(log N_ino)
    pub fn clear_inode(&self, ino: Ino) {
        self.i_set_state(ino, I_FREEING | I_CLEAR, I_DIRTY);
    }

    /// Record `d` as an alias of `inode` (Linux `d_instantiate` →
    /// `inode->i_dentry`). Creates/refreshes the icache slot if needed so an
    /// inode that was built ad-hoc (not via `iget`) still tracks its dentries.
    /// Idempotent: an already-listed live alias is not duplicated; dead alias
    /// `Weak`s are pruned on touch. # C: O(N_aliases)
    pub fn i_add_alias(&self, inode: &InodeRef, d: &Arc<Dentry>) {
        let ino = inode.ino();
        let mut c = self.icache.lock();
        let e = c.entry(ino).or_insert_with(|| IcacheEntry {
            inode: Arc::downgrade(inode), aliases: Vec::new(),
        });
        if e.inode.upgrade().is_none() { e.inode = Arc::downgrade(inode); }
        e.aliases.retain(|w| match w.upgrade() { Some(a) => !Arc::ptr_eq(&a, d), None => false });
        e.aliases.push(Arc::downgrade(d));
    }

    /// Drop `d` from `ino`'s alias list (Linux `d_drop`/dentry teardown). If
    /// the slot is then empty AND the inode is gone, reclaim it.
    /// # C: O(N_aliases)
    pub fn i_drop_alias(&self, ino: Ino, d: &Arc<Dentry>) {
        let mut c = self.icache.lock();
        let gone = if let Some(e) = c.get_mut(&ino) {
            e.aliases.retain(|w| match w.upgrade() { Some(a) => !Arc::ptr_eq(&a, d), None => false });
            e.aliases.is_empty() && e.inode.upgrade().is_none()
        } else { false };
        if gone { c.remove(&ino); }
    }

    /// Live dentry aliases of `ino` (Linux walk of `inode->i_dentry`).
    /// # C: O(N_aliases)
    pub fn i_aliases(&self, ino: Ino) -> Vec<Arc<Dentry>> {
        self.icache.lock().get(&ino)
            .map(|e| e.aliases.iter().filter_map(Weak::upgrade).collect())
            .unwrap_or_default()
    }

    /// `evict_inodes` (Linux fs/inode.c, run from `generic_shutdown_super`):
    /// sweep the per-SB inode cache evicting every inode with no remaining
    /// reference. In this `Weak`-keyed icache a referenceless inode is one whose
    /// `Weak::upgrade` already fails (Linux `i_count == 0`); its slot — and any
    /// dead alias `Weak`s — are dropped. Returns the count of BUSY inodes:
    /// slots whose inode still upgrades, i.e. a live reference outlived the
    /// unmount (Linux's "VFS: Busy inodes after unmount" WARN). A clean unmount
    /// returns `0`. Busy slots are retained, not force-freed: their owners drop
    /// them on their own ref release. # C: O(N_ino)
    pub fn evict_inodes(&self) -> u32 {
        let mut busy = 0u32;
        self.icache.lock().retain(|_, e| {
            if e.inode.upgrade().is_some() { busy += 1; true } else { false }
        });
        busy
    }

}
