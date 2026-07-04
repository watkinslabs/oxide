// Dentry flag constants. Numeric values live here so `dentry.rs` stays focused
// on object state and lifecycle logic.

/// `d_flags` bits (Linux `include/linux/dcache.h` subset).
pub const D_ROOT:       u32 = 0x0001; // this dentry is a superblock root
pub const D_NEGATIVE:   u32 = 0x0002; // d_inode == None
pub const D_HASHED:     u32 = 0x0004; // present in the global dentry_hashtable
pub const D_REFERENCED: u32 = 0x0008; // recently used — LRU two-hand-clock bit
pub const D_LRU:        u32 = 0x0010; // currently linked on the dcache LRU
pub const D_DISCONNECTED: u32 = 0x0020; // anonymous (parentless) alias, on s_anon
/// Drop this dentry the instant it goes unused — Linux `DCACHE_DONTCACHE`
/// (`d_mark_dontcache`, propagated from `I_DONTCACHE`). `retain_dentry` returns
/// false for it, so the final `dput` `dentry_kill`s instead of LRU-caching;
/// repeated lookups of a `DONTCACHE` name therefore never accumulate idle
/// dentries (DAX / on-demand fs that want their inodes evicted promptly).
pub const D_DONTCACHE:  u32 = 0x1000;
/// An in-flight PARALLEL lookup is resolving this (parent,name) — Linux
/// `DCACHE_PAR_LOOKUP` (`d_alloc_parallel`). Set on the placeholder dentry the
/// LEADER walker installs in the in-lookup table before it runs the slow
/// `i_op->lookup`; concurrent walkers for the SAME key find the placeholder and
/// wait on this bit instead of each constructing + racing their own. Cleared by
/// `d_lookup_done` (Linux `__d_lookup_done`) once the leader publishes the
/// resolved (positive or cached-negative) dentry, after which the bit-clear is
/// the waiters' wake condition. Bit position is this file's own layout.
pub const D_PAR_LOOKUP:  u32 = 0x4000;
/// A filesystem is mounted on this dentry — Linux `DCACHE_MOUNTED`. A single
/// REFCOUNTED hint bit (set when the dentry's `struct mountpoint` `m_count`
/// goes 0→1 in [`crate::mntns::get_mountpoint`], cleared on the last drop in
/// [`crate::mntns::put_mountpoint`]) that lets the path walk skip the mount
/// hash for the overwhelmingly common non-mountpoint dentry. ns-AGNOSTIC: the
/// per-ns covering identity comes from the mount hash keyed by the walk's
/// current `mnt_id`, not from this bit. Bit position is this file's own layout.
pub const D_MOUNTED:     u32 = 0x0001_0000;

// ---------------------------------------------------------------------------
// DCACHE_OP_* — `d_op` presence cache, stamped into `d_flags` at construction
// from the inherited `d_op` vector (Linux `d_set_d_op`). Each bit records that
// the corresponding `d_op` hook is non-NULL so the hot path can branch on a
// `d_flags` bit WITHOUT dereferencing `d_op` and probing the `Option` hook:
// `__d_lookup` tests `parent->d_flags & DCACHE_OP_COMPARE` before calling
// `d_compare`; `dput`/`dentry_kill` test `DCACHE_OP_DELETE` before `d_delete`.
// Bit positions are this file's own layout (the rest of `d_flags` already
// diverges from Linux's numeric bits — see the `D_ROOT..D_DISCONNECTED` block).
// Every dcache-exposed hook gets a presence bit; the only `dentry_operations`
// members WITHOUT a hook here are the mount-trigger pair (`d_automount`/
// `d_manage`, mount-coupled) and overlayfs `d_real`.
// ---------------------------------------------------------------------------
/// `d_op->d_hash` present (Linux `DCACHE_OP_HASH`).
pub const D_OP_HASH:       u32 = 0x0040;
/// `d_op->d_compare` present (Linux `DCACHE_OP_COMPARE`).
pub const D_OP_COMPARE:    u32 = 0x0080;
/// `d_op->d_revalidate` present (Linux `DCACHE_OP_REVALIDATE`).
pub const D_OP_REVALIDATE: u32 = 0x0100;
/// `d_op->d_delete` present (Linux `DCACHE_OP_DELETE`).
pub const D_OP_DELETE:     u32 = 0x0200;
/// `d_op->d_dname` present (Linux `DCACHE_OP_DNAME`) — the dentry renders its
/// OWN path string dynamically (pipefs `pipe:[ino]`, sockfs `socket:[ino]`,
/// anon-inode `[name]`), so `d_path`/`dentry_path` must NOT parent-walk it.
pub const D_OP_DNAME:      u32 = 0x0400;
/// `d_op->d_prune` present (Linux `DCACHE_OP_PRUNE`). `__dentry_kill` tests
/// this bit before firing `d_prune` on a dentry about to leave the cache, so
/// the eviction hot path skips the `d_op` deref for the common no-prune fs.
pub const D_OP_PRUNE:      u32 = 0x0800;
/// `d_op->d_weak_revalidate` present (Linux `DCACHE_OP_WEAK_REVALIDATE`).
/// `complete_walk` tests this on the FINAL path component (post-jump, e.g. a
/// `..`/procfs-symlink hop that changed mount) before the one-shot weak
/// revalidation, so the check stays off the per-component hot path.
pub const D_OP_WEAK_REVALIDATE: u32 = 0x2000;
/// All `d_op` presence bits (cleared together before a re-stamp).
pub const D_OP_MASK: u32 = D_OP_HASH | D_OP_COMPARE | D_OP_REVALIDATE | D_OP_DELETE | D_OP_DNAME | D_OP_PRUNE | D_OP_WEAK_REVALIDATE;

// ---------------------------------------------------------------------------
// DCACHE_ENTRY_TYPE — cached inode type, stamped into `d_flags` the moment an
// inode is associated (`build` / `set_inode`). Linux keeps these so the hot
// path (`d_is_dir` in the walker, `d_is_symlink` before a symlink follow)
// branches on the dentry WITHOUT read-locking + dereferencing `d_inode`.
// Layout mirrors Linux `include/linux/dcache.h`: the type occupies bits 20..22
// (`7 << 20`), `MISS == 0` so a negative dentry's type field is naturally clear.
// ---------------------------------------------------------------------------
/// Mask selecting the cached-type field (Linux `DCACHE_ENTRY_TYPE`).
pub const D_TYPE_MASK:      u32 = 0x0070_0000;
/// Negative dentry — no inode (Linux `DCACHE_MISS_TYPE`).
pub const D_MISS_TYPE:      u32 = 0x0000_0000;
/// Directory (Linux `DCACHE_DIRECTORY_TYPE`).
pub const D_DIRECTORY_TYPE: u32 = 0x0020_0000;
/// Regular file (Linux `DCACHE_REGULAR_TYPE`).
pub const D_REGULAR_TYPE:   u32 = 0x0040_0000;
/// char/block/fifo/socket (Linux `DCACHE_SPECIAL_TYPE`).
pub const D_SPECIAL_TYPE:   u32 = 0x0050_0000;
/// Symlink (Linux `DCACHE_SYMLINK_TYPE`).
pub const D_SYMLINK_TYPE:   u32 = 0x0060_0000;
