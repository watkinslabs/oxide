extern crate alloc;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, Superblock as SbClass};
use super::SuperBlock;

/// `unnamed_dev_ida` minor allocator (Linux `fs/super.c` `get_anon_bdev`) —
/// the single monotonically-increasing minor source shared by BOTH the
/// per-instance anon `s_dev` ([`next_anon_dev`]) AND the per-pseudo-fs-identity
/// `st_dev` registry ([`crate::getattr::st_dev_for_fsid`]), so no two
/// filesystems ever land on the same `(0, minor)` regardless of which path
/// allocated it. Minor 0 is reserved (Linux skips it), so the first fs gets
/// `(0, 1)`. # C: O(1)
static ANON_MINOR: AtomicU32 = AtomicU32::new(1);

/// Allocate one fresh anon-bdev minor from the shared `unnamed_dev_ida`
/// counter. # C: O(1)
pub(crate) fn alloc_anon_minor() -> u32 { ANON_MINOR.fetch_add(1, Ordering::Relaxed) }

/// `get_anon_bdev` (Linux `fs/super.c`) — allocate a fresh anonymous block-dev
/// number for a filesystem with no real backing device, as a REAL Linux anon
/// `dev_t`: major 0, a unique minor (`MKDEV(0, minor)`). Each mounted instance
/// gets a distinct `s_dev` so two `mount -t tmpfs` report different `st_dev`
/// (what a per-fs-type constant cannot express), AND the value is now a genuine
/// `dev_t` — `huge_encode_dev(s_dev)` is the `st_dev` userspace sees, not an
/// opaque hashed number. # C: O(1)
pub fn next_anon_dev() -> u64 {
    crate::devnode::mkdev(0, alloc_anon_minor()) as u64
}

/// `super_blocks` (Linux `fs/super.c` global `super_blocks` list) — the registry
/// of every live `SuperBlock` instance, held by `Weak` so it never keeps an SB
/// alive past its last reference. [`sget`] scans this to SHARE an existing
/// instance for the same backing device instead of building a duplicate. # C: O(1)
static FS_SUPERS: Spinlock<Vec<Weak<SuperBlock>>, SbClass> = Spinlock::new(Vec::new());

/// `fs_supers`/`super_blocks` snapshot — every live registered superblock
/// instance (dead `Weak`s skipped). # C: O(N_sb)
pub fn fs_supers() -> Vec<Arc<SuperBlock>> {
    FS_SUPERS.lock().iter().filter_map(Weak::upgrade).collect()
}

/// Register `sb` in the global `fs_supers` list (Linux `fill_super` →
/// `list_add(&s->s_list, &super_blocks)`). Prunes dead `Weak`s and de-dups an
/// already-registered live instance on the way. # C: O(N_sb)
pub fn register_super(sb: &Arc<SuperBlock>) {
    let mut g = FS_SUPERS.lock();
    g.retain(|w| w.upgrade().map(|e| !Arc::ptr_eq(&e, sb)).unwrap_or(false));
    g.push(Arc::downgrade(sb));
}

/// `sget` (Linux `fs/super.c`) — find-or-create a superblock for the backing
/// device `dev`. If a LIVE registered instance already serves `dev` AND is still
/// active ([`SuperBlock::grab_active`]), SHARE it: bump `s_count` and return it
/// (the caller owns one extra active ref to pair with `deactivate_super` at
/// umount). Otherwise `build()` a fresh instance, register it, and return it.
/// This is the dedup the mount table's `next_anon_dev`-per-mount path lacks;
/// wiring `register`/`register_bind` (mount.rs, another lane) to call `sget`
/// instead of always `for_backend(next_anon_dev())` is the cross-lane
/// follow-up. # C: O(N_sb)
pub fn sget(dev: u64, build: impl FnOnce() -> Arc<SuperBlock>) -> Arc<SuperBlock> {
    {
        let g = FS_SUPERS.lock();
        for w in g.iter() {
            if let Some(sb) = w.upgrade() {
                if sb.s_dev == dev && sb.grab_active() { sb.s_count_inc(); return sb; }
            }
        }
    }
    let sb = build();
    register_super(&sb);
    sb
}

// `s_flags` bits (Linux include/linux/fs.h). User-visible mount RO/option
