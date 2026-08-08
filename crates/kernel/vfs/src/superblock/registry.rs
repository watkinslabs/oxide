extern crate alloc;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, Superblock as SbClass};
use super::SuperBlock;
use crate::types::KResult;

/// Anonymous block-dev minor allocator — the single monotonically-increasing
/// minor source shared by BOTH the per-instance anon `s_dev`
/// ([`next_anon_dev`]) AND the per-pseudo-fs-identity `st_dev` registry
/// ([`crate::getattr::st_dev_for_fsid`]), so no two filesystems ever land on
/// the same `(0, minor)` regardless of which path allocated it. Minor 0 is
/// reserved, so the first fs gets `(0, 1)`. # C: O(1)
static ANON_MINOR: AtomicU32 = AtomicU32::new(1);

/// Allocate one fresh anon-bdev minor from the shared `unnamed_dev_ida`
/// counter. # C: O(1)
pub(crate) fn alloc_anon_minor() -> u32 { ANON_MINOR.fetch_add(1, Ordering::Relaxed) }

/// Allocate a fresh anonymous block-dev number for a filesystem with no real
/// backing device, as a REAL anon `dev_t`: major 0, a unique minor
/// (`MKDEV(0, minor)`). Each mounted instance
/// gets a distinct `s_dev` so two `mount -t tmpfs` report different `st_dev`
/// (what a per-fs-type constant cannot express), AND the value is now a genuine
/// `dev_t` — `huge_encode_dev(s_dev)` is the `st_dev` userspace sees, not an
/// opaque hashed number. # C: O(1)
pub fn next_anon_dev() -> u64 {
    crate::devnode::mkdev(0, alloc_anon_minor()) as u64
}

/// Global registry of every live `SuperBlock` instance, held by `Weak` so it
/// never keeps an SB alive past its last reference. [`sget`] scans this to SHARE an existing
/// instance for the same backing device instead of building a duplicate. # C: O(1)
static FS_SUPERS: Spinlock<Vec<Weak<SuperBlock>>, SbClass> = Spinlock::new(Vec::new());

/// Snapshot of the registry — every live registered superblock
/// instance (dead `Weak`s skipped). # C: O(N_sb)
pub fn fs_supers() -> Vec<Arc<SuperBlock>> {
    FS_SUPERS.lock().iter().filter_map(Weak::upgrade).collect()
}

/// `iterate_supers`: run `f` over every REGISTERED superblock instance that is
/// still usable, in registration order.
///
/// This is the whole-system sweep `sync(2)` walks, and it is deliberately NOT
/// the mount table: an instance whose last mount has been lazily detached while
/// file descriptions remain open is still live, still dirty, and still owes its
/// backend a flush — walking mounts loses exactly that superblock.
///
/// The discipline is the reference's, and each part earns its place:
/// * the registry lock is held only to SNAPSHOT, never across `f`, because `f`
///   blocks on device I/O and a sweep that held the lock would serialise every
///   mount and unmount in the system behind it;
/// * upgrading the `Weak` takes the existence reference that keeps the instance
///   alive for the duration of the call, so a concurrent last-umount cannot free
///   it underneath `f`;
/// * a DYING or not-yet-published instance is skipped — no root dentry, or the
///   mounted flag already cleared by teardown — because its backend state is
///   being dismantled and a flush into it is at best wasted and at worst a use
///   of half-torn-down state;
/// * `f` runs under `s_umount` shared, the lock the per-superblock flush path
///   requires, so a remount cannot flip the instance between read-only and
///   read-write while it is being written back.
/// # C: O(N_sb x f)
pub fn iterate_supers(mut f: impl FnMut(&Arc<SuperBlock>)) {
    let live: Vec<Arc<SuperBlock>> = fs_supers();
    for sb in live.iter() {
        if !sb_iterable(sb.is_mounted(), sb.s_root().is_some()) { continue; }
        sb.with_s_umount_read(|| f(sb));
    }
}

/// Whether an instance in the registry is one a whole-system sweep may touch:
/// published (a root dentry exists) and not yet dismantled (still flagged
/// mounted). Split out from [`iterate_supers`] so the predicate is checkable on
/// its own. # C: O(1)
pub fn sb_iterable(mounted: bool, has_root: bool) -> bool { mounted && has_root }

/// Find a live superblock by backing `s_dev`. # C: O(N_sb)
pub fn sb_by_dev(dev: u64) -> Option<Arc<SuperBlock>> {
    FS_SUPERS.lock().iter().filter_map(Weak::upgrade).find(|sb| sb.s_dev == dev)
}

/// Register `sb` in the global superblock registry. Prunes dead `Weak`s and
/// de-dups an already-registered live instance on the way. # C: O(N_sb)
pub fn register_super(sb: &Arc<SuperBlock>) {
    let mut g = FS_SUPERS.lock();
    g.retain(|w| w.upgrade().map(|e| !Arc::ptr_eq(&e, sb)).unwrap_or(false));
    g.push(Arc::downgrade(sb));
}

/// Find-or-create a superblock for the backing
/// device `dev`. If a LIVE registered instance already serves `dev` AND is still
/// active ([`SuperBlock::grab_active`]), SHARE it: bump `s_count` and return it
/// (the caller owns one extra active ref to pair with `deactivate_super` at
/// umount). Otherwise `build()` a fresh instance, register it, and return it.
/// This is the dedup used by the mount table's device-backed fill-super path;
/// anonymous/pseudo filesystems still receive a fresh anon device. # C: O(N_sb)
pub fn sget_result(dev: u64, build: impl FnOnce() -> KResult<Arc<SuperBlock>>) -> KResult<Arc<SuperBlock>> {
    sget_reused(dev, build).map(|(sb, _)| sb)
}

/// [`sget_result`], plus the one fact the caller cannot recover afterwards:
/// whether the instance was REUSED or freshly built.
///
/// A caller that must not change a live instance's state — a second mount of
/// one device asking for a different read-only setting — needs the answer, and
/// inferring it from the returned flags cannot work: a fresh instance whose
/// fill-super neglected to stamp is indistinguishable from a reused one that
/// disagrees. `true` = reused. # C: O(N_sb)
pub fn sget_reused(dev: u64, build: impl FnOnce() -> KResult<Arc<SuperBlock>>)
    -> KResult<(Arc<SuperBlock>, bool)> {
    {
        let g = FS_SUPERS.lock();
        for w in g.iter() {
            if let Some(sb) = w.upgrade() {
                if sb.s_dev == dev && sb.grab_active() { sb.s_count_inc(); return Ok((sb, true)); }
            }
        }
    }
    let sb = build()?;
    register_super(&sb);
    Ok((sb, false))
}

/// Infallible compatibility wrapper for callers whose fill-super cannot fail.
/// # C: O(N_sb)
pub fn sget(dev: u64, build: impl FnOnce() -> Arc<SuperBlock>) -> Arc<SuperBlock> {
    match sget_result(dev, || Ok(build())) {
        Ok(sb) => sb,
        Err(_) => unreachable!(),
    }
}

// `s_flags` bits. User-visible mount RO/option
