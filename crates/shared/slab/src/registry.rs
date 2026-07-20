//! Registered `kmem_cache` identity and PMM shrinker bridge.
//!
//! The registry deliberately stores only a stable reference to a cache's
//! native state.  Page ownership, free lists, and byte lifecycle remain in
//! `Cache`; this module never maintains a second allocation ledger.

use alloc::vec::Vec;
use core::ops::{BitOr, BitOrAssign};

use pmm::shrinker::{self, Shrinker};
use pmm::PageBacking;
use sync::{CpuLocalSource, IrqGate, Spinlock, TaskList};

use crate::Cache;

/// Linux `SLAB_*` properties carried by a named cache.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct CacheFlags(u32);

impl CacheFlags {
    pub const NONE: Self = Self(0);
    /// Cache pages may be reclaimed by the slab shrinker.
    pub const RECLAIM_ACCOUNT: Self = Self(1 << 0);
    /// Charge the concrete PMM pages to the cache's allocation memcg.
    pub const ACCOUNT: Self = Self(1 << 1);

    /// # C: O(1)
    pub const fn contains(self, flag: Self) -> bool { self.0 & flag.0 == flag.0 }
}

impl BitOr for CacheFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output { Self(self.0 | rhs.0) }
}

impl BitOrAssign for CacheFlags {
    fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
}

/// Canonical read-only cache observation.  `slab_pages` and `idle_pages`
/// come directly from the registered cache's PMM-backed page lists.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CacheSnapshot {
    pub cache_id: u32,
    pub name: &'static str,
    pub flags: CacheFlags,
    pub object_bytes: u16,
    pub allocated_objects: u64,
    pub slab_pages: u32,
    pub idle_pages: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RegistryError { Duplicate, NoMem }

#[derive(Copy, Clone)]
struct Entry {
    cache_id: u32,
    name: &'static str,
    flags: CacheFlags,
    object_bytes: u16,
    context: *const (),
    snapshot: unsafe fn(*const ()) -> CacheSnapshot,
    scan: unsafe fn(*const (), usize) -> usize,
}

// SAFETY: entries only point at `'static Cache` values accepted by register.
unsafe impl Send for Entry {}
// SAFETY: callbacks use Cache's own synchronization; registry copies entries.
unsafe impl Sync for Entry {}

static CACHES: Spinlock<Vec<Entry>, TaskList> = Spinlock::new(Vec::new());

/// Register a cache after placing it in stable kernel-lifetime storage.
/// `Cache` remains the sole owner of pages and accounting; registry is an
/// enumeration and shrinker dispatch table. # C: O(number of caches)
pub fn register<T, B: PageBacking, I: IrqGate, S: CpuLocalSource>(
    cache: &'static Cache<T, B, I, S>,
) -> Result<(), RegistryError> {
    let mut entries = CACHES.lock();
    if entries.iter().any(|entry| entry.cache_id == cache.cache_id()) {
        return Err(RegistryError::Duplicate);
    }
    entries.try_reserve(1).map_err(|_| RegistryError::NoMem)?;
    entries.push(Entry {
        cache_id: cache.cache_id(), name: cache.name(), flags: cache.flags(), object_bytes: cache.layout().obj_size,
        context: cache as *const Cache<T, B, I, S> as *const (),
        snapshot: cache_snapshot::<T, B, I, S>, scan: cache_scan::<T, B, I, S>,
    });
    Ok(())
}

/// Enumerate actual registered cache state. # C: O(number of caches)
pub fn snapshots() -> Vec<CacheSnapshot> {
    let entries = { CACHES.lock().clone() };
    entries.into_iter().map(|entry| {
        // SAFETY: register requires a kernel-lifetime Cache; callback restores
        // its exact concrete type and only takes synchronized observations.
        let state = unsafe { (entry.snapshot)(entry.context) };
        CacheSnapshot {
            cache_id: entry.cache_id, name: entry.name, flags: entry.flags,
            object_bytes: entry.object_bytes, allocated_objects: state.allocated_objects,
            slab_pages: state.slab_pages, idle_pages: state.idle_pages,
        }
    }).collect()
}

/// Install the single slab shrinker into PMM.  Duplicate installation is
/// benign because PMM identifies callback pairs. # C: O(number of caches)
pub fn register_shrinker() -> Result<(), RegistryError> {
    match shrinker::register_shrinker(Shrinker { count_objects: reclaimable_pages, scan_objects: scan_reclaimable }) {
        Ok(()) | Err(shrinker::ShrinkerError::Duplicate) => Ok(()),
        Err(shrinker::ShrinkerError::NoMem) => Err(RegistryError::NoMem),
    }
}

fn reclaimable_pages() -> usize {
    let entries = { CACHES.lock().clone() };
    entries.into_iter().filter(|entry| entry.flags.contains(CacheFlags::RECLAIM_ACCOUNT)).map(|entry| {
        // SAFETY: see snapshots; idle_pages is cache-native drained-page state.
        unsafe { (entry.snapshot)(entry.context).idle_pages as usize }
    }).sum()
}

fn scan_reclaimable(target: usize) -> usize {
    let entries = { CACHES.lock().clone() };
    let mut released = 0usize;
    for entry in entries.into_iter().filter(|entry| entry.flags.contains(CacheFlags::RECLAIM_ACCOUNT)) {
        let Some(remaining) = target.checked_sub(released) else { break; };
        if remaining == 0 { break; }
        // SAFETY: see snapshots; the cache serializes its own drain list.
        released = released.saturating_add(unsafe { (entry.scan)(entry.context, remaining) });
    }
    released
}

unsafe fn cache_snapshot<T, B: PageBacking, I: IrqGate, S: CpuLocalSource>(context: *const ()) -> CacheSnapshot {
    // SAFETY: context was formed from this exact Cache instantiation by register.
    let cache = unsafe { &*(context as *const Cache<T, B, I, S>) };
    CacheSnapshot {
        cache_id: cache.cache_id(), name: cache.name(), flags: cache.flags(),
        object_bytes: cache.layout().obj_size, allocated_objects: cache.allocated(),
        slab_pages: cache.total_slabs(), idle_pages: cache.idle_slabs(),
    }
}

unsafe fn cache_scan<T, B: PageBacking, I: IrqGate, S: CpuLocalSource>(context: *const (), target: usize) -> usize {
    // SAFETY: context was formed from this exact Cache instantiation by register.
    let cache = unsafe { &*(context as *const Cache<T, B, I, S>) };
    cache.release_idle_slabs(target)
}
