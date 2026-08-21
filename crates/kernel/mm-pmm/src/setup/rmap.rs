//! Page mapping-owner publication and lookup.
//!
//! `PageMeta::mapping` is the sole rmap owner/type truth.  As Linux does for
//! `struct page->mapping`, its low alignment bit tags an anonymous mapping; an
//! untagged non-null pointer is a file mapping. A bounded owner-lock table
//! protects the complete tuple (tagged pointer, index, and rmap flags), while
//! the independent sleeping page lock remains reserved for I/O serialization.

use alloc::sync::Arc;

use sync::{AnonVma as AnonVmaClass, Guard, Spinlock};

use super::metadata::page_meta;

const ANON_RMAP_TAG: usize = 1;
const RMAP_TAG_MASK: usize = ANON_RMAP_TAG;
const OWNER_LOCKS: usize = 256;
static OWNER_LOCK: [Spinlock<(), AnonVmaClass>; OWNER_LOCKS] =
    [const { Spinlock::new(()) }; OWNER_LOCKS];

/// Page-owner serialization, ordered PageTable(20) -> AnonVma(25). This is a
/// spinlock because PTE removal holds the page-table spinlock; no holder may
/// sleep. Hash collisions serialize unrelated pages but never duplicate owner
/// state: `PageMeta::mapping` remains the sole truth.
pub(super) fn lock_owner(pfn: hal::Pfn) -> Guard<'static, (), AnonVmaClass> {
    OWNER_LOCK[pfn.0 as usize & (OWNER_LOCKS - 1)].lock()
}

enum PreviousOwner {
    None,
    Anon(*const vmm::AnonVma),
    File(*const vmm::FileRmap),
}

pub(super) struct DetachedOwner {
    owner: PreviousOwner,
    memcg: Option<u64>,
}

fn pfn(pa: u64) -> hal::Pfn { hal::Pfn(pa / hal::PAGE_SIZE_BYTES) }

fn anon_raw(raw: *const vmm::AnonVma) -> *mut () {
    let bits = raw as usize;
    assert!(bits & RMAP_TAG_MASK == 0, "rmap owner alignment");
    (bits | ANON_RMAP_TAG) as *mut ()
}

fn is_anon(raw: *mut ()) -> bool { (raw as usize & ANON_RMAP_TAG) != 0 }

fn untag(raw: *mut ()) -> *const () { (raw as usize & !RMAP_TAG_MASK) as *const () }

fn previous(raw: *mut ()) -> PreviousOwner {
    if raw.is_null() { PreviousOwner::None }
    else if is_anon(raw) { PreviousOwner::Anon(untag(raw) as *const vmm::AnonVma) }
    else { PreviousOwner::File(raw as *const vmm::FileRmap) }
}

unsafe fn drop_previous(owner: PreviousOwner) {
    match owner {
        PreviousOwner::None => {}
        // SAFETY: the detached raw pointer was installed by Arc::into_raw.
        PreviousOwner::Anon(raw) => unsafe { drop(Arc::from_raw(raw)); },
        // SAFETY: the detached tagged pointer was installed by Arc::into_raw.
        PreviousOwner::File(raw) => unsafe { drop(Arc::from_raw(raw)); },
    }
}

fn replace_locked(meta: &crate::PageMetaArr, pfn: hal::Pfn, raw: *mut (), index: u32) -> PreviousOwner {
    let old = meta.swap_mapping(pfn, raw).unwrap_or(core::ptr::null_mut());
    let _ = meta.set_page_index(pfn, index);
    previous(old)
}

fn detach_locked(meta: &crate::PageMetaArr, pfn: hal::Pfn) -> PreviousOwner {
    let old = meta.swap_mapping(pfn, core::ptr::null_mut()).unwrap_or(core::ptr::null_mut());
    let _ = meta.set_page_index(pfn, 0);
    previous(old)
}

/// Clone an anonymous owner while the caller holds the rmap owner lock.
fn clone_anon_locked(meta: &crate::PageMetaArr, pfn: hal::Pfn) -> Option<Arc<vmm::AnonVma>> {
    let raw = meta.mapping(pfn)?;
    if raw.is_null() || !is_anon(raw) { return None; }
    let owner = untag(raw) as *const vmm::AnonVma;
    // SAFETY: the caller's owner lock prevents detach/final drop until this clone owns a count.
    unsafe { Arc::increment_strong_count(owner); Some(Arc::from_raw(owner)) }
}

/// Clone a file owner while the caller holds the rmap owner lock.
fn clone_file_locked(meta: &crate::PageMetaArr, pfn: hal::Pfn) -> Option<Arc<vmm::FileRmap>> {
    let raw = meta.mapping(pfn)?;
    if raw.is_null() || is_anon(raw) { return None; }
    let owner = raw as *const vmm::FileRmap;
    // SAFETY: the caller's owner lock prevents detach/final drop until this clone owns a count.
    unsafe { Arc::increment_strong_count(owner); Some(Arc::from_raw(owner)) }
}

/// Install the sole anonymous rmap owner for `pa`.
///
/// # SAFETY: `pa` names a managed live frame whose caller owns its rmap edge.
/// # Ctx: process
/// # Sleeps: no
/// # C: O(1)
pub unsafe fn set_anon_rmap_for_pa(pa: u64, av: &Arc<vmm::AnonVma>, page_index: u32) {
    let Some(meta) = page_meta() else { return; };
    let pfn = pfn(pa);
    let old = {
        let _owner = lock_owner(pfn);
        let raw = anon_raw(Arc::into_raw(Arc::clone(av)));
        let old = replace_locked(meta, pfn, raw, page_index);
        let _ = meta.set_flags(pfn, crate::PageFlags::ANON | crate::PageFlags::ANON_EXCLUSIVE);
        old
    };
    // SAFETY: replace_locked detached the exact former Arc owner.
    unsafe { drop_previous(old); }
}

/// Install the sole file/shmem rmap owner for `pa`.
///
/// # SAFETY: `pa` names a managed live frame whose caller owns its rmap edge.
/// # Ctx: process
/// # Sleeps: no
/// # C: O(1)
pub unsafe fn set_file_rmap_for_pa(pa: u64, rmap: &Arc<vmm::FileRmap>, page_index: u32) {
    let Some(meta) = page_meta() else { return; };
    let pfn = pfn(pa);
    let old = {
        let _owner = lock_owner(pfn);
        let raw = Arc::into_raw(Arc::clone(rmap)) as *mut ();
        replace_locked(meta, pfn, raw, page_index)
    };
    // SAFETY: replace_locked detached the exact former Arc owner.
    unsafe { drop_previous(old); }
}

/// Clone the resident frame's canonical file rmap while the owner lock keeps
/// its raw Arc owner alive.
/// # Ctx: process
/// # Sleeps: no
/// # C: O(1)
pub fn file_rmap_for_pa(pa: u64) -> Option<Arc<vmm::FileRmap>> {
    let meta = page_meta()?;
    let pfn = pfn(pa);
    let _owner = lock_owner(pfn);
    clone_file_locked(meta, pfn)
}

/// Clone the resident frame's canonical anonymous rmap while the owner lock
/// keeps its raw Arc owner alive.
/// # Ctx: process
/// # Sleeps: no
/// # C: O(1)
pub fn anon_vma_for_pa(pa: u64) -> Option<Arc<vmm::AnonVma>> {
    let meta = page_meta()?;
    let pfn = pfn(pa);
    let _owner = lock_owner(pfn);
    clone_anon_locked(meta, pfn)
}

fn clear_locked(meta: &crate::PageMetaArr, pfn: hal::Pfn, file: bool) -> PreviousOwner {
    let raw = meta.mapping(pfn).unwrap_or(core::ptr::null_mut());
    let want_anon = !file;
    if raw.is_null() || is_anon(raw) != want_anon { return PreviousOwner::None; }
    detach_locked(meta, pfn)
}

/// Remove the anonymous rmap owner for a frame.
///
/// # SAFETY: caller owns the frame's anonymous rmap edge.
/// # Ctx: process
/// # Sleeps: no
/// # C: O(1)
pub unsafe fn clear_anon_rmap_for_pa(pa: u64) {
    let Some(meta) = page_meta() else { return; };
    let pfn = pfn(pa);
    let (old, was_anon, memcg) = {
        let _owner = lock_owner(pfn);
        let memcg = meta.memcg(pfn).unwrap_or(cgroup::NO_MEMCG);
        let old = clear_locked(meta, pfn, false);
        let was_anon = matches!(old, PreviousOwner::Anon(_));
        if was_anon { let _ = meta.set_memcg(pfn, cgroup::NO_MEMCG); }
        (old, was_anon, memcg)
    };
    // SAFETY: clear_locked detached the exact former Arc owner.
    unsafe { drop_previous(old); }
    if was_anon && memcg != cgroup::NO_MEMCG {
        cgroup::uncharge_memcg(memcg, hal::PAGE_SIZE_BYTES);
    }
}

/// Remove the file/shmem rmap owner for a frame.
///
/// # SAFETY: caller owns the frame's file rmap edge.
/// # Ctx: process
/// # Sleeps: no
/// # C: O(1)
pub unsafe fn clear_file_rmap_for_pa(pa: u64) {
    let Some(meta) = page_meta() else { return; };
    let pfn = pfn(pa);
    let old = {
        let _owner = lock_owner(pfn);
        clear_locked(meta, pfn, true)
    };
    // SAFETY: clear_locked detached the exact former Arc owner.
    unsafe { drop_previous(old); }
}

/// Remove whichever typed rmap owner is installed while the caller already
/// owns the rmap owner lock. # C: O(1)
pub(super) fn take_final_rmap_locked(meta: &crate::PageMetaArr, pfn: hal::Pfn) -> DetachedOwner {
    let memcg = meta.memcg(pfn).unwrap_or(cgroup::NO_MEMCG);
    let old = detach_locked(meta, pfn);
    let was_anon = matches!(old, PreviousOwner::Anon(_));
    if was_anon { let _ = meta.set_memcg(pfn, cgroup::NO_MEMCG); }
    DetachedOwner { owner: old, memcg: was_anon.then_some(memcg).filter(|id| *id != cgroup::NO_MEMCG) }
}

/// Drop a detached rmap owner after releasing its owner lock. # C: O(1)
pub(super) unsafe fn release_detached(owner: DetachedOwner) {
    // SAFETY: take_final_rmap_locked removed this exact Arc ownership under the owner lock.
    unsafe { drop_previous(owner.owner); }
    if let Some(memcg) = owner.memcg { cgroup::uncharge_memcg(memcg, hal::PAGE_SIZE_BYTES); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc as StdArc, Barrier};
    use std::thread;

    fn meta() -> crate::PageMetaArr {
        let pages = alloc::boxed::Box::leak(alloc::vec![crate::PageMeta::new()].into_boxed_slice());
        crate::PageMetaArr::new(0, pages)
    }

    #[test]
    fn tagged_owner_is_single_type_truth() {
        let meta = meta();
        let pfn = hal::Pfn(0);
        let anon = vmm::AnonVma::new();
        let file = vmm::FileRmap::new();
        let owner = lock_owner(pfn);
        let old = replace_locked(&meta, pfn, anon_raw(Arc::into_raw(Arc::clone(&anon))), 3);
        assert!(matches!(old, PreviousOwner::None));
        let anon_raw = meta.mapping(pfn).unwrap();
        assert!(is_anon(anon_raw));
        let old = replace_locked(&meta, pfn, Arc::into_raw(Arc::clone(&file)) as *mut (), 7);
        assert!(matches!(old, PreviousOwner::Anon(_)));
        let file_raw = meta.mapping(pfn).unwrap();
        assert!(!is_anon(file_raw));
        assert_eq!(meta.page_index(pfn), Some(7));
        let old = detach_locked(&meta, pfn);
        drop(owner);
        // SAFETY: both owners were detached exactly once by this test.
        unsafe { drop_previous(old); }
        // SAFETY: the replaced anonymous owner was detached exactly once.
        unsafe { drop_previous(PreviousOwner::Anon(untag(anon_raw) as *const vmm::AnonVma)); }
    }

    #[test]
    fn locked_clone_survives_final_detach() {
        let meta = meta();
        let pfn = hal::Pfn(0);
        let anon = vmm::AnonVma::new();

        let owner = lock_owner(pfn);
        let old = replace_locked(&meta, pfn, anon_raw(Arc::into_raw(Arc::clone(&anon))), 0);
        assert!(matches!(old, PreviousOwner::None));
        let retained = clone_anon_locked(&meta, pfn).expect("locked clone");
        drop(owner);

        let owner = lock_owner(pfn);
        let detached = detach_locked(&meta, pfn);
        drop(owner);
        // SAFETY: detach_locked transferred the raw slot reference exactly once.
        unsafe { drop_previous(detached); }

        // The clone acquired under the owner lock remains a valid independent owner
        // after final detach drops the PageMeta-held reference.
        assert_eq!(Arc::strong_count(&anon), 2);
        drop(anon);
        assert_eq!(Arc::strong_count(&retained), 1);
    }

    #[test]
    fn final_detach_excludes_a_concurrent_clone() {
        let meta: &'static crate::PageMetaArr = alloc::boxed::Box::leak(alloc::boxed::Box::new(meta()));
        let pfn = hal::Pfn(0);
        let anon = vmm::AnonVma::new();
        let owner = lock_owner(pfn);
        let old = replace_locked(meta, pfn, anon_raw(Arc::into_raw(Arc::clone(&anon))), 0);
        assert!(matches!(old, PreviousOwner::None));
        drop(owner);

        let entered = StdArc::new(Barrier::new(2));
        let reader_entered = StdArc::clone(&entered);
        let reader = thread::spawn(move || {
            reader_entered.wait();
            let owner = lock_owner(pfn);
            let clone = clone_anon_locked(meta, pfn);
            drop(owner);
            clone
        });

        let owner = lock_owner(pfn);
        let detached = detach_locked(meta, pfn);
        drop(owner);
        entered.wait();
        // Publishing null before unlock makes the reader's eventual lookup empty.
        // SAFETY: detach_locked transferred the raw slot reference exactly once.
        unsafe { drop_previous(detached); }
        assert!(reader.join().unwrap().is_none());
        assert_eq!(Arc::strong_count(&anon), 1);
    }

    #[test]
    fn rmap_owner_progress_is_independent_of_the_sleeping_page_lock() {
        let meta = meta();
        let pfn = hal::Pfn(0);
        assert_eq!(meta.try_lock_page(pfn), Some(true));
        {
            let _owner = lock_owner(pfn);
            assert!(meta.flags(pfn).unwrap().contains(crate::PageFlags::LOCKED),
                "owner transition must not consume the I/O page lock");
            let anon = vmm::AnonVma::new();
            let old = replace_locked(&meta, pfn,
                anon_raw(Arc::into_raw(Arc::clone(&anon))), 0);
            assert!(matches!(old, PreviousOwner::None));
            let detached = detach_locked(&meta, pfn);
            // SAFETY: this test detached the one raw owner it installed.
            unsafe { drop_previous(detached); }
        }
        assert_eq!(meta.unlock_page(pfn), Some(true));
    }
}
