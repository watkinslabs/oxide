use super::*;
extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use std::sync::Arc;
use std::thread;

fn leak_arr(base_pfn: u64, count: usize) -> PageMetaArr {
    let v: Vec<PageMeta> = (0..count).map(|_| PageMeta::new()).collect();
    let s: &'static [PageMeta] = Box::leak(v.into_boxed_slice());
    PageMetaArr::new(base_pfn, s)
}

#[test]
fn new_empty() {
    let a = leak_arr(0, 0);
    assert!(a.is_empty()); assert_eq!(a.len(), 0); assert!(a.get(Pfn(0)).is_none());
}

#[test]
fn out_of_range_pfn_returns_none() {
    let a = leak_arr(100, 16);
    assert!(a.get(Pfn(99)).is_none()); assert!(a.get(Pfn(116)).is_none());
    assert!(a.get(Pfn(100)).is_some()); assert!(a.get(Pfn(115)).is_some());
}

#[test]
fn refcount_inc_dec_roundtrip() {
    let a = leak_arr(0, 8);
    assert_eq!(a.refcount(Pfn(3)), Some(0)); assert_eq!(a.inc_ref(Pfn(3)), Some(0));
    assert_eq!(a.refcount(Pfn(3)), Some(1)); assert_eq!(a.inc_ref(Pfn(3)), Some(1));
    assert_eq!(a.refcount(Pfn(3)), Some(2)); assert_eq!(a.dec_ref(Pfn(3)), Some(1));
    assert_eq!(a.dec_ref(Pfn(3)), Some(0)); assert_eq!(a.refcount(Pfn(3)), Some(0));
}

#[test]
fn flag_set_clear() {
    let a = leak_arr(0, 4);
    assert_eq!(a.flags(Pfn(0)), Some(PageFlags::empty()));
    a.set_flags(Pfn(0), PageFlags::DIRTY | PageFlags::REFERENCED).unwrap();
    assert!(a.flags(Pfn(0)).unwrap().contains(PageFlags::DIRTY));
    a.clear_flags(Pfn(0), PageFlags::DIRTY).unwrap();
    assert!(!a.flags(Pfn(0)).unwrap().contains(PageFlags::DIRTY));
}

#[test]
fn page_lock_has_one_winner_and_releases() {
    let a = leak_arr(0, 1); let page = Pfn(0);
    assert_eq!(a.try_lock_page(page), Some(true)); assert_eq!(a.try_lock_page(page), Some(false));
    assert_eq!(a.unlock_page(page), Some(true)); assert_eq!(a.unlock_page(page), Some(false));
    assert_eq!(a.try_lock_page(page), Some(true));
}

#[test]
fn mapping_pointer_swap() {
    let a = leak_arr(0, 4); let p1 = 0xdead_beef as *mut (); let p2 = 0x1234_5678 as *mut ();
    assert_eq!(a.mapping(Pfn(2)), Some(core::ptr::null_mut()));
    assert_eq!(a.set_mapping(Pfn(2), p1), Some(core::ptr::null_mut())); assert_eq!(a.mapping(Pfn(2)), Some(p1));
    assert_eq!(a.set_mapping(Pfn(2), p2), Some(p1)); assert_eq!(a.mapping(Pfn(2)), Some(p2));
}

#[test]
fn concurrent_inc_dec_preserves_count() {
    let a: &'static PageMetaArr = Box::leak(Box::new(leak_arr(0, 1))); let arc = Arc::new(a); let mut hs = Vec::new();
    for _ in 0..8 { let arc = Arc::clone(&arc); hs.push(thread::spawn(move || for _ in 0..1_000 { arc.inc_ref(Pfn(0)); arc.dec_ref(Pfn(0)); })); }
    for h in hs { h.join().unwrap(); } assert_eq!(a.refcount(Pfn(0)), Some(0));
}

#[test]
fn refcount_only_affects_target_pfn() {
    let a = leak_arr(0, 4); a.inc_ref(Pfn(1)).unwrap(); a.inc_ref(Pfn(1)).unwrap(); a.inc_ref(Pfn(2)).unwrap();
    assert_eq!(a.refcount(Pfn(0)), Some(0)); assert_eq!(a.refcount(Pfn(1)), Some(2));
    assert_eq!(a.refcount(Pfn(2)), Some(1)); assert_eq!(a.refcount(Pfn(3)), Some(0));
}

#[test]
fn mapcount_inc_dec_roundtrip() {
    let a = leak_arr(0, 8); assert_eq!(a.mapcount(Pfn(5)), Some(0));
    assert_eq!(a.inc_map(Pfn(5)), Some(0)); assert_eq!(a.mapcount(Pfn(5)), Some(1));
    assert_eq!(a.inc_map(Pfn(5)), Some(1)); assert_eq!(a.mapcount(Pfn(5)), Some(2));
    assert_eq!(a.dec_map(Pfn(5)), Some(1)); assert_eq!(a.dec_map(Pfn(5)), Some(0));
    a.inc_ref(Pfn(5)).unwrap(); assert_eq!(a.refcount(Pfn(5)), Some(1)); assert_eq!(a.mapcount(Pfn(5)), Some(0));
}

#[test]
fn meta_size_matches_spec() {
    #[cfg(not(feature = "debug-watchdog"))]
    assert_eq!(core::mem::size_of::<PageMeta>(), 48);
    #[cfg(feature = "debug-watchdog")]
    assert_eq!(core::mem::size_of::<PageMeta>(), 56);
}

#[test]
fn pagetable_context_uses_mapping_slot_without_layout_growth() {
    let a = leak_arr(0, 1); let pfn = Pfn(0); let root_pa = 0x20_000u64;
    a.set_flags(pfn, PageFlags::PAGETABLE).unwrap(); a.set_mapping(pfn, root_pa as usize as *mut ()).unwrap();
    assert!(a.flags(pfn).unwrap().contains(PageFlags::PAGETABLE)); assert_eq!(a.mapping(pfn).unwrap() as usize as u64, root_pa);
    a.clear_flags(pfn, PageFlags::PAGETABLE).unwrap(); a.set_mapping(pfn, core::ptr::null_mut()).unwrap();
    assert!(!a.flags(pfn).unwrap().contains(PageFlags::PAGETABLE)); assert!(a.mapping(pfn).unwrap().is_null());
}
