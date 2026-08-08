// mseal(2) VMA-state torture tests: what sealing marks, and — the part that
// is the security contract — which operations a sealed range then refuses.
// Argument validation lives in `crate::mseal`; this file is the enforcement.

use super::*;

#[test]
fn mseal_marks_whole_vma() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert!(!a.range_sealed(h, 4 * PAGE));
    a.mseal_range(h, uva(0x4000_4000)).unwrap();
    assert!(a.range_sealed(h, 4 * PAGE));
    a.audit().unwrap();
}

#[test]
fn mseal_partial_range_splits_and_seals_middle_only() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.mseal_range(uva(0x4000_1000), uva(0x4000_3000)).unwrap();  // seal middle 2 pages
    assert!(a.range_sealed(uva(0x4000_1000), 2 * PAGE));
    assert!(!a.range_sealed(h, PAGE));                 // first page unsealed
    assert!(!a.range_sealed(uva(0x4000_3000), PAGE));  // last page unsealed
    a.audit().unwrap();
}

#[test]
fn mseal_hole_rejected() {
    let a = AddressSpace::new(0).unwrap();
    assert!(a.mseal_range(uva(0x4000_0000), uva(0x4000_1000)).is_err());  // unmapped → ENOMEM
}

/// mseal(2) is a security primitive, so the operations it must BLOCK are the
/// contract. Linux blocks munmap, mmap(MAP_FIXED) over the
/// range (same gather path), mprotect and mremap — all with EPERM.
///
/// Pre-F763 the MAP_FIXED leg was OPEN: `glue_mmap` discarded `glue_munmap`'s
/// EPERM and `mmap_with_may(fixed)` called `remove_range` unconditionally, so
/// a sealed .text mapping could be replaced wholesale. This test fails against
/// that code.
#[test]
fn a_sealed_range_refuses_munmap_and_map_fixed_replacement() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true).unwrap();
    a.mseal_range(h, uva(0x4000_4000)).unwrap();

    assert_eq!(a.munmap(h, 4 * PAGE), Err(crate::Error::Perm), "munmap of a sealed range");
    assert_eq!(a.munmap(uva(0x4000_1000), PAGE), Err(crate::Error::Perm),
        "partial munmap inside a sealed range");
    assert_eq!(a.mmap(Some(h), PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true),
        Err(crate::Error::Perm), "MAP_FIXED must not replace a sealed mapping");
    // The mapping is still there, unchanged.
    assert!(a.range_sealed(h, 4 * PAGE));
    assert_eq!(a.find_vma(h).map(|v| v.end.as_u64()), Some(0x4000_4000));
    a.audit().unwrap();
}

/// A MAP_FIXED that only touches unsealed neighbours still works — the seal
/// must not become a blanket ban on the whole address space.
#[test]
fn map_fixed_next_to_a_sealed_range_still_works() {
    let a = AddressSpace::new(0).unwrap();
    a.mmap(Some(uva(0x4000_0000)), 2 * PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true).unwrap();
    a.mmap(Some(uva(0x4000_2000)), 2 * PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true).unwrap();
    a.mseal_range(uva(0x4000_0000), uva(0x4000_2000)).unwrap();
    a.mmap(Some(uva(0x4000_2000)), 2 * PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true).unwrap();
    a.munmap(uva(0x4000_2000), 2 * PAGE).unwrap();
    assert!(a.range_sealed(uva(0x4000_0000), 2 * PAGE));
    a.audit().unwrap();
}

/// Sealing twice is a no-op success, and there is no unseal.
#[test]
fn sealing_an_already_sealed_range_succeeds() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 2 * PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true).unwrap();
    a.mseal_range(h, uva(0x4000_2000)).unwrap();
    a.mseal_range(h, uva(0x4000_2000)).unwrap();
    a.mseal_range(uva(0x4000_1000), uva(0x4000_2000)).unwrap();
    assert!(a.range_sealed(h, 2 * PAGE));
    a.audit().unwrap();
}
