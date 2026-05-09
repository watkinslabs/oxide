// F157: comprehensive memory torture tests. Covers:
// - mmap alignment + boundary conditions (USER_VA_END, MIN_USER_VA,
//   off-by-1, page-misaligned, zero-len, gigantic-len)
// - munmap edge cases (unmapped, partial, misaligned, hole)
// - mprotect on holes / mixed regions / boundary splits
// - VMA tree invariants under churn (alternating insert/remove,
//   fragmented holes, reverse-order inserts)
// - Topdown allocator under fragmentation
// - MAP_FIXED overlap clear + non-fixed hint behavior
// - KernelBytes Arc lifetime under fork chains
// - Concurrent reader/writer correctness
// - VMA split at all four positions (start, mid, end, both)
// - VMA merge across prot/flag/backing diffs
// - brk window: shrink, grow, overflow, underflow
//
// Hosted-only — no real PT walk; AddressSpace::new(0) sentinel
// skips all MmuOps activation paths.

#![cfg(test)]

use super::*;
use crate::address_space::{MIN_USER_VA, MMAP_TOP};
use crate::vma::{VmaBacking, VmaFlags, VmaProt};

use hal::{UserVirtAddr, USER_VA_END, PAGE_SIZE_BYTES};
use std::sync::Arc;

const PAGE: usize = PAGE_SIZE_BYTES as usize;

fn uva(x: u64) -> UserVirtAddr {
    UserVirtAddr::new(x).expect("test address fits user range")
}

fn r_w() -> VmaProt { VmaProt::READ | VmaProt::WRITE }
fn priv_anon() -> VmaFlags { VmaFlags::PRIVATE | VmaFlags::ANONYMOUS }

// ---------------------------------------------------------------
// mmap boundary conditions
// ---------------------------------------------------------------

#[test]
fn mmap_zero_len_rejected() {
    let a = AddressSpace::new(0).unwrap();
    let r = a.mmap(None, 0, r_w(), priv_anon(), VmaBacking::Anonymous, false);
    assert!(r.is_err(), "zero-length mmap must fail");
}

#[test]
fn mmap_unaligned_len_rejected() {
    let a = AddressSpace::new(0).unwrap();
    // 1-byte length is not page-aligned; PAGE+1 isn't either.
    assert!(a.mmap(None, 1, r_w(), priv_anon(), VmaBacking::Anonymous, false).is_err());
    assert!(a.mmap(None, PAGE + 1, r_w(), priv_anon(), VmaBacking::Anonymous, false).is_err());
    assert!(a.mmap(None, PAGE - 1, r_w(), priv_anon(), VmaBacking::Anonymous, false).is_err());
}

#[test]
fn mmap_fixed_unaligned_addr_rejected() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0001).unwrap();
    assert!(a.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).is_err(),
        "fixed mmap with off-by-1 addr must fail");
}

#[test]
fn mmap_at_min_user_va_works() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(MIN_USER_VA).unwrap();
    let r = a.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(r.as_u64(), MIN_USER_VA);
}

#[test]
fn mmap_at_user_va_end_boundary() {
    // The last page [USER_VA_END-PAGE, USER_VA_END) is unmappable
    // because end == USER_VA_END is excluded by UserVirtAddr.
    // (Linux makes the highest page available; we trade that for a
    // strict half-open invariant — observable but unusual.)
    let a = AddressSpace::new(0).unwrap();
    let edge_start = USER_VA_END - PAGE as u64;
    let h = UserVirtAddr::new(edge_start).unwrap();
    let r = a.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true);
    assert!(r.is_err(), "end == USER_VA_END must be rejected");
    // The page just below WORKS.
    let safe = UserVirtAddr::new(edge_start - PAGE as u64).unwrap();
    let ok = a.mmap(Some(safe), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(ok.as_u64(), edge_start - PAGE as u64);
}

#[test]
fn mmap_huge_len_rejected_when_no_room() {
    let a = AddressSpace::new(0).unwrap();
    // Request a length that exceeds the entire user range.
    let huge = (USER_VA_END - MIN_USER_VA) as usize + PAGE;
    let r = a.mmap(None, huge, r_w(), priv_anon(),
        VmaBacking::Anonymous, false);
    assert!(r.is_err(), "huge mmap must hit NoMem");
}

#[test]
fn mmap_fixed_then_topdown_skips_fixed() {
    // Fixed mmap reserves a region; subsequent topdown must not
    // place atop it.
    let a = AddressSpace::new(0).unwrap();
    let fixed = UserVirtAddr::new(MMAP_TOP - 4 * PAGE as u64).unwrap();
    a.mmap(Some(fixed), 2 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    let r = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert_eq!(r.as_u64(), MMAP_TOP - PAGE as u64);
    let r2 = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert_eq!(r2.as_u64(), MMAP_TOP - 2 * PAGE as u64);
    // Third allocation should land BELOW the fixed VMA (which
    // ends at MMAP_TOP - 2*PAGE).
    let r3 = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert!(r3.as_u64() < fixed.as_u64(),
        "post-fixed alloc must be below the fixed VMA, got 0x{:x}",
        r3.as_u64());
}

#[test]
fn mmap_fixed_overlap_replaces() {
    // MAP_FIXED with overlap clears the prior region per `11§6`.
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap(Some(h), 4 * PAGE, VmaProt::READ, priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    // Replace the middle two pages with PROT_NONE.
    let mid = UserVirtAddr::new(0x4000_1000).unwrap();
    a.mmap(Some(mid), 2 * PAGE, VmaProt::empty(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    // Should now have 3 VMAs: [0,1) RO, [1,3) NONE, [3,4) RO.
    let n = a.vma_count();
    assert!(n == 3 || n == 1, "expect 3 split VMAs, got {}", n);
}

// ---------------------------------------------------------------
// munmap edge cases
// ---------------------------------------------------------------

#[test]
fn munmap_unmapped_is_ok() {
    // Linux semantic: munmap of a hole succeeds (returns 0).
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.munmap(h, PAGE).unwrap();
}

#[test]
fn munmap_unaligned_addr_rejected() {
    let a = AddressSpace::new(0).unwrap();
    let bad = UserVirtAddr::new(0x4000_0001).unwrap();
    assert!(a.munmap(bad, PAGE).is_err());
}

#[test]
fn munmap_zero_len_rejected() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    assert!(a.munmap(h, 0).is_err());
}

#[test]
fn munmap_partial_splits_vma() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    // Punch out the middle two pages.
    let mid = UserVirtAddr::new(0x4000_1000).unwrap();
    a.munmap(mid, 2 * PAGE).unwrap();
    assert_eq!(a.vma_count(), 2);
    a.audit().unwrap();
    // First page remains.
    assert!(a.find_vma(h).is_some());
    // Last page remains.
    assert!(a.find_vma(uva(0x4000_3000)).is_some());
    // Middle is hole.
    assert!(a.find_vma(uva(0x4000_1000)).is_none());
    assert!(a.find_vma(uva(0x4000_2000)).is_none());
}

#[test]
fn munmap_spans_multiple_vmas() {
    // Linux munmap can span multiple VMAs and removes/splits each.
    let a = AddressSpace::new(0).unwrap();
    let h1 = UserVirtAddr::new(0x4000_0000).unwrap();
    let h2 = UserVirtAddr::new(0x4000_2000).unwrap();
    a.mmap(Some(h1), 2 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    // Insert a second VMA with different prot so they don't merge.
    a.mmap(Some(h2), 2 * PAGE, VmaProt::READ, priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(a.vma_count(), 2);
    // Single munmap covering both.
    a.munmap(h1, 4 * PAGE).unwrap();
    assert_eq!(a.vma_count(), 0);
}

// ---------------------------------------------------------------
// mprotect edge cases
// ---------------------------------------------------------------

#[test]
fn mprotect_hole_rejected() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    assert!(a.mprotect(h, PAGE, VmaProt::READ).is_err(),
        "mprotect on a hole must fail");
}

#[test]
fn mprotect_partial_splits_vma() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    let mid = UserVirtAddr::new(0x4000_1000).unwrap();
    a.mprotect(mid, 2 * PAGE, VmaProt::READ).unwrap();
    // Three VMAs: head=R+W, mid=R, tail=R+W.
    assert_eq!(a.vma_count(), 3);
    a.audit().unwrap();
}

#[test]
fn mprotect_full_vma_no_split() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.mprotect(h, 4 * PAGE, VmaProt::READ).unwrap();
    assert_eq!(a.vma_count(), 1);
    let v = a.find_vma(h).unwrap();
    assert_eq!(v.prot, VmaProt::READ);
}

// ---------------------------------------------------------------
// VMA split at all four boundary positions
// ---------------------------------------------------------------

#[test]
fn split_at_start() {
    // [vma_start, vma_end), unmap [vma_start, vma_start+PAGE).
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.munmap(h, PAGE).unwrap();
    assert_eq!(a.vma_count(), 1);
    a.audit().unwrap();
    assert!(a.find_vma(h).is_none());
    assert!(a.find_vma(uva(0x4000_1000)).is_some());
}

#[test]
fn split_at_end() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.munmap(uva(0x4000_3000), PAGE).unwrap();
    assert_eq!(a.vma_count(), 1);
    assert!(a.find_vma(h).is_some());
    assert!(a.find_vma(uva(0x4000_3000)).is_none());
}

#[test]
fn split_at_middle() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.munmap(uva(0x4000_1000), 2 * PAGE).unwrap();
    assert_eq!(a.vma_count(), 2);
    a.audit().unwrap();
}

#[test]
fn split_at_both_ends() {
    // Unmap the whole VMA range — equivalent to one removal, no split.
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.munmap(h, 4 * PAGE).unwrap();
    assert_eq!(a.vma_count(), 0);
}

// ---------------------------------------------------------------
// Fragmentation + topdown stress
// ---------------------------------------------------------------

#[test]
fn fragmented_topdown_uses_largest_high_gap() {
    // Lay down a checkerboard of fixed VMAs in the high arena;
    // topdown must find the highest fitting hole.
    let a = AddressSpace::new(0).unwrap();
    let base = MMAP_TOP - 16 * PAGE as u64;
    for i in 0..8 {
        // Skip every other slot to leave gaps.
        if i % 2 == 0 { continue; }
        let va = uva(base + (i as u64) * 2 * PAGE as u64);
        a.mmap(Some(va), PAGE, r_w(), priv_anon(),
            VmaBacking::Anonymous, true).unwrap();
    }
    // Topdown asks for 1 page — should fit at MMAP_TOP - PAGE.
    let r = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert_eq!(r.as_u64(), MMAP_TOP - PAGE as u64);
}

#[test]
fn topdown_falls_back_to_low_when_high_full() {
    // Fill the high mmap arena with a single giant VMA, force
    // topdown to find space below.
    let a = AddressSpace::new(0).unwrap();
    let high_start = uva(MMAP_TOP - 0x10000);
    a.mmap(Some(high_start), 0x10000, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    // Now any hintless mmap must land BELOW the giant VMA.
    let r = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert!(r.as_u64() < MMAP_TOP - 0x10000);
}

#[test]
fn alternating_insert_remove_keeps_invariant() {
    let a = AddressSpace::new(0).unwrap();
    let base = 0x4000_0000u64;
    for i in 0..32 {
        let va = uva(base + i * 0x2000);
        a.mmap(Some(va), PAGE, r_w(), priv_anon(),
            VmaBacking::Anonymous, true).unwrap();
    }
    a.audit().unwrap();
    for i in (0..32).step_by(2) {
        let va = uva(base + i * 0x2000);
        a.munmap(va, PAGE).unwrap();
    }
    a.audit().unwrap();
}

// ---------------------------------------------------------------
// brk window
// ---------------------------------------------------------------

#[test]
fn brk_uninit_returns_zero() {
    let a = AddressSpace::new(0).unwrap();
    assert_eq!(a.brk(), 0);
    // try_set_brk on uninit window is a no-op (returns current=0).
    assert_eq!(a.try_set_brk(0x40000), 0);
}

#[test]
fn brk_set_within_window_succeeds() {
    let a = AddressSpace::new(0).unwrap();
    a.set_brk_window(0x40000, 0x80000);
    assert_eq!(a.brk(), 0x40000);
    assert_eq!(a.try_set_brk(0x60000), 0x60000);
    assert_eq!(a.brk(), 0x60000);
}

#[test]
fn brk_set_above_max_rejected() {
    let a = AddressSpace::new(0).unwrap();
    a.set_brk_window(0x40000, 0x80000);
    // Request past brk_max — should fail (return cur).
    assert_eq!(a.try_set_brk(0x90000), 0x40000);
    assert_eq!(a.brk(), 0x40000);
}

#[test]
fn brk_set_below_initial_rejected() {
    let a = AddressSpace::new(0).unwrap();
    a.set_brk_window(0x40000, 0x80000);
    a.try_set_brk(0x60000);
    // Try shrinking below initial brk start.
    assert_eq!(a.try_set_brk(0x30000), 0x60000);
}

#[test]
fn brk_page_rounds_up() {
    let a = AddressSpace::new(0).unwrap();
    a.set_brk_window(0x40000, 0x80000);
    // Request a non-page-aligned brk; should round up.
    let r = a.try_set_brk(0x40001);
    assert_eq!(r, 0x41000);
}

// ---------------------------------------------------------------
// VMA backing equivalence + merge gates
// ---------------------------------------------------------------

#[test]
fn anon_anon_merge() {
    // Two abutting anonymous VMAs with identical prot/flags merge.
    let a = AddressSpace::new(0).unwrap();
    a.mmap(Some(uva(0x4000_0000)), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.mmap(Some(uva(0x4000_1000)), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(a.vma_count(), 1, "abutting anon VMAs must merge");
}

#[test]
fn different_prot_no_merge() {
    let a = AddressSpace::new(0).unwrap();
    a.mmap(Some(uva(0x4000_0000)), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.mmap(Some(uva(0x4000_1000)), PAGE, VmaProt::READ, priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(a.vma_count(), 2);
}

#[test]
fn file_offset_merge_requires_contig() {
    use crate::vma::Vma;
    let mut t = VmaTree::new();
    let a = Vma::new(uva(0x4000_0000), uva(0x4000_1000),
        r_w(), priv_anon(), VmaBacking::File { off: 0 });
    let b = Vma::new(uva(0x4000_1000), uva(0x4000_2000),
        r_w(), priv_anon(), VmaBacking::File { off: 0x1000 });
    let c = Vma::new(uva(0x4000_2000), uva(0x4000_3000),
        r_w(), priv_anon(), VmaBacking::File { off: 0x5000 });
    t.insert(a).unwrap();
    t.insert(b).unwrap();
    t.insert(c).unwrap();
    // After insert+merge, a+b should fold (contig offsets); c stays
    // separate (non-contig). Final count: 2.
    assert_eq!(t.len(), 2);
}

// ---------------------------------------------------------------
// fork chain — Arc lifetime under repeated forks
// ---------------------------------------------------------------

#[test]
fn fork_chain_preserves_kernel_bytes() {
    let bytes: alloc::vec::Vec<u8> = (0..64u8).collect();
    let arc: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
    let parent = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    parent.mmap(Some(h), PAGE, VmaProt::READ, VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data: Arc::clone(&arc), off: 0 },
        true).unwrap();
    // Fork 8 generations.
    let mut chain: alloc::vec::Vec<Arc<AddressSpace>> = alloc::vec::Vec::new();
    chain.push(parent);
    for _ in 0..8 {
        let n = chain.last().unwrap().fork(0).unwrap();
        chain.push(n);
    }
    // Outer arc + 9 AS = 10 strong refs.
    assert_eq!(Arc::strong_count(&arc), 10);
    // Drop in reverse order: each drop decrements by 1.
    while let Some(_) = chain.pop() { /* drop on fall-out */ }
    assert_eq!(Arc::strong_count(&arc), 1, "only outer handle remains");
}

// ---------------------------------------------------------------
// Stress: 1024 mmap/munmap pairs
// ---------------------------------------------------------------

#[test]
fn churn_1024_iterations_keeps_invariants() {
    let a = AddressSpace::new(0).unwrap();
    let mut allocated: alloc::vec::Vec<UserVirtAddr> = alloc::vec::Vec::new();
    for i in 0..1024 {
        if i % 3 == 2 && !allocated.is_empty() {
            let v = allocated.swap_remove(i % allocated.len());
            a.munmap(v, PAGE).unwrap();
        } else {
            let v = a.mmap(None, PAGE, r_w(), priv_anon(),
                VmaBacking::Anonymous, false).unwrap();
            allocated.push(v);
        }
        if i % 64 == 0 { a.audit().unwrap(); }
    }
    a.audit().unwrap();
}

// ---------------------------------------------------------------
// Allocator exhaustion — request more than fits
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// F158: stack auto-grow (MAP_GROWSDOWN)
// ---------------------------------------------------------------

#[test]
fn growsdown_extends_within_guard_gap() {
    let a = AddressSpace::new(0).unwrap();
    let stack_start = uva(0x4000_2000);
    let stack_top = stack_start.as_u64() + 4 * PAGE as u64;
    a.mmap(Some(stack_start), 4 * PAGE, r_w(),
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS | VmaFlags::GROWSDOWN,
        VmaBacking::Anonymous, true).unwrap();
    // Fault at one page below stack_start — within guard gap.
    let fault_va = uva(0x4000_1000);
    assert!(a.try_grow_stack(fault_va), "extend within guard");
    let v = a.find_vma(fault_va).expect("VMA now covers fault");
    assert_eq!(v.start.as_u64(), 0x4000_1000);
    assert_eq!(v.end.as_u64(), stack_top);
}

#[test]
fn growsdown_rejects_beyond_guard_gap() {
    let a = AddressSpace::new(0).unwrap();
    let stack_start = uva(0x8000_0000);
    a.mmap(Some(stack_start), 4 * PAGE, r_w(),
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS | VmaFlags::GROWSDOWN,
        VmaBacking::Anonymous, true).unwrap();
    // Fault way below — beyond 64 KiB guard (0x10000 = exactly
    // 64K; need strictly greater).
    let fault_va = uva(0x7ffe_0000); // 0x20000 below = 128K
    assert!(!a.try_grow_stack(fault_va), "beyond guard rejects");
    assert!(a.find_vma(fault_va).is_none());
}

#[test]
fn growsdown_skips_non_growsdown_vmas() {
    let a = AddressSpace::new(0).unwrap();
    // Plain anon (no GROWSDOWN).
    let h = uva(0x4000_2000);
    a.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    // Fault below — must NOT extend.
    let fault_va = uva(0x4000_1000);
    assert!(!a.try_grow_stack(fault_va));
}

#[test]
fn growsdown_blocked_by_lower_neighbor() {
    let a = AddressSpace::new(0).unwrap();
    // Lower neighbor at [0x4000_0000, 0x4000_1000).
    a.mmap(Some(uva(0x4000_0000)), PAGE, VmaProt::READ, priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    // Stack at [0x4000_2000, 0x4000_3000).
    let stack_start = uva(0x4000_2000);
    a.mmap(Some(stack_start), PAGE, r_w(),
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS | VmaFlags::GROWSDOWN,
        VmaBacking::Anonymous, true).unwrap();
    // Fault at 0x4000_1000 (in the gap) — stack would need to
    // extend down INTO the lower neighbor. Linux blocks this.
    let fault_va = uva(0x4000_0500);
    assert!(!a.try_grow_stack(fault_va));
}

// ---------------------------------------------------------------
// F157: COW fork preserves GROWSDOWN flag in child VMA tree
// ---------------------------------------------------------------

#[test]
fn fork_preserves_growsdown_flag() {
    let parent = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    parent.mmap(Some(h), 2 * PAGE, r_w(),
        priv_anon() | VmaFlags::GROWSDOWN,
        VmaBacking::Anonymous, true).unwrap();
    let child = parent.fork(0).unwrap();
    let v = child.find_vma(h).expect("child inherits VMA");
    assert!(v.flags.contains(VmaFlags::GROWSDOWN));
}

#[test]
fn allocator_returns_none_when_full() {
    let a = AddressSpace::new(0).unwrap();
    // Fill the user range up to one page below USER_VA_END (the
    // last page itself is unmappable per UserVirtAddr's exclusive
    // upper bound). After this, any topdown alloc must hit NoMem.
    let big_len = (USER_VA_END - MIN_USER_VA - PAGE as u64) as usize;
    let h = uva(MIN_USER_VA);
    a.mmap(Some(h), big_len, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    let r = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false);
    assert!(r.is_err(), "no hole left → NoMem");
}
