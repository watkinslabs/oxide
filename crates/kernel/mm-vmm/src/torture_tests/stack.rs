use super::*;

/// `RLIM_INFINITY` translated into the byte caps `try_grow_stack` applies —
/// the rlimit tests are exercised separately, below.
const NO_CAP: u64 = u64::MAX;

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
    assert!(a.try_grow_stack(fault_va, NO_CAP, NO_CAP), "extend within guard");
    let v = a.find_vma(fault_va).expect("VMA now covers fault");
    assert_eq!(v.start.as_u64(), 0x4000_1000);
    assert_eq!(v.end.as_u64(), stack_top);
}

#[test]
fn growsdown_rejects_beyond_guard_gap() {
    let a = AddressSpace::new(0).unwrap();
    let stack_start = uva(0x4000_0000);
    a.mmap(Some(stack_start), 4 * PAGE, r_w(),
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS | VmaFlags::GROWSDOWN,
        VmaBacking::Anonymous, true).unwrap();
    // D32: v1 grow-cap = 8 MiB (RLIMIT_STACK default). A fault
    // beyond that is treated as a wild pointer, not a deep stack
    // frame. Pre-D32 cap was 64 KiB — dhcpcd's musl-init wide
    // frame (~140 KiB on first resolver call) tripped it.
    let fault_va = uva(0x3000_0000); // 0x1000_0000 below = 256 MiB
    assert!(!a.try_grow_stack(fault_va, NO_CAP, NO_CAP), "beyond cap rejects");
    assert!(a.find_vma(fault_va).is_none());
}

/// Linux `acct_stack_growth`: `if (size > rlimit(RLIMIT_STACK)) return -ENOMEM`,
/// where `size` is the WHOLE post-growth VMA (`vm_end - address`) — not the
/// increment. A 4-page stack under a 4-page limit cannot take a fifth page.
#[test]
fn growsdown_refuses_past_the_stack_size_cap() {
    let a = AddressSpace::new(0).unwrap();
    let stack_start = uva(0x4000_2000);
    a.mmap(Some(stack_start), 4 * PAGE, r_w(),
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS | VmaFlags::GROWSDOWN,
        VmaBacking::Anonymous, true).unwrap();
    let fault_va = uva(0x4000_1000);
    let four_pages = 4 * PAGE as u64;
    assert!(!a.try_grow_stack(fault_va, four_pages, NO_CAP),
        "the whole 5-page VMA is over a 4-page RLIMIT_STACK");
    assert!(a.find_vma(fault_va).is_none());
    assert!(a.try_grow_stack(fault_va, 5 * PAGE as u64, NO_CAP),
        "a limit that admits the whole post-growth VMA grows it");
    assert_eq!(a.find_vma(fault_va).unwrap().start.as_u64(), 0x4000_1000);
}

/// Linux `acct_stack_growth`'s first test, `may_expand_vm(mm, …, grow)`: the
/// INCREMENT is what RLIMIT_AS charges, so a mm with no address-space headroom
/// left cannot grow its stack even when RLIMIT_STACK is generous.
#[test]
fn growsdown_refuses_without_address_space_headroom() {
    let a = AddressSpace::new(0).unwrap();
    let stack_start = uva(0x4000_2000);
    a.mmap(Some(stack_start), 4 * PAGE, r_w(),
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS | VmaFlags::GROWSDOWN,
        VmaBacking::Anonymous, true).unwrap();
    let fault_va = uva(0x4000_1000);
    assert!(!a.try_grow_stack(fault_va, NO_CAP, 0), "no headroom, no growth");
    assert!(!a.try_grow_stack(fault_va, NO_CAP, PAGE as u64 - 1));
    assert!(a.try_grow_stack(fault_va, NO_CAP, PAGE as u64),
        "one page of headroom buys exactly one page of stack");
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
    assert!(!a.try_grow_stack(fault_va, NO_CAP, NO_CAP));
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
    assert!(!a.try_grow_stack(fault_va, NO_CAP, NO_CAP));
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

// ---------------------------------------------------------------
// PROT_NONE enforcement — every access kind must be denied
// ---------------------------------------------------------------

#[test]
fn prot_none_denies_read_write_exec() {
    use crate::vma::FaultAccess;
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), PAGE, VmaProt::empty(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    let v = a.find_vma(h).unwrap();
    assert!(!v.permits(FaultAccess::Read));
    assert!(!v.permits(FaultAccess::Write));
    assert!(!v.permits(FaultAccess::Exec));
}

#[test]
fn prot_x_only_denies_read_and_write() {
    use crate::vma::FaultAccess;
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), PAGE, VmaProt::EXEC, priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    let v = a.find_vma(h).unwrap();
    assert!(!v.permits(FaultAccess::Read));
    assert!(!v.permits(FaultAccess::Write));
    assert!(v.permits(FaultAccess::Exec));
}

#[test]
fn prot_r_only_denies_write_and_exec() {
    use crate::vma::FaultAccess;
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), PAGE, VmaProt::READ, priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    let v = a.find_vma(h).unwrap();
    assert!(v.permits(FaultAccess::Read));
    assert!(!v.permits(FaultAccess::Write));
    assert!(!v.permits(FaultAccess::Exec));
}

// ---------------------------------------------------------------
// Mremap shrink / no-op / grow MAYMOVE preserves data semantics
// ---------------------------------------------------------------

#[test]
fn munmap_idempotent_on_already_torn_down() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 2 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.munmap(h, 2 * PAGE).unwrap();
    // Second munmap of the same range — Linux returns 0.
    a.munmap(h, 2 * PAGE).unwrap();
    assert_eq!(a.vma_count(), 0);
}

#[test]
fn growsdown_within_one_page_of_lower_neighbor() {
    // Lower neighbor at [0x4000_0000, 0x4000_1000); stack at
    // [0x4000_2000, 0x4000_3000). Fault at 0x4000_1000 — exactly
    // adjacent — extension would go to 0x4000_1000 which is the
    // lower neighbor's end. Allowed (touching, not overlapping).
    let a = AddressSpace::new(0).unwrap();
    a.mmap(Some(uva(0x4000_0000)), PAGE, VmaProt::READ, priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.mmap(Some(uva(0x4000_2000)), PAGE, r_w(),
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS | VmaFlags::GROWSDOWN,
        VmaBacking::Anonymous, true).unwrap();
    let fault = uva(0x4000_1000);
    assert!(a.try_grow_stack(fault, NO_CAP, NO_CAP), "abutting extension allowed");
}

// ---------------------------------------------------------------
// VmaProt -> page-flags translation
// ---------------------------------------------------------------

#[test]
fn page_flags_carry_user_bit_always() {
    use hal::PageFlags;
    let pf = VmaProt::empty().to_page_flags();
    assert!(pf.contains(PageFlags::USER), "USER bit always set on user VMA");
    let pf2 = (VmaProt::READ | VmaProt::WRITE | VmaProt::EXEC).to_page_flags();
    assert!(pf2.contains(PageFlags::USER));
    assert!(pf2.contains(PageFlags::READ));
    assert!(pf2.contains(PageFlags::WRITE));
    assert!(pf2.contains(PageFlags::EXEC));
}

// ---------------------------------------------------------------
// Maximum churn at fragmentation extreme
// ---------------------------------------------------------------

#[test]
fn fragmentation_extreme_recovery() {
    // Allocate, free every other, alloc again — verify allocator
    // recovers the freed slots.
    let a = AddressSpace::new(0).unwrap();
    let mut allocated: alloc::vec::Vec<UserVirtAddr> = alloc::vec::Vec::new();
    for _ in 0..256 {
        let v = a.mmap(None, PAGE, r_w(), priv_anon(),
            VmaBacking::Anonymous, false).unwrap();
        allocated.push(v);
    }
    // Free every other.
    let n = allocated.len();
    for i in (0..n).rev().step_by(2) {
        let v = allocated.remove(i);
        a.munmap(v, PAGE).unwrap();
    }
    // Alloc 128 more — should fit.
    for _ in 0..128 {
        let v = a.mmap(None, PAGE, r_w(), priv_anon(),
            VmaBacking::Anonymous, false).unwrap();
        allocated.push(v);
    }
    a.audit().unwrap();
}
