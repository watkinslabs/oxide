// mlock-family VMA transitions: `apply_vma_lock_flags`, `apply_mlockall_flags`,
// `munlock_all`, and the fork/def_flags interactions. The behavior encoded here
// is the observable Linux contract for mlock(2)/mlock2(2)/munlock(2)/
// mlockall(2)/munlockall(2).

use super::*;
use crate::address_space::LockedSpan;

fn anon(a: &AddressSpace, at: u64, pages: u64) {
    a.mmap(Some(uva(at)), (pages * PAGE as u64) as usize, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
}

fn locked(a: &AddressSpace, at: u64) -> bool {
    a.find_vma(uva(at)).unwrap().flags.contains(VmaFlags::LOCKED)
}

fn onfault(a: &AddressSpace, at: u64) -> bool {
    a.find_vma(uva(at)).unwrap().flags.contains(VmaFlags::LOCKONFAULT)
}

const BASE: u64 = 0x4000_0000;

/// A whole-VMA lock reports one span covering the range and leaves the VMA
/// LOCKED without LOCKONFAULT.
#[test]
fn locking_a_full_vma_reports_one_span() {
    let a = AddressSpace::new(0).unwrap();
    anon(&a, BASE, 4);
    let out = a.apply_vma_lock_flags(uva(BASE), 4 * PAGE, VmaFlags::LOCKED);
    assert_eq!(out.error, None);
    assert_eq!(out.spans, alloc::vec![LockedSpan { start: uva(BASE), len: 4 * PAGE, onfault: false }]);
    assert!(locked(&a, BASE));
    assert!(!onfault(&a, BASE));
    a.audit().unwrap();
}

/// Locking a sub-range splits the VMA at both boundaries and locks only the
/// middle — mlock(2) must not extend past the bytes it was given.
#[test]
fn locking_a_subrange_splits_the_vma() {
    let a = AddressSpace::new(0).unwrap();
    anon(&a, BASE, 4);
    let out = a.apply_vma_lock_flags(uva(BASE + PAGE as u64), 2 * PAGE, VmaFlags::LOCKED);
    assert_eq!(out.error, None);
    assert_eq!(a.snapshot_vmas().len(), 3);
    assert!(!locked(&a, BASE));
    assert!(locked(&a, BASE + PAGE as u64));
    assert!(locked(&a, BASE + 2 * PAGE as u64));
    assert!(!locked(&a, BASE + 3 * PAGE as u64));
    a.audit().unwrap();
}

/// A hole inside the range is ENOMEM, but the VMAs BEFORE the hole stay
/// locked: Linux applies the transition VMA by VMA and does not roll back.
/// Reporting the error with nothing applied is the tempting-but-wrong shape.
#[test]
fn a_hole_is_enomem_with_the_leading_vmas_left_locked() {
    let a = AddressSpace::new(0).unwrap();
    anon(&a, BASE, 2);
    anon(&a, BASE + 3 * PAGE as u64, 2);  // one-page hole at BASE+2 pages
    let out = a.apply_vma_lock_flags(uva(BASE), 5 * PAGE, VmaFlags::LOCKED);
    assert_eq!(out.error, Some(Error::NoMem));
    assert!(locked(&a, BASE), "the VMA before the hole is locked");
    assert!(!locked(&a, BASE + 3 * PAGE as u64), "the walk stopped at the hole");
    assert_eq!(out.spans.len(), 1);
    a.audit().unwrap();
}

/// A range that starts in a hole is ENOMEM with nothing applied, and a range
/// that runs off the end of the last VMA is ENOMEM even though every VMA it
/// did reach was locked.
#[test]
fn holes_at_the_start_and_the_end_are_both_enomem() {
    let a = AddressSpace::new(0).unwrap();
    anon(&a, BASE + PAGE as u64, 2);
    let lead = a.apply_vma_lock_flags(uva(BASE), 3 * PAGE, VmaFlags::LOCKED);
    assert_eq!(lead.error, Some(Error::NoMem));
    assert!(lead.spans.is_empty());
    assert!(!locked(&a, BASE + PAGE as u64));

    let trail = a.apply_vma_lock_flags(uva(BASE + PAGE as u64), 3 * PAGE, VmaFlags::LOCKED);
    assert_eq!(trail.error, Some(Error::NoMem));
    assert!(locked(&a, BASE + PAGE as u64), "the mapped prefix is still locked");
}

/// mlock2(MLOCK_ONFAULT) sets both bits and marks the span on-fault so the
/// caller skips prefaulting. A plain mlock(2) over the same range must then
/// CLEAR LOCKONFAULT and hand back a populate-me span — the mask is replaced,
/// not OR'd, or a range could never be un-deferred.
#[test]
fn plain_mlock_clears_a_previous_onfault_marking() {
    let a = AddressSpace::new(0).unwrap();
    anon(&a, BASE, 2);
    let out = a.apply_vma_lock_flags(uva(BASE), 2 * PAGE, VmaFlags::LOCKED_MASK);
    assert_eq!(out.spans[0].onfault, true);
    assert!(locked(&a, BASE) && onfault(&a, BASE));

    let out = a.apply_vma_lock_flags(uva(BASE), 2 * PAGE, VmaFlags::LOCKED);
    assert_eq!(out.error, None);
    assert_eq!(out.spans[0].onfault, false);
    assert!(locked(&a, BASE) && !onfault(&a, BASE));
    a.audit().unwrap();
}

/// munlock clears both bits and reports no spans to populate.
#[test]
fn munlock_clears_the_whole_locked_mask() {
    let a = AddressSpace::new(0).unwrap();
    anon(&a, BASE, 2);
    a.apply_vma_lock_flags(uva(BASE), 2 * PAGE, VmaFlags::LOCKED_MASK);
    let out = a.apply_vma_lock_flags(uva(BASE), 2 * PAGE, VmaFlags::empty());
    assert_eq!(out.error, None);
    assert!(out.spans.is_empty());
    assert!(!locked(&a, BASE) && !onfault(&a, BASE));
    a.audit().unwrap();
}

/// Device / raw-PFN mappings (Linux VM_SPECIAL) never take VM_LOCKED, and a
/// range spanning one is NOT an error — the special VMA is skipped and the rest
/// of the range still locks. Rejecting it would make `mlockall(MCL_CURRENT)`
/// fail for any process with a framebuffer mapped.
#[test]
fn special_mappings_are_skipped_not_rejected() {
    let a = AddressSpace::new(0).unwrap();
    anon(&a, BASE, 1);
    a.mmap(Some(uva(BASE + PAGE as u64)), PAGE, r_w(), priv_anon(),
        VmaBacking::PhysRange {
            base_pa: 0x1000_0000,
            cache: PhysCacheMode::Device,
        }, true).unwrap();
    anon(&a, BASE + 2 * PAGE as u64, 1);
    let out = a.apply_vma_lock_flags(uva(BASE), 3 * PAGE, VmaFlags::LOCKED);
    assert_eq!(out.error, None);
    assert!(locked(&a, BASE));
    assert!(!locked(&a, BASE + PAGE as u64), "VM_SPECIAL never takes VM_LOCKED");
    assert!(locked(&a, BASE + 2 * PAGE as u64));
    assert_eq!(out.spans.len(), 2, "only the lockable halves are populated");
}

/// An empty range succeeds without touching anything; Linux checks
/// `end == start` before it even loads a VMA, so an empty range in unmapped
/// space is success, not ENOMEM.
#[test]
fn an_empty_range_succeeds_even_in_unmapped_space() {
    let a = AddressSpace::new(0).unwrap();
    let out = a.apply_vma_lock_flags(uva(BASE), 0, VmaFlags::LOCKED);
    assert_eq!(out.error, None);
    assert!(out.spans.is_empty());
}

/// mlockall(MCL_CURRENT) locks every existing VMA; mlockall(MCL_FUTURE) alone
/// touches none of them and only installs the policy.
#[test]
fn mlockall_current_locks_everything_future_alone_locks_nothing() {
    let a = AddressSpace::new(0).unwrap();
    anon(&a, BASE, 1);
    anon(&a, BASE + 4 * PAGE as u64, 1);
    let spans = a.apply_mlockall_flags(false, true, false);
    assert_eq!(spans.len(), 2);
    assert!(locked(&a, BASE) && locked(&a, BASE + 4 * PAGE as u64));

    let b = AddressSpace::new(0).unwrap();
    anon(&b, BASE, 1);
    let spans = b.apply_mlockall_flags(true, false, false);
    assert!(spans.is_empty());
    assert!(!locked(&b, BASE));
    assert_eq!(b.mlock_future_policy(), (true, false));
}

/// The MCL_FUTURE policy is rewritten UNCONDITIONALLY, so a later
/// `mlockall(MCL_CURRENT)` — which does not name MCL_FUTURE — clears it.
/// Linux documents that repeated mlockall calls do not stack.
#[test]
fn mlockall_without_mcl_future_clears_an_earlier_future_policy() {
    let a = AddressSpace::new(0).unwrap();
    a.apply_mlockall_flags(true, false, true);
    assert_eq!(a.mlock_future_policy(), (true, true));
    a.apply_mlockall_flags(false, true, false);
    assert_eq!(a.mlock_future_policy(), (false, false));
}

/// An MCL_FUTURE|MCL_ONFAULT policy propagates BOTH bits into VMAs created
/// afterwards, so those mappings are locked but not prefaulted.
#[test]
fn future_onfault_policy_lands_on_later_mappings() {
    let a = AddressSpace::new(0).unwrap();
    a.apply_mlockall_flags(true, false, true);
    anon(&a, BASE, 1);
    assert!(locked(&a, BASE) && onfault(&a, BASE));

    a.apply_mlockall_flags(true, false, false);
    anon(&a, BASE + 2 * PAGE as u64, 1);
    let at = BASE + 2 * PAGE as u64;
    assert!(locked(&a, at) && !onfault(&a, at));
}

/// munlockall drops the future policy AND clears both bits everywhere,
/// including a range that was only mlock2(MLOCK_ONFAULT)'d.
#[test]
fn munlockall_clears_current_state_and_future_policy() {
    let a = AddressSpace::new(0).unwrap();
    anon(&a, BASE, 1);
    anon(&a, BASE + 4 * PAGE as u64, 1);
    a.apply_vma_lock_flags(uva(BASE), PAGE, VmaFlags::LOCKED_MASK);
    a.apply_mlockall_flags(true, false, true);
    let cleared = a.munlock_all();
    assert_eq!(cleared.len(), 1, "only the locked VMA needed clearing");
    assert!(!locked(&a, BASE) && !onfault(&a, BASE));
    assert_eq!(a.mlock_future_policy(), (false, false));
    a.audit().unwrap();
}

/// fork(2) does NOT inherit locked state: the child's VMAs come back with both
/// bits clear even though the parent had mlockall(MCL_CURRENT|MCL_ONFAULT)
/// applied. Inheriting it would let a process multiply its locked footprint
/// past RLIMIT_MEMLOCK by forking.
#[test]
fn fork_does_not_inherit_locked_vmas() {
    let parent = AddressSpace::new(0).unwrap();
    anon(&parent, BASE, 2);
    parent.apply_mlockall_flags(true, true, true);
    assert!(locked(&parent, BASE) && onfault(&parent, BASE));

    let child = parent.fork(0).unwrap();
    assert!(!locked(&child, BASE), "VM_LOCKED is not inherited across fork");
    assert!(!onfault(&child, BASE), "VM_LOCKONFAULT is not inherited across fork");
    assert_eq!(child.mlock_future_policy(), (false, false));
    assert_eq!(child.accounting_snapshot().locked_virtual_bytes, 0);
    assert!(locked(&parent, BASE), "the parent keeps its own locked state");
}

/// `locked_bytes_in_range` counts only the overlap, which is what keeps an
/// idempotent re-lock from being charged twice against RLIMIT_MEMLOCK.
#[test]
fn locked_bytes_in_range_counts_only_the_overlap() {
    let a = AddressSpace::new(0).unwrap();
    anon(&a, BASE, 4);
    a.apply_vma_lock_flags(uva(BASE), 2 * PAGE, VmaFlags::LOCKED);
    assert_eq!(a.locked_bytes_in_range(uva(BASE), 4 * PAGE), 2 * PAGE as u64);
    assert_eq!(a.locked_bytes_in_range(uva(BASE + PAGE as u64), PAGE), PAGE as u64);
    assert_eq!(a.locked_bytes_in_range(uva(BASE + 2 * PAGE as u64), 2 * PAGE), 0);
}

/// `total_mapped_bytes` is the quantity mlockall(MCL_CURRENT) charges against
/// RLIMIT_MEMLOCK, so it must track every VMA, locked or not.
#[test]
fn total_mapped_bytes_sums_every_vma() {
    let a = AddressSpace::new(0).unwrap();
    assert_eq!(a.total_mapped_bytes(), 0);
    anon(&a, BASE, 3);
    anon(&a, BASE + 8 * PAGE as u64, 2);
    assert_eq!(a.total_mapped_bytes(), 5 * PAGE as u64);
}

/// Locked bytes are accounted as the flags move, in both directions — the
/// number `do_mlock` compares against RLIMIT_MEMLOCK comes from here.
#[test]
fn locked_accounting_follows_the_flag_transitions() {
    let a = AddressSpace::new(0).unwrap();
    anon(&a, BASE, 4);
    assert_eq!(a.accounting_snapshot().locked_virtual_bytes, 0);
    a.apply_vma_lock_flags(uva(BASE), 2 * PAGE, VmaFlags::LOCKED);
    assert_eq!(a.accounting_snapshot().locked_virtual_bytes, 2 * PAGE as u64);
    a.apply_vma_lock_flags(uva(BASE), 4 * PAGE, VmaFlags::LOCKED);
    assert_eq!(a.accounting_snapshot().locked_virtual_bytes, 4 * PAGE as u64);
    a.munlock_all();
    assert_eq!(a.accounting_snapshot().locked_virtual_bytes, 0);
}
