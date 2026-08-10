//! The reaper's rules, proved without a kthread, a page table or a boot.

use alloc::sync::Arc;

use hal::UserVirtAddr;
use vmm::{FileBackingError, PhysCacheMode, Vma, VmaBacking, VmaFlags, VmaProt};

use super::*;

/// An ordinary file. `huge_page_size` defaults to zero, which is what makes it
/// an ordinary one.
struct PlainFile;
/// A hugetlbfs file: its mappings install block leaves owned by the huge-page
/// pool.
struct HugeFile;

impl vmm::FileBacking for PlainFile {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { 0 }
}

impl vmm::FileBacking for HugeFile {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { 0 }
    fn huge_page_size(&self) -> u64 { 2 << 20 }
}

fn plain_file() -> VmaBacking { VmaBacking::File { backing: Arc::new(PlainFile), off: 0 } }
fn huge_file() -> VmaBacking { VmaBacking::File { backing: Arc::new(HugeFile), off: 0 } }

const PRIVATE: VmaFlags = VmaFlags::PRIVATE;
const SHARED: VmaFlags = VmaFlags::SHARED;
const PRIVATE_ANON: VmaFlags = VmaFlags::PRIVATE.union(VmaFlags::ANONYMOUS);

#[test]
fn private_anonymous_memory_is_what_the_reaper_is_for() {
    assert!(reapable(PRIVATE_ANON, &VmaBacking::Anonymous));
}

#[test]
fn a_shared_mapping_is_never_reaped_however_it_is_backed() {
    // It is somebody else's memory as much as the victim's. Anonymous shared
    // memory is the trap here: the backing says "anonymous" while the flag
    // says the pages outlive this process.
    assert!(!reapable(SHARED | VmaFlags::ANONYMOUS, &VmaBacking::Anonymous));
    assert!(!reapable(SHARED, &plain_file()));
    assert!(!reapable(SHARED | VmaFlags::SYSVSHM, &VmaBacking::Anonymous));
}

#[test]
fn a_private_file_mapping_is_reaped_like_the_reference_reaps_it() {
    // Not just anonymous memory: everything private. Its pages are either COW
    // copies the victim owns outright or clean cache pages that come back from
    // the backing store.
    assert!(reapable(PRIVATE, &plain_file()));
    assert!(reapable(PRIVATE, &VmaBacking::KernelBytes { data: Arc::from(&[0u8][..]), off: 0 }));
}

#[test]
fn a_device_range_is_left_alone() {
    // No reclaimable frame stands behind it, and its leaves are installed
    // without a reference the reaper could drop.
    let dev = VmaBacking::PhysRange { base_pa: 0x1000, cache: PhysCacheMode::WriteCombine };
    assert!(!reapable(PRIVATE, &dev));
    assert!(!reapable(SHARED, &dev));
}

#[test]
fn kernel_owned_pages_the_victim_merely_sees_are_left_alone() {
    assert!(!reapable(PRIVATE, &VmaBacking::KernelFrame { pa: 0x2000 }));
    assert!(!reapable(PRIVATE, &VmaBacking::Special));
}

#[test]
fn a_huge_mapping_is_left_alone_so_the_pool_is_not_shrunk() {
    // Its leaves are block leaves whose frames live in the huge-page pool; a
    // base-granule teardown would account one page and destroy the whole block.
    assert!(!reapable(PRIVATE, &huge_file()));
    // The rule is the huge backing, not the THP preference flag, which names
    // ordinary pages the reaper may take.
    assert!(reapable(PRIVATE | VmaFlags::HUGEPAGE, &VmaBacking::Anonymous));
}

#[test]
fn an_mlocked_private_mapping_is_still_reaped() {
    // The victim is dead; nothing is left that the lock is protecting, and
    // the reference reaps it. Skipping it would leave the largest process on a
    // memory-locking workload holding everything it owns.
    assert!(reapable(PRIVATE_ANON | VmaFlags::LOCKED, &VmaBacking::Anonymous));
}

#[test]
fn the_whole_descriptor_form_agrees_with_the_field_form() {
    let start = UserVirtAddr::new(0x1_0000).expect("user address");
    let end = UserVirtAddr::new(0x1_1000).expect("user address");
    let anon = Vma::new(start, end, VmaProt::READ, PRIVATE_ANON, VmaBacking::Anonymous);
    assert!(reapable_vma(&anon));
    let shared = Vma::new(start, end, VmaProt::READ, SHARED, plain_file());
    assert!(!reapable_vma(&shared));
}

#[test]
fn a_pass_that_released_memory_ends_the_reaping() {
    assert_eq!(after_attempt(1, true), ReapStep::Drained);
    assert!(ReapStep::Drained.marks_skippable());
}

#[test]
fn a_pass_that_released_nothing_is_retried_until_the_attempts_are_spent() {
    for attempts in 1..MAX_REAP_ATTEMPTS { assert_eq!(after_attempt(attempts, false), ReapStep::Retry); }
    assert!(!ReapStep::Retry.marks_skippable());
}

#[test]
fn an_mm_that_resists_every_attempt_is_written_off_not_waited_on() {
    // The row this whole module exists for: the terminal answer for a victim
    // that will not release anything is still to mark it skippable, because
    // the alternative is a selector that waits on it forever.
    assert_eq!(after_attempt(MAX_REAP_ATTEMPTS, false), ReapStep::GaveUp);
    assert_eq!(after_attempt(MAX_REAP_ATTEMPTS + 1, false), ReapStep::GaveUp);
    assert!(ReapStep::GaveUp.marks_skippable());
}

#[test]
fn the_grace_period_is_a_delay_not_a_poll() {
    // Every queued victim is due exactly one delay after it was queued, so the
    // kthread can sleep to that moment instead of waking to look.
    assert!(REAP_DELAY_NS > REAP_RETRY_NS);
    assert_eq!(REAP_DELAY_NS % 1_000_000, 0);
}
