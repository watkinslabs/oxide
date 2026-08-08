use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const TEST_START: u64 = 0x40_000;
const TEST_LEN: u64 = PAGE;

struct RecordedOps {
    pageout: Option<(u64, u64)>,
    evicted: bool,
}

impl MadviseOps for RecordedOps {
    fn evict_pages(&mut self, _start: u64, _len: u64) -> i64 {
        self.evicted = true;
        0
    }

    fn pageout_anon_pages(&mut self, start: u64, len: u64) -> i64 {
        self.pageout = Some((start, len));
        0
    }
}

fn anonymous_vma() -> vmm::Vma {
    let end = TEST_START + TEST_LEN;
    vmm::Vma::new(
        hal::UserVirtAddr::new(TEST_START).expect("test address is user canonical"),
        hal::UserVirtAddr::new(end).expect("test end is user canonical"),
        vmm::VmaProt::READ | vmm::VmaProt::WRITE,
        vmm::VmaFlags::PRIVATE | vmm::VmaFlags::ANONYMOUS,
        vmm::VmaBacking::Anonymous,
    )
}

struct SharedPageoutBacking {
    called: AtomicBool,
    off: AtomicU64,
    len: AtomicU64,
}

impl vmm::FileBacking for SharedPageoutBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> {
        Ok(0)
    }

    fn size_hint(&self) -> u64 { TEST_LEN }

    fn madvise_pageout(
        &self,
        off: u64,
        len: u64,
    ) -> Option<Result<usize, vmm::FileBackingError>> {
        self.called.store(true, Ordering::Release);
        self.off.store(off, Ordering::Release);
        self.len.store(len, Ordering::Release);
        Some(Ok(1))
    }
}

#[test]
fn pageout_dispatches_anonymous_range_to_swap_reclaim() {
    let vmas = [anonymous_vma()];
    let mut ops = RecordedOps { pageout: None, evicted: false };
    assert_eq!(madvise_vmas(TEST_START, TEST_LEN, MADV_PAGEOUT, &vmas, &mut ops), 0);
    assert_eq!(ops.pageout, Some((TEST_START, TEST_LEN)));
    assert!(!ops.evicted, "anonymous PAGEOUT must use swap reclaim, not discard");
}

#[test]
fn pageout_dispatches_shared_file_range_to_backing_transaction() {
    let backing = Arc::new(SharedPageoutBacking {
        called: AtomicBool::new(false),
        off: AtomicU64::new(0),
        len: AtomicU64::new(0),
    });
    let vma = vmm::Vma::new(
        hal::UserVirtAddr::new(TEST_START).expect("test address is user canonical"),
        hal::UserVirtAddr::new(TEST_START + TEST_LEN).expect("test end is user canonical"),
        vmm::VmaProt::READ | vmm::VmaProt::WRITE,
        vmm::VmaFlags::SHARED,
        vmm::VmaBacking::File { backing: backing.clone(), off: PAGE },
    );
    let mut ops = RecordedOps { pageout: None, evicted: false };
    assert_eq!(madvise_vmas(TEST_START, TEST_LEN, MADV_PAGEOUT, &[vma], &mut ops), 0);
    assert!(backing.called.load(Ordering::Acquire));
    assert_eq!(backing.off.load(Ordering::Acquire), PAGE);
    assert_eq!(backing.len.load(Ordering::Acquire), TEST_LEN);
    assert!(!ops.evicted, "shared pageout must not discard before backing transaction");
}

#[test]
fn pageout_private_file_falls_back_without_calling_shared_backing() {
    let backing = Arc::new(SharedPageoutBacking {
        called: AtomicBool::new(false),
        off: AtomicU64::new(0),
        len: AtomicU64::new(0),
    });
    let vma = vmm::Vma::new(
        hal::UserVirtAddr::new(TEST_START).expect("test address is user canonical"),
        hal::UserVirtAddr::new(TEST_START + TEST_LEN).expect("test end is user canonical"),
        vmm::VmaProt::READ | vmm::VmaProt::WRITE,
        vmm::VmaFlags::PRIVATE,
        vmm::VmaBacking::File { backing: backing.clone(), off: PAGE },
    );
    let mut ops = RecordedOps { pageout: None, evicted: false };
    assert_eq!(madvise_vmas(TEST_START, TEST_LEN, MADV_PAGEOUT, &[vma], &mut ops), 0);
    assert!(
        !backing.called.load(Ordering::Acquire),
        "MAP_PRIVATE must not page out the inode backing",
    );
    assert!(ops.evicted, "MAP_PRIVATE PAGEOUT falls back to private-page eviction");
}

// ── process_madvise: remote admission + the vector loop ──────────────────
// Linux's madvise core owns both, so they are pinned here beside `madvise_vmas`.

const EINVAL: i64 = -(Errno::Einval.as_i32() as i64);

// A remote mm accepts only the four non-destructive reclaim hints. Everything
// that could DROP the target's data — DONTNEED, FREE, REMOVE — is refused, and
// so is every VMA-flag advice, which would let a remote caller reshape the
// target's fork/dump behaviour.
#[test]
fn remote_valid_admits_only_non_destructive_hints() {
    for advice in [MADV_COLD, MADV_PAGEOUT, MADV_WILLNEED, MADV_COLLAPSE] {
        assert!(process_madvise_remote_valid(advice), "advice {advice} is a remote hint");
    }
    for advice in [MADV_NORMAL, MADV_RANDOM, MADV_SEQUENTIAL, MADV_DONTNEED, MADV_FREE,
                   MADV_REMOVE, MADV_DONTFORK, MADV_DOFORK, MADV_MERGEABLE, MADV_UNMERGEABLE,
                   MADV_HUGEPAGE, MADV_NOHUGEPAGE, MADV_DONTDUMP, MADV_DODUMP, MADV_WIPEONFORK,
                   MADV_KEEPONFORK, MADV_POPULATE_READ, MADV_POPULATE_WRITE,
                   MADV_DONTNEED_LOCKED, MADV_HWPOISON] {
        assert!(!process_madvise_remote_valid(advice), "advice {advice} must not reach a remote mm");
    }
}

// Remote-validity is a SUBSET check, not a replacement: an advice the syscall
// does not recognise at all is rejected before the remote question is asked.
#[test]
fn every_remote_valid_advice_is_also_a_recognised_advice() {
    for advice in [MADV_COLD, MADV_PAGEOUT, MADV_WILLNEED, MADV_COLLAPSE] {
        assert!(madvise_behavior_valid(advice));
    }
    assert!(!madvise_behavior_valid(0xDEAD));
    assert!(!process_madvise_remote_valid(0xDEAD));
}

// `check_input_range`: unaligned start, a length that rounds up to zero (i.e.
// wrapped), and a range whose end overflows are all EINVAL. Zero length is
// fine — it is simply nothing to do.
#[test]
fn check_input_range_rejects_unaligned_wrapped_and_overflowing() {
    assert_eq!(check_input_range(PAGE, PAGE), Ok(()));
    assert_eq!(check_input_range(0, 0), Ok(()));
    assert_eq!(check_input_range(1, PAGE), Err(Errno::Einval));
    assert_eq!(check_input_range(PAGE, u64::MAX), Err(Errno::Einval));
    assert_eq!(check_input_range(u64::MAX & !PAGE_MASK, PAGE), Err(Errno::Einval));
}

// All entries succeeding: the result is the total byte count, and every
// non-empty range was actually applied.
#[test]
fn vector_returns_total_bytes_when_every_entry_succeeds() {
    let iovs = [(PAGE, PAGE), (4 * PAGE, 2 * PAGE)];
    let mut seen = alloc::vec::Vec::new();
    let rv = vector_madvise(&iovs, |s, l| { seen.push((s, l)); 0 });
    assert_eq!(rv, (3 * PAGE) as i64);
    assert_eq!(seen, alloc::vec![(PAGE, PAGE), (4 * PAGE, 2 * PAGE)]);
}

// A failure on a LATER entry reports the bytes advised before it, not the
// errno — the caller detects the failure by the short count.
#[test]
fn vector_reports_bytes_advised_before_a_failing_entry() {
    let iovs = [(PAGE, PAGE), (4 * PAGE, PAGE), (8 * PAGE, PAGE)];
    let mut calls = 0;
    let rv = vector_madvise(&iovs, |_, _| { calls += 1; if calls == 2 { EINVAL } else { 0 } });
    assert_eq!(rv, PAGE as i64);
    assert_eq!(calls, 2, "the vector stops at the failing entry");
}

// A failure on the FIRST entry consumed nothing, so the errno itself is the
// only thing left to report.
#[test]
fn vector_reports_the_errno_when_nothing_was_advised() {
    let rv = vector_madvise(&[(PAGE, PAGE), (4 * PAGE, PAGE)], |_, _| EINVAL);
    assert_eq!(rv, EINVAL);
}

// A malformed entry is rejected without ever reaching the walk, and stops the
// vector exactly as a failing walk would.
#[test]
fn vector_rejects_a_malformed_entry_without_applying_it() {
    let mut calls = 0;
    let rv = vector_madvise(&[(1, PAGE)], |_, _| { calls += 1; 0 });
    assert_eq!(rv, EINVAL);
    assert_eq!(calls, 0);
}

// A zero-length entry is skipped rather than applied, and counts as consumed —
// so a vector of nothing but empty ranges succeeds with zero bytes.
#[test]
fn vector_skips_zero_length_entries() {
    let mut calls = 0;
    assert_eq!(vector_madvise(&[(PAGE, 0), (4 * PAGE, 0)], |_, _| { calls += 1; 0 }), 0);
    assert_eq!(calls, 0);
    let mut applied = alloc::vec::Vec::new();
    assert_eq!(vector_madvise(&[(PAGE, 0), (4 * PAGE, PAGE)], |s, l| { applied.push((s, l)); 0 }), PAGE as i64);
    assert_eq!(applied, alloc::vec![(4 * PAGE, PAGE)]);
}

// An empty vector is a no-op success, not an error.
#[test]
fn empty_vector_succeeds_with_zero_bytes() {
    assert_eq!(vector_madvise(&[], |_, _| EINVAL), 0);
}
