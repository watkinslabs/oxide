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
