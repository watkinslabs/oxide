use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use hal::UserVirtAddr;

use crate::{AddressSpace, FileBacking, FileBackingError, FileMmapSetup, VmaBacking, VmaFlags, VmaProt};

struct SetupBacking { seen: AtomicU64 }
impl FileBacking for SetupBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { 4096 }
    fn mmap_setup(&self, setup: &mut FileMmapSetup) -> Result<(), FileBackingError> {
        self.seen.store(setup.start().as_u64() ^ setup.end().as_u64() ^ setup.pgoff(), Ordering::Release);
        Ok(())
    }
}

#[test]
fn file_mmap_setup_receives_final_range_before_vma_publication() {
    let mm = AddressSpace::new(0).unwrap();
    let backing = Arc::new(SetupBacking { seen: AtomicU64::new(0) });
    let start = UserVirtAddr::new(0x4000_0000).unwrap();
    mm.mmap(Some(start), 4096, VmaProt::READ, VmaFlags::PRIVATE,
        VmaBacking::File { backing: backing.clone(), off: 8192 }, false).unwrap();
    assert_eq!(backing.seen.load(Ordering::Acquire), 0x4000_0000 ^ 0x4000_1000 ^ 2);
    assert!(mm.find_vma(start).is_some());
}
