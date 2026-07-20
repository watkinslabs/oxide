use std::sync::{Arc, Mutex};

use hal::UserVirtAddr;
use syscall::errno::Errno;
use vmm::{FileBacking, Vma, VmaBacking, VmaFlags, VmaProt};

#[path = "../../syscalls/src/026_msync.rs"]
mod msync_syscall;

const PAGE: u64 = 0x1000;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

#[derive(Default)]
struct MockBacking {
    calls: Mutex<Vec<(u64, u64)>>,
    fail: bool,
}

impl FileBacking for MockBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { 0 }
    fn writeback_range(&self, start: u64, end: u64) -> Result<(), ()> {
        self.calls.lock().unwrap().push((start, end));
        if self.fail { Err(()) } else { Ok(()) }
    }
}

fn uva(x: u64) -> UserVirtAddr {
    UserVirtAddr::new(x).expect("test VA in user range")
}

fn anon(start: u64, pages: u64, flags: VmaFlags) -> Vma {
    Vma::new(uva(start), uva(start + pages * PAGE), VmaProt::READ | VmaProt::WRITE,
        flags, VmaBacking::Anonymous)
}

fn file(start: u64, pages: u64, flags: VmaFlags, backing: Arc<MockBacking>, off: u64) -> Vma {
    let backing: Arc<dyn FileBacking> = backing;
    Vma::new(uva(start), uva(start + pages * PAGE), VmaProt::READ | VmaProt::WRITE,
        flags, VmaBacking::File { backing, off })
}

#[test]
fn msync_validates_flags_alignment_and_zero_len_like_linux() {
    assert_eq!(msync_syscall::msync_vmas(0x4000_0001, PAGE, 0, &[]), errno(Errno::Einval));
    assert_eq!(msync_syscall::msync_vmas(0x4000_0000, PAGE, 0x8000, &[]), errno(Errno::Einval));
    assert_eq!(msync_syscall::msync_vmas(0x4000_0000, PAGE,
        msync_syscall::MS_SYNC | msync_syscall::MS_ASYNC, &[]), errno(Errno::Einval));
    assert_eq!(msync_syscall::msync_vmas(0x4000_0000, 0, 0, &[]), 0);
}

#[test]
fn msync_reports_enomem_for_unmapped_ranges_after_scanning() {
    let b = Arc::new(MockBacking::default());
    let vmas = [file(0x4000_2000, 1, VmaFlags::SHARED, b.clone(), 0x8000)];
    assert_eq!(msync_syscall::msync_vmas(0x4000_0000, 3 * PAGE,
        msync_syscall::MS_SYNC, &vmas), errno(Errno::Enomem));
    assert_eq!(*b.calls.lock().unwrap(), vec![(0x8000, 0x9000)]);
}

#[test]
fn msync_async_on_initial_hole_returns_enomem_without_writeback() {
    let b = Arc::new(MockBacking::default());
    let vmas = [file(0x4000_2000, 1, VmaFlags::SHARED, b.clone(), 0)];
    assert_eq!(msync_syscall::msync_vmas(0x4000_0000, 3 * PAGE,
        msync_syscall::MS_ASYNC, &vmas), errno(Errno::Enomem));
    assert!(b.calls.lock().unwrap().is_empty());
}

#[test]
fn msync_invalidate_locked_vma_is_ebusy() {
    let vmas = [anon(0x4000_0000, 1, VmaFlags::PRIVATE | VmaFlags::LOCKED)];
    assert_eq!(msync_syscall::msync_vmas(0x4000_0000, PAGE,
        msync_syscall::MS_INVALIDATE, &vmas), errno(Errno::Ebusy));
}

#[test]
fn msync_sync_flushes_only_shared_file_ranges() {
    let shared = Arc::new(MockBacking::default());
    let private = Arc::new(MockBacking::default());
    let vmas = [
        file(0x4000_0000, 2, VmaFlags::SHARED, shared.clone(), 0x20_0000),
        file(0x4000_2000, 1, VmaFlags::PRIVATE, private.clone(), 0x30_0000),
        anon(0x4000_3000, 1, VmaFlags::SHARED),
    ];
    assert_eq!(msync_syscall::msync_vmas(0x4000_1000, 3 * PAGE,
        msync_syscall::MS_SYNC, &vmas), 0);
    assert_eq!(*shared.calls.lock().unwrap(), vec![(0x20_1000, 0x20_2000)]);
    assert!(private.calls.lock().unwrap().is_empty());
}

#[test]
fn msync_writeback_failure_is_eio() {
    let b = Arc::new(MockBacking { calls: Mutex::new(Vec::new()), fail: true });
    let vmas = [file(0x4000_0000, 1, VmaFlags::SHARED, b, 0)];
    assert_eq!(msync_syscall::msync_vmas(0x4000_0000, PAGE,
        msync_syscall::MS_SYNC, &vmas), errno(Errno::Eio));
}
