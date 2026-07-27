extern crate alloc;

use std::sync::{Arc, Mutex};

use hal::UserVirtAddr;
use syscall::errno::Errno;
use vmm::{FileBacking, FileBackingError, Vma, VmaBacking, VmaFlags, VmaProt};

#[path = "../../syscalls/src/028_madvise.rs"]
mod madvise_syscall;

const PAGE: u64 = 0x1000;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }
fn uva(x: u64) -> UserVirtAddr { UserVirtAddr::new(x).expect("test VA") }

fn anon(start: u64, pages: u64, flags: VmaFlags, prot: VmaProt) -> Vma {
    Vma::new(uva(start), uva(start + pages * PAGE), prot,
        flags | VmaFlags::ANONYMOUS, VmaBacking::Anonymous)
}

fn file(start: u64, pages: u64, flags: VmaFlags, may: VmaProt,
        backing: Arc<MockBacking>, off: u64) -> Vma {
    let backing: Arc<dyn FileBacking> = backing;
    Vma::new_with_may(uva(start), uva(start + pages * PAGE),
        VmaProt::READ | VmaProt::WRITE, may, flags, VmaBacking::File { backing, off })
}

#[derive(Default)]
struct Ops {
    evicts: Vec<(u64, u64)>,
    flags: Vec<(u64, u64, VmaFlags, VmaFlags)>,
    populates: Vec<(u64, u64, bool)>,
}

impl madvise_syscall::MadviseOps for Ops {
    fn evict_pages(&mut self, start: u64, len: u64) -> i64 {
        self.evicts.push((start, len));
        0
    }

    fn update_flags(&mut self, start: u64, len: u64, set: VmaFlags, clear: VmaFlags) {
        self.flags.push((start, len, set, clear));
    }

    fn populate(&mut self, start: u64, len: u64, write: bool) -> i64 {
        self.populates.push((start, len, write));
        0
    }
}

struct MockBacking {
    calls: Mutex<Vec<(u64, u64)>>,
    result: Result<(), FileBackingError>,
}

impl FileBacking for MockBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { 0 }
    fn madvise_remove(&self, off: u64, len: u64) -> Result<(), FileBackingError> {
        self.calls.lock().unwrap().push((off, len));
        self.result
    }
}

fn madvise(start: u64, len: u64, advice: u64, vmas: &[Vma], ops: &mut Ops) -> i64 {
    madvise_syscall::madvise_vmas(start, len, advice, vmas, ops)
}

#[test]
fn validates_advice_alignment_overflow_and_zero_len_in_linux_order() {
    let mut ops = Ops::default();
    assert_eq!(madvise(0x4000_0001, PAGE, 999, &[], &mut ops), errno(Errno::Einval));
    assert_eq!(madvise(0x4000_0001, PAGE, 0, &[], &mut ops), errno(Errno::Einval));
    assert_eq!(madvise(0x4000_0000, u64::MAX, 0, &[], &mut ops), errno(Errno::Einval));
    assert_eq!(madvise(0x4000_0000, 0, 0, &[], &mut ops), 0);
    assert!(ops.evicts.is_empty());
}

#[test]
fn holes_return_enomem_after_mapped_prefix_side_effects() {
    let vmas = [anon(0x4000_0000, 1, VmaFlags::PRIVATE, VmaProt::READ | VmaProt::WRITE)];
    let mut ops = Ops::default();
    assert_eq!(madvise(0x4000_0000, 2 * PAGE, 4, &vmas, &mut ops), errno(Errno::Enomem));
    assert_eq!(ops.evicts, vec![(0x4000_0000, PAGE)]);
}

#[test]
fn dontneed_locked_gate_matches_locked_variant() {
    let vmas = [anon(0x4000_0000, 1, VmaFlags::PRIVATE | VmaFlags::LOCKED,
        VmaProt::READ | VmaProt::WRITE)];
    let mut ops = Ops::default();
    assert_eq!(madvise(0x4000_0000, PAGE, 4, &vmas, &mut ops), errno(Errno::Einval));
    assert!(ops.evicts.is_empty());
    assert_eq!(madvise(0x4000_0000, PAGE, 24, &vmas, &mut ops), 0);
    assert_eq!(ops.evicts, vec![(0x4000_0000, PAGE)]);
}

#[test]
fn free_requires_private_anonymous_mapping() {
    let f = Arc::new(MockBacking { calls: Mutex::new(Vec::new()), result: Ok(()) });
    let vmas = [file(0x4000_0000, 1, VmaFlags::PRIVATE, VmaProt::WRITE, f, 0)];
    let mut ops = Ops::default();
    assert_eq!(madvise(0x4000_0000, PAGE, 8, &vmas, &mut ops), errno(Errno::Einval));
    assert!(ops.evicts.is_empty());
}

#[test]
fn remove_punches_shared_maywrite_file_range() {
    let backing = Arc::new(MockBacking { calls: Mutex::new(Vec::new()), result: Ok(()) });
    let vmas = [file(0x4000_0000, 2, VmaFlags::SHARED, VmaProt::WRITE, backing.clone(), 0x20_0000)];
    let mut ops = Ops::default();
    assert_eq!(madvise(0x4000_1000, PAGE, 9, &vmas, &mut ops), 0);
    assert_eq!(*backing.calls.lock().unwrap(), vec![(0x20_1000, PAGE)]);
    assert!(ops.evicts.is_empty());
}

#[test]
fn remove_rejects_private_or_non_writable_mapping_before_backend() {
    let backing = Arc::new(MockBacking { calls: Mutex::new(Vec::new()), result: Ok(()) });
    let vmas = [file(0x4000_0000, 1, VmaFlags::PRIVATE, VmaProt::WRITE, backing.clone(), 0)];
    let mut ops = Ops::default();
    assert_eq!(madvise(0x4000_0000, PAGE, 9, &vmas, &mut ops), errno(Errno::Eacces));
    assert!(backing.calls.lock().unwrap().is_empty());
}

#[test]
fn wipeonfork_is_anon_private_only_and_dontfork_splits_flags() {
    let f = Arc::new(MockBacking { calls: Mutex::new(Vec::new()), result: Ok(()) });
    let file_vma = [file(0x4000_0000, 1, VmaFlags::PRIVATE, VmaProt::WRITE, f, 0)];
    let mut ops = Ops::default();
    assert_eq!(madvise(0x4000_0000, PAGE, 18, &file_vma, &mut ops), errno(Errno::Einval));

    let anon_vma = [anon(0x5000_0000, 2, VmaFlags::PRIVATE, VmaProt::READ | VmaProt::WRITE)];
    assert_eq!(madvise(0x5000_1000, PAGE, 10, &anon_vma, &mut ops), 0);
    assert_eq!(ops.flags.last().copied(),
        Some((0x5000_1000, PAGE, VmaFlags::DONTFORK, VmaFlags::empty())));
}

#[test]
fn populate_checks_vma_permissions() {
    let vmas = [anon(0x4000_0000, 1, VmaFlags::PRIVATE, VmaProt::READ)];
    let mut ops = Ops::default();
    assert_eq!(madvise(0x4000_0000, PAGE, 23, &vmas, &mut ops), errno(Errno::Einval));
    assert_eq!(madvise(0x4000_0000, PAGE, 22, &vmas, &mut ops), 0);
    assert_eq!(ops.populates, vec![(0x4000_0000, PAGE, false)]);
}
