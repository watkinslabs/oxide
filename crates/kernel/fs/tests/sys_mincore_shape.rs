use std::sync::Arc;

use hal::UserVirtAddr;
use syscall::errno::Errno;
use vmm::{FileBacking, Vma, VmaBacking, VmaFlags, VmaProt};

#[path = "../../syscalls/src/027_mincore.rs"]
mod mincore_syscall;

const PAGE: u64 = 0x1000;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

struct MockBacking {
    reveal: bool,
    resident: &'static [u64],
}

impl FileBacking for MockBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { 0 }
    fn mincore_page(&self, off: u64) -> bool { self.resident.contains(&off) }
    fn mincore_can_reveal(&self) -> bool { self.reveal }
}

fn uva(x: u64) -> UserVirtAddr {
    UserVirtAddr::new(x).expect("test VA in user range")
}

fn anon(start: u64, pages: u64) -> Vma {
    Vma::new(uva(start), uva(start + pages * PAGE), VmaProt::READ,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS, VmaBacking::Anonymous)
}

fn file(start: u64, pages: u64, backing: Arc<MockBacking>, off: u64) -> Vma {
    let backing: Arc<dyn FileBacking> = backing;
    Vma::new(uva(start), uva(start + pages * PAGE), VmaProt::READ,
        VmaFlags::PRIVATE, VmaBacking::File { backing, off })
}

fn mincore(start: u64, len: u64, out: &mut [u8], vmas: &[Vma], present_pages: &[u64]) -> i64 {
    mincore_syscall::mincore_vmas(start, len, out, vmas, |va| present_pages.contains(&va))
}

#[test]
fn mincore_alignment_zero_len_and_output_size_match_linux_shape() {
    let mut out = [0x55u8; 1];
    assert_eq!(mincore(0x4000_0001, PAGE, &mut out, &[], &[]), errno(Errno::Einval));
    assert_eq!(mincore(0x4000_0000, 0, &mut [], &[], &[]), 0);
    assert_eq!(mincore(0x4000_0000, PAGE, &mut [], &[anon(0x4000_0000, 1)], &[]),
        errno(Errno::Efault));
}

#[test]
fn mincore_anon_reports_present_ptes_and_absent_pages() {
    let vmas = [anon(0x4000_0000, 3)];
    let mut out = [0u8; 3];
    assert_eq!(mincore(0x4000_0000, 3 * PAGE, &mut out, &vmas,
        &[0x4000_0000, 0x4000_2000]), 0);
    assert_eq!(out, [1, 0, 1]);
}

#[test]
fn mincore_file_mapping_uses_page_cache_when_pte_absent() {
    let backing = Arc::new(MockBacking { reveal: true, resident: &[0x20_1000] });
    let vmas = [file(0x4000_0000, 3, backing, 0x20_0000)];
    let mut out = [0u8; 3];
    assert_eq!(mincore(0x4000_0000, 3 * PAGE, &mut out, &vmas,
        &[0x4000_2000]), 0);
    assert_eq!(out, [0, 1, 1]);
}

#[test]
fn mincore_restricted_file_mapping_reports_resident_without_revealing_cache() {
    let backing = Arc::new(MockBacking { reveal: false, resident: &[] });
    let vmas = [file(0x4000_0000, 3, backing, 0)];
    let mut out = [0u8; 3];
    assert_eq!(mincore(0x4000_0000, 3 * PAGE, &mut out, &vmas, &[]), 0);
    assert_eq!(out, [1, 1, 1]);
}

#[test]
fn mincore_crossing_unmapped_gap_keeps_prefix_and_returns_enomem() {
    let vmas = [anon(0x4000_0000, 1), anon(0x4000_2000, 1)];
    let mut out = [0x55u8; 3];
    assert_eq!(mincore(0x4000_0000, 3 * PAGE, &mut out, &vmas,
        &[0x4000_0000, 0x4000_2000]), errno(Errno::Enomem));
    assert_eq!(out, [1, 0x55, 0x55]);
}
