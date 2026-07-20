// VMA tree tests: invariant 1 (non-overlap, `11§2`) + split/merge
// behavior (`11§4`, `11§6`). Per `11§11` this is the hosted-unit
// portion of the test contract; QEMU integration + soak land in
// `40§3`-controlled CI.

mod address_space;
mod accounting;
mod vma_tree;

use super::*;
use crate::vma::{FileBacking, FileBackingError, Vma, VmaBacking, VmaFlags, VmaProt};
use hal::{UserVirtAddr, PAGE_SIZE_BYTES};
use std::sync::Arc;
use std::thread;
use std::vec::Vec;

const PAGE: usize = PAGE_SIZE_BYTES as usize;

fn uva(x: u64) -> UserVirtAddr {
    UserVirtAddr::new(x).expect("test address fits user range")
}

/// Trivial FileBacking impl for VMA-tree tests: never invoked
/// (the tree tests don't fault), only used as an Arc identity for
/// `mergeable_with_next` + `PartialEq`.
struct FakeFile;
impl FileBacking for FakeFile {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> {
        Ok(0)
    }
    fn size_hint(&self) -> u64 {
        0
    }
}

fn fake_backing() -> alloc::sync::Arc<dyn FileBacking> {
    alloc::sync::Arc::new(FakeFile)
}

fn anon(start: u64, end: u64, prot: VmaProt) -> Vma {
    Vma::new(
        uva(start),
        uva(end),
        prot,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous,
    )
}

fn file(start: u64, end: u64, off: u64, prot: VmaProt) -> Vma {
    Vma::new(
        uva(start),
        uva(end),
        prot,
        VmaFlags::PRIVATE,
        VmaBacking::File {
            backing: fake_backing(),
            off,
        },
    )
}

fn kbytes(start: u64, end: u64, data: &'static [u8], prot: VmaProt) -> Vma {
    let arc: alloc::sync::Arc<[u8]> =
        alloc::sync::Arc::from(data.to_vec().into_boxed_slice());
    Vma::new(
        uva(start),
        uva(end),
        prot,
        VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data: arc, off: 0 },
    )
}

fn r_w() -> VmaProt {
    VmaProt::READ | VmaProt::WRITE
}

fn priv_anon() -> VmaFlags {
    VmaFlags::PRIVATE | VmaFlags::ANONYMOUS
}
