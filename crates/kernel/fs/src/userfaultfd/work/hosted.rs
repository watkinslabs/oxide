// Hosted counterpart of the resolve paths. The live work needs the PMM and a
// per-arch page-table walker, neither of which exists under `cargo test`, so
// the hosted build reports the range as completed without touching anything.
//
// Everything a hosted test cares about — range validation, the destination
// ladder, the mode words, the wake decision and the reply protocol — happens
// AROUND these calls, in `policy`, and is exercised for real. The work itself
// is reached only from the kernel build.

use vmm::address_space::uffd::UffdVma;

use super::{FillReq, Progress};

/// # C: O(1)
pub fn fill_pages(_mm: &vmm::AddressSpace, req: &FillReq, _vma: &UffdVma) -> Progress {
    (req.len, None)
}

/// # C: O(1)
pub fn wp_range(_mm: &vmm::AddressSpace, _start: u64, _end: u64, _protect: bool) {}

/// # C: O(1)
pub fn poison_range(_mm: &vmm::AddressSpace, start: u64, end: u64) -> Progress {
    (end - start, None)
}

/// # C: O(1)
pub fn move_pages(_mm: &vmm::AddressSpace, _dst: u64, _src: u64, len: u64, _holes: bool,
                  _dst_vma: &UffdVma, _src_vma: &UffdVma) -> Progress {
    (len, None)
}
