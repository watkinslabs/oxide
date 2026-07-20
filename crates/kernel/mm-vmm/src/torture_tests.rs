// F157: comprehensive memory torture tests. Covers:
// - mmap alignment + boundary conditions (USER_VA_END, MIN_USER_VA,
//   off-by-1, page-misaligned, zero-len, gigantic-len)
// - munmap edge cases (unmapped, partial, misaligned, hole)
// - mprotect on holes / mixed regions / boundary splits
// - VMA tree invariants under churn (alternating insert/remove,
//   fragmented holes, reverse-order inserts)
// - Topdown allocator under fragmentation
// - MAP_FIXED overlap clear + non-fixed hint behavior
// - KernelBytes Arc lifetime under fork chains
// - Concurrent reader/writer correctness
// - VMA split at all four positions (start, mid, end, both)
// - VMA merge across prot/flag/backing diffs
// - brk window: shrink, grow, overflow, underflow
//
// Hosted-only — no real PT walk; AddressSpace::new(0) sentinel
// skips all MmuOps activation paths.

#![cfg(test)]

mod mapping;
mod stack;
mod stress;

use super::*;
use crate::address_space::{MIN_USER_VA, MMAP_TOP};
use crate::vma::{FileBacking, FileBackingError, VmaBacking, VmaFlags, VmaProt};
use hal::{UserVirtAddr, PAGE_SIZE_BYTES, USER_VA_END};
use std::sync::Arc;

struct FakeFile;
impl FileBacking for FakeFile {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> {
        Ok(0)
    }
    fn size_hint(&self) -> u64 {
        0
    }
}

const PAGE: usize = PAGE_SIZE_BYTES as usize;

fn uva(x: u64) -> UserVirtAddr {
    UserVirtAddr::new(x).expect("test address fits user range")
}

fn r_w() -> VmaProt {
    VmaProt::READ | VmaProt::WRITE
}

fn priv_anon() -> VmaFlags {
    VmaFlags::PRIVATE | VmaFlags::ANONYMOUS
}
