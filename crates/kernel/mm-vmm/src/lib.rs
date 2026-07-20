// Virtual Memory Manager — VMA tree + page faults + COW.
//
// Per docs/11 (FROZEN). VMA tree foundation lives in `vma.rs` + `tree.rs`;
// page-fault handler, COW, TLB shootdown, and per-page metadata land in
// subsequent P1-N branches alongside HAL `MmuOps`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod address_space;
pub mod debug_cow;
#[cfg(feature = "debug-atexit")]
pub mod tailwatch;
mod mremap;
pub mod anon_vma;
pub mod file_rmap;
pub mod migration;
pub mod rmap;
pub mod vma;
pub mod tree;
pub mod uffd;
pub(crate) mod hole;

pub use address_space::{
    global_accounting_snapshot, page_table_frame_allocated, page_table_frame_released, swap_pte_teardown,
    live_address_spaces, AddressSpace, MIN_USER_VA, MMAP_BASE_GAP, VmAccountingSnapshot,
};
pub use address_space::{
    prctl_mm_map_size, validate_mm_map, PrctlMmMap,
    PR_SET_MM_ARG_END, PR_SET_MM_ARG_START, PR_SET_MM_AUXV, PR_SET_MM_BRK,
    PR_SET_MM_END_CODE, PR_SET_MM_END_DATA, PR_SET_MM_ENV_END, PR_SET_MM_ENV_START,
    PR_SET_MM_EXE_FILE, PR_SET_MM_MAP, PR_SET_MM_MAP_SIZE, PR_SET_MM_START_BRK,
    PR_SET_MM_START_CODE, PR_SET_MM_START_DATA, PR_SET_MM_START_STACK,
};
pub use anon_vma::{AnonVma, RmapTarget};
pub use file_rmap::FileRmap;
pub use migration::{migration_attach_marker, migration_begin, migration_drop_marker_mapping, migration_finish, migration_pending_then, migration_restore_marker_mapping};
pub use vma::{EXEC_STACK_VMA_FLAGS, FaultAccess, FaultKind, FileBacking, FileBackingError, SharedFrame, Vma, VmaBacking, VmaFlags, VmaProt};
pub use tree::VmaTree;
pub use uffd::UffdContext;

/// DIAG (debug-atexit): fn-ptr the arch layer installs to arm a DR0 hardware
/// write-watchpoint at a VA. The File fill arm calls it once, on the first
/// lib-arena full page, so the #DB hook can name the instruction that later
/// zeros that page. 0 = not installed.
#[cfg(feature = "debug-atexit")]
pub static WATCH_ARM: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Subsystem-level error per `38`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Fault,
    Perm,
    Again,
    Access,
    Io,
}

pub type KResult<T> = core::result::Result<T, Error>;

/// Initialization entry; called by the kernel boot phase per `00§3` /
/// `boot-flow.md`. v1 returns `NotImplemented`; bodies in P1-N.
///
/// # SAFETY: caller is the boot path, runs single-CPU with IRQs off
/// per `boot-flow.md`. Subsystem-specific preconditions documented at
/// the implementation site.
///
/// # C: O(N_pfn) once at boot
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> KResult<()> {
    Err(Error::NotImplemented)
}

#[cfg(test)]
mod stub_tests {
    use super::*;

    #[test]
    fn init_returns_not_implemented() {
        // SAFETY: hosted-test entry; nothing else has touched the subsystem; init's preconditions trivially hold.
        let r = unsafe { init() };
        assert_eq!(r, Err(Error::NotImplemented));
    }
}

#[cfg(test)]
mod tests;

// F157: comprehensive memory torture test suite — boundary
// conditions, fragmentation, fork chains, churn stress, brk
// underflow/overflow, ARG_MAX, alignment edge cases.
#[cfg(test)]
mod torture_tests;

// F156: rmap + COW chain regression tests against a HostMmu that
// enforces the same defensive AlreadyMapped semantics as the real
// PT walker. Pins the F156 boot fix in place.
#[cfg(test)]
mod tests_rmap_cow;
#[cfg(test)]
mod tests_swap_fork;

// B430: prctl(PR_SET_MM) field storage / ordering validation / whole-map
// apply + fork-copy of the mm layout.
#[cfg(test)]
mod tests_setmm;

// fork+COW data-isolation + refcount-accuracy reproduction (multi-AS PTs).
#[cfg(test)]
mod tests_cow_isolation;

// Phase C: per-inode address_space (i_mapping) + shmem MAP_SHARED/MAP_PRIVATE
// fault behaviour against the production file-fault arms.
#[cfg(test)]
mod tests_pagecache;

// fork+COW GLOBAL refcount-invariant proptest: refcount(pa) == live PTEs + base
// across all ASes, asserted after every op over 200k randomized fork/COW/
// munmap/teardown operations. Catches refcount UNDER-COUNT (free-while-mapped).
#[cfg(test)]
mod tests_cow_invariant;

// B240: File demand-fault must retry short `read_at` for a non-EOF page and
// refuse to install a partially-zero page (SIGBUS, not silent zeros).
#[cfg(test)]
mod tests_shortfill;

// ld.so `needed != NULL` blocker: the write-protection fault must never
// zero-fill over File/KernelBytes backing when the leaf is zapped between the
// normalization translate and the CoW re-read (SMP TOCTOU).
#[cfg(test)]
mod tests_ldso_toctou;
