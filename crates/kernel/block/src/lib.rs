// Block layer + page cache per docs/17.
//
// `types.rs` — `BlockOp`, `BlockError`, `PageFlags`, `InodeId`, `PAGE_BYTES`.
// `queue_limits.rs` — canonical block queue topology + sysfs leaf mapping.
// `blockdev.rs` — `BlockDevice` trait + `BlockRequest` + `MemDisk` test backing.
// `pagecache.rs` — `PageCache` (sync `read_page` / `write_page` /
// `fsync` / `invalidate`); `CachedPage` with `PG_*` flags.
//
// The owned-request completion contract is present; individual driver queue
// engines migrate from their synchronous compatibility path to it. Remaining:
// writeback daemon (`17§4`), radix-tree, PG_LOCKED waiters, io_uring fixed
// buffers, and multi-command driver queues.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod blockdev;
pub mod devbridge;
pub mod pagecache;
pub mod queue_limits;
pub mod registry;
pub mod stats;
pub mod types;
pub mod uapi;

pub use blockdev::{BlockCompletion, BlockDevice, BlockRequest, MemDisk};
pub use pagecache::{CachedPage, PageCache};
pub use queue_limits::{QueueLimits, LINUX_SECTOR_BYTES};
pub use registry::{Disk, register, unregister, by_name, by_index, snapshot};
pub use types::{BlockError, BlockOp, InodeId, KResult, PageFlags, PAGE_BYTES};

use core::sync::atomic::{AtomicPtr, Ordering};

/// Charge a completed block I/O to the current task's cgroup io.stat.
/// The io controller lives in block (Linux: blk-cgroup) — block reads the
/// current task (sched) + charges the cgroup tree directly. Called from the
/// page-cache submit path. No-op on host builds (no live scheduler).
/// # C: O(1) + cgroup lookup
pub fn charge_io(bytes: u64, is_write: bool) {
    #[cfg(target_os = "oxide-kernel")]
    if let Some(t) = sched::live::current() {
        let pid = t.tgid.load(Ordering::Acquire) as u64;
        cgroup::charge_io(pid, bytes, is_write);
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = (bytes, is_write);
}

#[cfg(test)]
mod tests;

/// Subsystem-level error per `38`. Kept for the existing skeleton
/// `init` shim; the canonical block error is `BlockError` above.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Io,
}

#[allow(dead_code)]
pub(crate) type StubResult<T> = core::result::Result<T, Error>;

/// Initialization entry; called by the kernel boot phase per `00§3` /
/// `boot-flow.md`. v1 returns `NotImplemented`; bodies in P1-N.
///
/// # SAFETY: caller is the boot path, runs single-CPU with IRQs off
/// per `boot-flow.md`. Subsystem-specific preconditions documented at
/// the implementation site.
///
/// # C: O(N_pfn) once at boot
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> StubResult<()> {
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
