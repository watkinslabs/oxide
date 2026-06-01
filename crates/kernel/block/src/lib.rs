// Block layer + page cache per docs/17.
//
// `types.rs` — `BlockOp`, `BlockError`, `PageFlags`, `InodeId`, `PAGE_BYTES`.
// `blockdev.rs` — `BlockDevice` trait + `BlockRequest` + `MemDisk` test backing.
// `pagecache.rs` — `PageCache` (sync `read_page` / `write_page` /
// `fsync` / `invalidate`); `CachedPage` with `PG_*` flags.
//
// Out of scope: async submit + soft-IRQ completion (`17§3`),
// writeback daemon (`17§4`), radix-tree, PG_LOCKED waiters, io_uring
// fixed buffers, real-driver impls (virtio-blk / NVMe / AHCI).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod blockdev;
pub mod pagecache;
pub mod registry;
pub mod types;

pub use blockdev::{BlockDevice, BlockRequest, MemDisk};
pub use pagecache::{CachedPage, PageCache};
pub use registry::{Disk, register, by_name, by_index, snapshot};
pub use types::{BlockError, BlockOp, InodeId, KResult, PageFlags, PAGE_BYTES};

use core::sync::atomic::{AtomicPtr, Ordering};

/// cgroup io.stat charge hook (`26`): the kernel installs a fn that
/// charges `(bytes, is_write)` to the *current* task's cgroup. This leaf
/// crate stays cgroup/sched-free; the hook resolves `current()` itself.
static IO_CHARGE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the io.stat charge hook. Boot path.
/// # C: O(1)
pub fn set_io_charge_hook(f: fn(u64, bool)) {
    IO_CHARGE_HOOK.store(f as *mut (), Ordering::Release);
}

/// Charge a completed block I/O to the current task's cgroup io.stat
/// (no-op when the hook is unset). Called from the page-cache submit path.
/// # C: O(1) + hook
pub fn charge_io(bytes: u64, is_write: bool) {
    let p = IO_CHARGE_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: hook installed at boot with the exact `fn(u64, bool)` ABI.
    let f: fn(u64, bool) = unsafe { core::mem::transmute(p) };
    f(bytes, is_write);
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
