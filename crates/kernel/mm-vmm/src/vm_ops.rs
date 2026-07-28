//! Linux `vm_operations_struct.open` / `.close` for the one user that needs
//! them: SysV shared memory (`ipc/shm.c` `shm_vm_ops`).
//!
//! `shm_nattch` counts VMAs, not processes — `shm_open` runs on every VMA
//! that comes into existence referencing the segment (`shmat`'s own mmap,
//! `dup_mmap` on fork, `__split_vma` on an mprotect/munmap that cuts the
//! attachment) and `shm_close` on every one that goes away, with the last
//! close destroying a segment already marked `SHM_DEST` by `IPC_RMID`. A
//! kernel that only counts `shmat`/`shmdt` reports a stale `shm_nattch` to
//! every `ipcs -m` and never reclaims an `IPC_RMID`ed segment whose last
//! attacher simply exited.
//!
//! `mm-vmm` cannot depend on `ipc`, so the two callbacks are installed at
//! boot exactly like the SysV `exit_sem` hook (`sched::live`). VMAs that are
//! not SysV attachments carry no `VmaFlags::SYSVSHM` and never reach the
//! indirect call, so the mmap/munmap fast paths pay one flag test.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::vma::{Vma, VmaBacking, VmaFlags};

/// Callback shape: the segment is identified by its backing object, which is
/// what `VmaBacking::File` carries and what `ipc` already keys `shmdt` on.
pub type VmaOpsFn = fn(&alloc::sync::Arc<dyn crate::vma::FileBacking>);

static OPEN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static CLOSE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install Linux `shm_vm_ops`' open/close. Called once from kernel bring-up.
/// # C: O(1)
pub fn set_shm_vm_ops(open: VmaOpsFn, close: VmaOpsFn) {
    OPEN.store(open as *mut (), Ordering::Release);
    CLOSE.store(close as *mut (), Ordering::Release);
}

fn dispatch(slot: &AtomicPtr<()>, vma: &Vma) {
    if !vma.flags.contains(VmaFlags::SYSVSHM) { return; }
    let VmaBacking::File { backing, .. } = &vma.backing else { return };
    let p = slot.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: `p` was stored by `set_shm_vm_ops` from a `VmaOpsFn` with this exact signature; the Acquire load pairs with that Release store, and a function address is 'static.
    let f: VmaOpsFn = unsafe { core::mem::transmute::<*mut (), VmaOpsFn>(p) };
    f(backing);
}

/// Linux `vm_ops->open(vma)`: a new VMA now references this segment.
/// # C: O(1) plus the callback
pub(crate) fn vma_opened(vma: &Vma) { dispatch(&OPEN, vma); }

/// Linux `vm_ops->close(vma)`: this VMA no longer references the segment.
/// The callback owns the last-close destroy decision.
/// # C: O(1) plus the callback
pub(crate) fn vma_closed(vma: &Vma) { dispatch(&CLOSE, vma); }
