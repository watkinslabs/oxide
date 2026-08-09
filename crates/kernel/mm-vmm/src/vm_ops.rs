//! VMA open/close/may_split lifecycle hooks — Linux `vm_operations_struct`.
//!
//! Two dispatch shapes, one contract. The object's own
//! [`crate::vma::FileBacking`] methods are the general one and run for every
//! file-backed VMA, exactly as Linux's ops table belongs to whatever the
//! mapping was created from; a mapping-lifetime charge (perf's per-user
//! `locked_vm`) is released there. The `AtomicPtr` slots below are the SysV
//! shm pair, which cannot be trait methods because the same shmem object also
//! backs plain `MAP_SHARED|MAP_ANONYMOUS` mappings that are not attachments —
//! `VmaFlags::SYSVSHM` is what tells the two apart.
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
    dispatch_slot(slot, backing);
}

fn dispatch_slot(slot: &AtomicPtr<()>, backing: &alloc::sync::Arc<dyn crate::vma::FileBacking>) {
    let p = slot.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: `p` was stored by `set_shm_vm_ops` from a `VmaOpsFn` with this exact signature; the Acquire load pairs with that Release store, and a function address is 'static.
    let f: VmaOpsFn = unsafe { core::mem::transmute::<*mut (), VmaOpsFn>(p) };
    f(backing);
}

/// The mapped object behind `vma`, if it has one.
fn object_of(vma: &Vma) -> Option<&alloc::sync::Arc<dyn crate::vma::FileBacking>> {
    match &vma.backing { VmaBacking::File { backing, .. } => Some(backing), _ => None }
}

/// Linux `vm_ops->open(vma)`: a new VMA now references the mapped object.
/// # C: O(1) plus the callback
pub(crate) fn vma_opened(vma: &Vma) {
    if let Some(b) = object_of(vma) { b.vma_open(); }
    dispatch(&OPEN, vma);
}

/// Linux `vm_ops->close(vma)`: this VMA no longer references the object. The
/// object's own hook owns whatever it charged while mapped; the SysV slot
/// owns the last-close destroy decision.
/// # C: O(1) plus the callback
pub(crate) fn vma_closed(vma: &Vma) {
    if let Some(b) = object_of(vma) { b.vma_close(); }
    dispatch(&CLOSE, vma);
}

/// Linux `vm_ops->may_split(vma, addr)`: whether the mapped object tolerates
/// its VMA being cut at an interior address. # C: O(1)
pub(crate) fn vma_may_split(vma: &Vma) -> bool {
    object_of(vma).is_none_or(|b| b.may_split())
}
