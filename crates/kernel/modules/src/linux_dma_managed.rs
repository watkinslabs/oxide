use crate::linux_device::devres;
use crate::linux_device::types::LinuxDevice;
use crate::linux_dma::{dma_alloc_attrs, dma_free_attrs};
use core::ffi::c_void;
use sync::{Modules as ModulesLockClass, Spinlock};

const MAX_MANAGED_DMA: usize = 128;

#[derive(Copy, Clone)]
struct ManagedDma { dev: usize, size: usize, cpu_addr: usize, dma_handle: u64, attrs: u64 }

static MANAGED_DMA: Spinlock<[Option<ManagedDma>; MAX_MANAGED_DMA], ModulesLockClass> = Spinlock::new([None; MAX_MANAGED_DMA]);

/// Allocate DMA memory whose lifetime follows the owning Linux device. # C: O(N_records)
pub(crate) extern "C" fn dmam_alloc_attrs(dev: *mut LinuxDevice, size: usize, dma_handle: *mut u64, flags: u64, attrs: u64) -> *mut c_void {
    if dev.is_null() { return core::ptr::null_mut(); }
    let cpu_addr = dma_alloc_attrs(dev, size, dma_handle, flags, attrs);
    if cpu_addr.is_null() { return core::ptr::null_mut(); }
    // SAFETY: dma_alloc_attrs only succeeds with a non-null caller-provided DMA-handle output.
    let handle = unsafe { *dma_handle };
    let rec = ManagedDma { dev: dev as usize, size, cpu_addr: cpu_addr as usize, dma_handle: handle, attrs };
    if !insert(rec) {
        dma_free_attrs(dev, size, cpu_addr, handle, attrs);
        return core::ptr::null_mut();
    }
    if devres::add_action_or_reset(dev, Some(release_action), cpu_addr) != 0 { return core::ptr::null_mut(); }
    cpu_addr
}

/// Allocate coherent DMA memory with device-resource ownership. # C: O(N_records)
pub(crate) extern "C" fn dmam_alloc_coherent(dev: *mut LinuxDevice, size: usize, dma_handle: *mut u64, flags: u64) -> *mut c_void {
    dmam_alloc_attrs(dev, size, dma_handle, flags, 0)
}

/// Release a managed coherent allocation before device detach. # C: O(N_records)
pub(crate) extern "C" fn dmam_free_coherent(dev: *mut LinuxDevice, size: usize, cpu_addr: *mut c_void, dma_handle: u64) {
    if dev.is_null() || cpu_addr.is_null() { return; }
    devres::remove_action(dev, Some(release_action), cpu_addr);
    if !release(cpu_addr as usize) { dma_free_attrs(dev, size, cpu_addr, dma_handle, 0); }
}

unsafe extern "C" fn release_action(data: *mut c_void) {
    let _ = release(data as usize);
}

fn insert(rec: ManagedDma) -> bool {
    let mut g = MANAGED_DMA.lock();
    let Some(slot) = g.iter_mut().find(|slot| slot.is_none()) else { return false; };
    *slot = Some(rec);
    true
}

fn release(cpu_addr: usize) -> bool {
    let rec = {
        let mut g = MANAGED_DMA.lock();
        let Some(slot) = g.iter_mut().find(|slot| slot.is_some_and(|r| r.cpu_addr == cpu_addr)) else { return false; };
        let Some(rec) = slot.take() else { return false; };
        rec
    };
    dma_free_attrs(rec.dev as *mut LinuxDevice, rec.size, rec.cpu_addr as *mut c_void, rec.dma_handle, rec.attrs);
    true
}

#[cfg(test)]
pub(crate) fn tracked(dev: *mut LinuxDevice) -> usize {
    MANAGED_DMA.lock().iter().flatten().filter(|rec| rec.dev == dev as usize).count()
}
