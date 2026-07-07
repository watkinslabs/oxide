use super::types::{LinuxClass, LinuxDevice};
use alloc::alloc::{alloc, dealloc, Layout};
use core::mem::size_of;
use core::ptr::{null_mut, write_bytes};

pub(super) fn alloc_device() -> *mut LinuxDevice {
    let p = alloc_zeroed::<LinuxDevice>();
    if !p.is_null() {
        // SAFETY: p has LinuxDevice layout and was just zero-initialized.
        unsafe { (*p).coherent_dma_mask = u64::MAX; }
    }
    p
}

pub(super) fn free_device(dev: *mut LinuxDevice) {
    free_typed(dev);
}

pub(super) fn alloc_class() -> *mut LinuxClass {
    alloc_zeroed::<LinuxClass>()
}

pub(super) fn free_class(class: *mut LinuxClass) {
    free_typed(class);
}

fn alloc_zeroed<T>() -> *mut T {
    let layout = Layout::new::<T>();
    // SAFETY: layout describes one T allocation exactly.
    let p = unsafe { alloc(layout) as *mut T };
    if p.is_null() { return null_mut(); }
    // SAFETY: p covers one T allocation and size_of::<T>() bytes.
    unsafe { write_bytes(p as *mut u8, 0, size_of::<T>()); }
    p
}

fn free_typed<T>(ptr: *mut T) {
    if ptr.is_null() { return; }
    // SAFETY: ptr was allocated by alloc_zeroed with Layout::new::<T>().
    unsafe { dealloc(ptr as *mut u8, Layout::new::<T>()); }
}
