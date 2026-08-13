//! DMA-fence signal-state ABI helpers.

use core::ffi::c_void;
use core::ptr::read;

const OPS_OFF: usize = 8; const FLAGS_OFF: usize = 48; const SIGNALED: usize = 1 << 3; const SIGNALED_OP: usize = 24;

pub fn export_symbols() { crate::symtab::export("dma_fence_is_signaled", dma_fence_is_signaled as *const () as usize, false); }

/// Test the published fence signal bit, consulting the driver's optional fast-path callback. # C: O(1)
extern "C" fn dma_fence_is_signaled(fence: *mut c_void) -> bool {
    if fence.is_null() { return false; }
    let f = fence.cast::<u8>();
    // SAFETY: caller owns the live DMA-fence reference while querying its immutable ops and atomic signal flag.
    unsafe { if read(f.add(FLAGS_OFF).cast::<usize>()) & SIGNALED != 0 { return true; } let ops = read(f.add(OPS_OFF).cast::<*const u8>()); if ops.is_null() { return false; } let callback = read(ops.add(SIGNALED_OP).cast::<usize>()); callback != 0 && core::mem::transmute::<usize, unsafe extern "C" fn(*mut c_void) -> bool>(callback)(fence) }
}
