// Linux fbdev compat shim per docs/48. /dev/fb0..fbN over a DRM
// dumb-buffer + scanout. Full FBIO* ioctl surface per
// linux/include/uapi/linux/fb.h. No DRM modeset privileges
// needed; this crate is a thin presenter on top of `47`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

mod uapi;
pub use uapi::*;

mod registry;
pub use registry::{
    apply_blank, backing_of, blank_of, clear_ops, count, fix_of, flush, init_scanout,
    is_blank_level, kva_of, line_length, pack_pseudo, palette_at, pan_check, register,
    set_blank, set_ops, set_palette, set_var, unregister, unregister_by_base, unpack_pseudo,
    var_of, Error, FbDev, FbOps, KResult, FBS, INVALID_FB_INDEX,
};

mod vblank;
pub use vblank::{
    clear_wait_hooks, set_now_hook, set_yield_hook, vblank_seq, vblank_tick, wait_vblank,
    VSYNC_DEADLINE_NS,
};
#[cfg(test)]
use vblank::{NOW_HOOK, VBLANK_SEQ, YIELD_HOOK};
#[cfg(not(test))]
use vblank::VBLANK_SEQ;

#[cfg(test)]
mod tests;

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod devfs;
