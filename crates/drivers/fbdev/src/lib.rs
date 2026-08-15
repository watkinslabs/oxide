// Linux fbdev compat shim per docs/48. /dev/fb0..fbN over a DRM
// dumb-buffer + scanout. Full FBIO* ioctl surface per the Linux
// fbdev UAPI. No DRM modeset privileges
// needed; this crate is a thin presenter on top of `47`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

mod uapi;
pub use uapi::*;

mod registry;
pub use registry::{
    apply_blank, backing_of, backing_with_cache_of, blank_of, clear_ops, count, fix_of, flush,
    init_scanout, init_scanout_configured, init_scanout_with_cache, is_blank_level, kva_of, line_length, pack_pseudo,
    palette_at, pan_check, register,
    set_blank, set_ops, set_palette, set_var, unregister, unregister_by_base, unpack_pseudo,
    var_of, Error, FbDev, FbDriverKey, FbOps, KResult, FBS, INVALID_FB_INDEX,
};

mod aperture;
pub use aperture::{
    acquire_aperture, release_aperture, remove_conflicting_apertures, ApertureError, ApertureKey,
    ApertureResult,
};

#[cfg(test)]
mod test_claim;

#[cfg(test)]
mod tests;

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod devfs;
