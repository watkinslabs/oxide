// D5b-1 DRM dumb buffers + ADDFB2 (offscreen half). Real, no façade:
//   - MODE_CREATE_DUMB allocates contiguous physical pages via the PMM
//     buddy and tracks them in a DRM-card-owned handle table.
//   - MODE_MAP_DUMB returns a DRM mmap cookie; mmap pins are tracked as
//     object refs so backing pages cannot be freed while a VMA can fault them.
//   - MODE_DESTROY_DUMB frees the pages once no FB or mmap references them.
//   - MODE_ADDFB2 / MODE_ADDFB build a metadata-only FB object that
//     bumps the dumb handle refcount (NO virtio-gpu resource — that's
//     D5b-2 SETCRTC).
//   - MODE_RMFB drops the FB object + unrefs its handles.
//
// This slice does NOT touch the scanout. No SETCRTC, no flip, so the
// fb console is unaffected.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as DumbLockClass};

use crate::{DRM_FORMAT_ARGB8888, DRM_FORMAT_XRGB8888};

pub const DRM_MODE_FB_MODIFIERS: u32 = 1 << 1;

mod uapi;
pub use uapi::{
    DrmModeCreateDumb,
    DrmModeDestroyDumb,
    DrmModeFbCmd,
    DrmModeFbCmd2,
    DrmModeMapDumb,
};

mod math;
pub use math::{
    align_up_u64,
    cookie_for,
    dumb_pitch,
    dumb_size,
    fb_plane_fits_buf,
    format_cpp,
    format_supported,
    handle_of_cookie,
    order_for_bytes,
    DRM_MMAP_COOKIE_BASE,
};
mod tables;
pub use tables::{
    alloc_dumb_handle,
    alloc_fb_id,
    bind_fb_scanout_resource,
    clear_card_state,
    cursor_source,
    mmap_backing,
    pin_mmap,
    ref_cursor_handle,
    unref_cursor_handle,
    unpin_mmap,
    DumbBuf,
    DumbMmapPin,
    DumbTables,
    FbObj,
    TABLES,
};
use tables::release_scanout_resource;

mod ioctl;
pub use ioctl::{addfb, addfb2, create_dumb, destroy_dumb, map_dumb, rmfb};

#[cfg(test)]
mod tests;
