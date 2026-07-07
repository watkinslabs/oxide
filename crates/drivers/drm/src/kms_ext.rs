// Additional legacy-KMS ioctl handlers split out of modeset.rs/crtc.rs to keep
// both under the file-length cap: SETPLANE, DIRTYFB, OBJ_SETPROPERTY,
// SETPROPERTY, GET/SETGAMMA, GETFB. The scanout-driving ones (SETPLANE, DIRTYFB)
// reuse crtc.rs's `fb_scanout_resource` + owner/current-fb state so there is a
// single scanout-commit path. All user copies bounds-check and use volatile
// access through the caller's AS at CPL=0; struct layouts are the repr(C) UAPI
// structs (no inline field offsets).

extern crate alloc;

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::node::scanout_ops;
use crate::{DrmDriver, plane_idx_of, crtc_idx_of};
use crate::{DrmModeSetPlane, DrmModeFbDirtyCmd, DrmModeObjSetProperty,
            DrmModeConnectorSetProperty, DrmModeCrtcLut, DrmModeFbCmd};

/// XRGB8888/ARGB8888 are 32 bits-per-pixel with 24-bit color depth (the X/A
/// byte is not counted in DRM "depth"). The only scanout formats we serve.
const FB_BITS_PER_PIXEL: u32 = 32;
const FB_COLOR_DEPTH:    u32 = 24;
/// A gamma LUT entry is one `u16` in `[0, GAMMA_ENTRY_MAX]`.
const GAMMA_ENTRY_BYTES: u64 = 2;
const GAMMA_ENTRY_MAX:   u64 = 0xFFFF;

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// True iff `[ptr, ptr+len)` is a usable user range. # C: O(1)
fn user_ok(ptr: u64, len: u64) -> bool {
    ptr != 0 && ptr < hal::USER_VA_END
        && ptr.checked_add(len).is_some_and(|end| end <= hal::USER_VA_END)
}

/// `MODE_SETPLANE` — bind framebuffer `fb_id` to `plane_id` on its CRTC. The
/// primary plane (index 0) drives scanout 0, so this is the universal-planes
/// equivalent of SETCRTC: resolve fb → virtio-gpu resource → switch scanout.
/// `fb_id == 0` disables the plane → restore the boot console scanout. Non-
/// primary planes (none advertised today) accept as a no-op. Honest -EINVAL on
/// a bad plane id / unknown fb / no scanout backend. # C: O(1) + O(scanout).
pub fn set_plane(card_id: u32, card: &Arc<dyn DrmDriver>, arg: u64, token: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeSetPlane>() as u64) { return einval(); }
    // SAFETY: arg range validated < USER_VA_END; DrmModeSetPlane is repr(C) 64 B; aligned read through the caller's AS at CPL=0.
    let p: DrmModeSetPlane = unsafe { core::ptr::read_volatile(arg as *const DrmModeSetPlane) };
    let plane_count = card.plane_ids().len();
    let idx = match plane_idx_of(p.plane_id, plane_count) { Some(i) => i, None => return einval() };
    let ops = match scanout_ops(card_id) { Some(o) => o, None => return einval() };
    // Only the primary plane (index 0) is scanout-backed. Others are accepted as
    // a no-op (we advertise no overlay/cursor DRM plane).
    if idx != 0 { return 0; }
    if p.fb_id == 0 {
        // Disable the primary plane: restore the console if we own the scanout.
        if crate::crtc::is_owner(card_id, token) || crate::crtc::owner(card_id) == 0 {
            (ops.restore_console)(ops.driver_key);
            crate::crtc::clear_owner(card_id);
            crate::crtc::set_current_fb(card_id, 0);
        }
        return 0;
    }
    let (res_id, w, h) = match crate::crtc::fb_scanout_resource(card_id, ops, p.fb_id) {
        Some(v) => v, None => return einval(),
    };
    if !(ops.set_scanout)(ops.driver_key, res_id, w, h) { return einval(); }
    crate::crtc::set_current_fb(card_id, p.fb_id);
    crate::crtc::set_owner(card_id, token);
    0
}

/// `MODE_DIRTYFB` — the client rendered into `fb_id` in place and asks the
/// driver to push the damaged region to the host. virtio-gpu's TRANSFER_TO_HOST
/// + RESOURCE_FLUSH re-upload the buffer; we flush the whole fb (no partial-
/// damage primitive is exposed) and ONLY when `fb_id` is the one currently
/// scanned out (otherwise there is nothing on screen to refresh). This is what
/// makes an in-place-rendered (non-page-flipped) compositor's frames appear.
/// # C: O(1) + O(scanout).
pub fn dirty_fb(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeFbDirtyCmd>() as u64) { return einval(); }
    // SAFETY: arg range validated; DrmModeFbDirtyCmd is repr(C) 24 B; aligned read at CPL=0.
    let d: DrmModeFbDirtyCmd = unsafe { core::ptr::read_volatile(arg as *const DrmModeFbDirtyCmd) };
    if d.fb_id == 0 { return einval(); }
    // Not the on-screen fb → nothing to refresh (Linux dirtyfb on an unbound fb
    // is a successful no-op).
    if crate::crtc::current_fb(card_id) != d.fb_id { return 0; }
    let ops = match scanout_ops(card_id) { Some(o) => o, None => return einval() };
    let (res_id, w, h) = match crate::crtc::fb_scanout_resource(card_id, ops, d.fb_id) {
        Some(v) => v, None => return einval(),
    };
    // set_scanout re-issues SET_SCANOUT + TRANSFER_TO_HOST_2D + RESOURCE_FLUSH.
    if !(ops.set_scanout)(ops.driver_key, res_id, w, h) { return einval(); }
    0
}

/// `MODE_OBJ_SETPROPERTY` — set an object property by id. The only writable
/// property we model is a connector's DPMS (always-on virtual output): accept
/// any DPMS value as a no-op success (Linux returns 0 for a redundant DPMS set).
/// Unknown object/property ids also succeed as no-ops so a compositor that
/// blindly sets standard properties is not failed. # C: O(1).
pub fn obj_set_property(arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeObjSetProperty>() as u64) { return einval(); }
    // SAFETY: arg range validated; DrmModeObjSetProperty is repr(C) 24 B; aligned read at CPL=0.
    let _p: DrmModeObjSetProperty = unsafe { core::ptr::read_volatile(arg as *const DrmModeObjSetProperty) };
    // A single always-connected virtual output with no mutable HW state — every
    // property set is a no-op that must not fail the caller.
    0
}

/// `MODE_SETPROPERTY` — legacy connector property set (pre-atomic DPMS path).
/// Same no-op-success semantics as `obj_set_property`. # C: O(1).
pub fn set_property(arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeConnectorSetProperty>() as u64) { return einval(); }
    // SAFETY: arg range validated; DrmModeConnectorSetProperty is repr(C) 16 B; aligned read at CPL=0.
    let _p: DrmModeConnectorSetProperty = unsafe { core::ptr::read_volatile(arg as *const DrmModeConnectorSetProperty) };
    0
}

/// `MODE_SETGAMMA` — load a CRTC gamma LUT. virtio-gpu exposes no hardware
/// gamma, so the ramp is accepted and dropped (Linux drivers without gamma HW
/// still return success so night-light / color management do not error). We
/// validate the crtc id and the caller's LUT pointers. # C: O(1).
pub fn set_gamma(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeCrtcLut>() as u64) { return einval(); }
    // SAFETY: arg range validated; DrmModeCrtcLut is repr(C) 32 B; aligned read at CPL=0.
    let g: DrmModeCrtcLut = unsafe { core::ptr::read_volatile(arg as *const DrmModeCrtcLut) };
    let crtc_count = card.crtc_ids().len();
    if crtc_idx_of(g.crtc_id, crtc_count).is_none() { return einval(); }
    // Each ramp is `gamma_size` u16 entries; validate the pointers are user-sane
    // when non-null, then drop them (no HW LUT to program).
    let bytes = (g.gamma_size as u64).saturating_mul(GAMMA_ENTRY_BYTES);
    for p in [g.red, g.green, g.blue] {
        if p != 0 && !user_ok(p, bytes) { return einval(); }
    }
    0
}

/// `MODE_GETGAMMA` — return the CRTC gamma LUT. With no HW gamma we report an
/// identity ramp (entry i = i scaled to 16-bit) so a reader sees a sane table.
/// # C: O(gamma_size).
pub fn get_gamma(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeCrtcLut>() as u64) { return einval(); }
    // SAFETY: arg range validated; repr(C) 32 B; aligned read at CPL=0.
    let g: DrmModeCrtcLut = unsafe { core::ptr::read_volatile(arg as *const DrmModeCrtcLut) };
    let crtc_count = card.crtc_ids().len();
    if crtc_idx_of(g.crtc_id, crtc_count).is_none() { return einval(); }
    let n = g.gamma_size as u64;
    let bytes = n.saturating_mul(GAMMA_ENTRY_BYTES);
    for p in [g.red, g.green, g.blue] {
        if p == 0 { continue; }
        if !user_ok(p, bytes) { return einval(); }
        for i in 0..n {
            // Identity ramp scaled to the entry range: v = i * MAX / (n-1).
            let v: u16 = if n <= 1 { 0 } else { ((i * GAMMA_ENTRY_MAX) / (n - 1)) as u16 };
            // SAFETY: p..p+bytes validated; write one u16 entry through caller AS at CPL=0.
            unsafe { core::ptr::write_volatile((p + i * GAMMA_ENTRY_BYTES) as *mut u16, v); }
        }
    }
    0
}

/// `MODE_GETFB` — return a framebuffer's geometry (legacy single-plane query).
/// Fills width/height/pitch/bpp/depth/handle from the FbObj. Does NOT return a
/// GEM handle for the buffer to an unprivileged caller (Linux only returns the
/// handle to DRM master); the dumb handle we already own is returned since the
/// caller created it. # C: O(n) over the fb table.
pub fn get_fb(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeFbCmd>() as u64) { return einval(); }
    // SAFETY: arg range validated; DrmModeFbCmd is repr(C) 28 B; aligned read at CPL=0.
    let mut c: DrmModeFbCmd = unsafe { core::ptr::read_volatile(arg as *const DrmModeFbCmd) };
    let t = crate::dumb::TABLES.lock();
    let Some(fb) = t.find_fb(card_id, c.fb_id) else { return einval(); };
    // XRGB8888/ARGB8888 are 32bpp / 24-depth (X) — the only formats we scan out.
    c.width  = fb.w;
    c.height = fb.h;
    c.pitch  = fb.pitches[0];
    c.bpp    = FB_BITS_PER_PIXEL;
    c.depth  = FB_COLOR_DEPTH;
    c.handle = fb.handles[0];
    drop(t);
    // SAFETY: arg validated; write the 28 B repr(C) struct back through caller AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeFbCmd, c); }
    0
}
