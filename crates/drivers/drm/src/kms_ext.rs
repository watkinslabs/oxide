// Additional legacy-KMS ioctl handlers split out of modeset.rs/crtc.rs to keep
// both under the file-length cap: SETPLANE, DIRTYFB, OBJ_SETPROPERTY,
// SETPROPERTY, GET/SETGAMMA, GETFB. The scanout-driving ones (SETPLANE, DIRTYFB)
// reuse crtc.rs's `fb_scanout_resource` + owner/current-fb state so there is a
// single scanout-commit path. All user copies bounds-check and use volatile
// access through the caller's AS at CPL=0; struct layouts are the repr(C) UAPI
// structs (no inline field offsets).

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};

use sync::{Spinlock, TaskList as CursorLockClass};

use syscall::errno::Errno;

use crate::node::scanout_ops;
use crate::{DrmDriver, crtc_idx_of};
use crate::{DrmModeSetPlane, DrmModeFbDirtyCmd, DrmModeObjSetProperty,
            DrmModeConnectorSetProperty, DrmModeCrtcLut, DrmModeFbCmd,
            DrmModeCursor, DrmModeCursor2, DRM_MODE_CURSOR_BO, DRM_MODE_CURSOR_MOVE,
            DRM_FORMAT_ARGB8888};

/// XRGB8888/ARGB8888 are 32 bits-per-pixel with 24-bit color depth (the X/A
/// byte is not counted in DRM "depth"). The only scanout formats we serve.
const FB_BITS_PER_PIXEL: u32 = 32;
const FB_COLOR_DEPTH:    u32 = 24;
/// A gamma LUT entry is one `u16` in `[0, GAMMA_ENTRY_MAX]`.
const GAMMA_ENTRY_BYTES: u64 = 2;
const GAMMA_ENTRY_MAX:   u64 = 0xFFFF;

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

#[derive(Copy, Clone)]
struct CursorState {
    card_id: u32,
    handle: u32,
    res_id: u32,
}

static CURSORS: Spinlock<Vec<CursorState>, CursorLockClass> = Spinlock::new(Vec::new());

fn take_cursor(card_id: u32) -> Option<CursorState> {
    let mut cursors = CURSORS.lock();
    let idx = cursors.iter().position(|state| state.card_id == card_id)?;
    Some(cursors.remove(idx))
}

fn release_cursor(card_id: u32, state: CursorState) {
    if let Some(ops) = scanout_ops(card_id) {
        let _ = (ops.destroy_resource)(ops.driver_key, state.res_id);
    }
    crate::dumb::unref_cursor_handle(card_id, state.handle);
}

/// Drop the current hardware cursor before card teardown. Called while the
/// scanout backend is still registered, preserving resource and dumb-buffer
/// ownership symmetry.
pub(crate) fn clear_cursor_state(card_id: u32) {
    if let Some(state) = take_cursor(card_id) {
        release_cursor(card_id, state);
    }
}

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
    let idx = match card.plane_ids().iter().position(|id| *id == p.plane_id) { Some(i) => i, None => return einval() };
    let ops = match scanout_ops(card_id) { Some(o) => o, None => return einval() };
    // The virtio GPU exposes a primary/cursor pair for each enabled CRTC.
    // Overlay planes remain absent. A cursor plane maps its framebuffer to a
    // real virtio resource then publishes it through CURSORQ.
    if idx & 1 != 0 {
        if crtc_idx_of(p.crtc_id, card.crtc_ids().len()).is_none() || p.flags != 0 { return einval(); }
        if p.fb_id == 0 {
            if !(ops.set_cursor)(ops.driver_key, 0, 0, 0, p.crtc_x, p.crtc_y, 0, 0) { return einval(); }
            if let Some(old) = take_cursor(card_id) { release_cursor(card_id, old); }
            return 0;
        }
        let (res_id, w, h) = match crate::crtc::fb_scanout_resource(card_id, ops, p.fb_id) {
            Some(v) => v, None => return einval(),
        };
        if w > 64 || h > 64 || p.crtc_w != w || p.crtc_h != h
            || p.src_x != 0 || p.src_y != 0 || p.src_w != (w as u64) << 16 || p.src_h != (h as u64) << 16 {
            return einval();
        }
        return if (ops.set_cursor)(ops.driver_key, res_id, w, h, p.crtc_x, p.crtc_y, 0, 0) { 0 } else { einval() };
    }
    if idx != 0 { return einval(); }
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

/// Shared implementation of legacy CURSOR and CURSOR2. Both perform the
/// Linux BO and MOVE operations; CURSOR2 additionally preserves hotspot
/// coordinates. Cursor backing is held independently of the user handle for
/// as long as the device can scan it out.
fn set_cursor(card_id: u32, card: &Arc<dyn DrmDriver>, flags: u32, crtc_id: u32,
    x: i32, y: i32, width: u32, height: u32, handle: u32, hot_x: i32, hot_y: i32) -> i64 {
    if flags == 0 || flags & !(DRM_MODE_CURSOR_BO | DRM_MODE_CURSOR_MOVE) != 0 {
        return einval();
    }
    if crtc_idx_of(crtc_id, card.crtc_ids().len()).is_none() { return einval(); }
    let ops = match scanout_ops(card_id) { Some(ops) => ops, None => return einval() };
    if flags & DRM_MODE_CURSOR_BO == 0 {
        let active = CURSORS.lock().iter().any(|state| state.card_id == card_id);
        return if active && (ops.move_cursor)(ops.driver_key, x, y) { 0 } else { einval() };
    }
    if handle == 0 {
        if !(ops.set_cursor)(ops.driver_key, 0, 0, 0, x, y, 0, 0) { return einval(); }
        if let Some(old) = take_cursor(card_id) { release_cursor(card_id, old); }
        return 0;
    }
    if width == 0 || height == 0 || width > 64 || height > 64 || hot_x < 0 || hot_y < 0
        || hot_x as u32 >= width || hot_y as u32 >= height {
        return einval();
    }
    let (pa, buf_w, buf_h, pitch) = match crate::dumb::cursor_source(card_id, handle) {
        Some(source) => source,
        None => return einval(),
    };
    // The 2D virtio resource derives stride as width*4. Do not silently
    // reinterpret a padded dumb buffer as tightly packed cursor pixels.
    if buf_w != width || buf_h != height || pitch != width.saturating_mul(4) {
        return einval();
    }
    if !crate::dumb::ref_cursor_handle(card_id, handle) { return einval(); }
    let Some(res_id) = (ops.create_from_pa)(ops.driver_key, pa, width, height, DRM_FORMAT_ARGB8888) else {
        crate::dumb::unref_cursor_handle(card_id, handle);
        return einval();
    };
    if !(ops.set_cursor)(ops.driver_key, res_id, width, height, x, y, hot_x, hot_y) {
        let _ = (ops.destroy_resource)(ops.driver_key, res_id);
        crate::dumb::unref_cursor_handle(card_id, handle);
        return einval();
    }
    let old = {
        let mut cursors = CURSORS.lock();
        let old = cursors.iter().position(|state| state.card_id == card_id).map(|idx| cursors.remove(idx));
        cursors.push(CursorState { card_id, handle, res_id });
        old
    };
    if let Some(old) = old { release_cursor(card_id, old); }
    0
}

/// `MODE_CURSOR` legacy cursor ioctl. # C: O(n) table lookup + device work.
pub fn cursor(card_id: u32, card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeCursor>() as u64) { return einval(); }
    let cursor = unsafe { core::ptr::read_volatile(arg as *const DrmModeCursor) };
    set_cursor(card_id, card, cursor.flags, cursor.crtc_id, cursor.x, cursor.y,
        cursor.width, cursor.height, cursor.handle, 0, 0)
}

/// `MODE_CURSOR2` cursor ioctl with a hotspot. # C: O(n) + device work.
pub fn cursor2(card_id: u32, card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeCursor2>() as u64) { return einval(); }
    let cursor = unsafe { core::ptr::read_volatile(arg as *const DrmModeCursor2) };
    set_cursor(card_id, card, cursor.flags, cursor.crtc_id, cursor.x, cursor.y,
        cursor.width, cursor.height, cursor.handle, cursor.hot_x, cursor.hot_y)
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
