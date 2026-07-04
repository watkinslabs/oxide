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
//
// All user copies bounds-check the pointer (< hal::USER_VA_END) and use
// volatile reads/writes through the caller's address space at CPL=0.
// UAPI struct layouts copied from linux/include/uapi/drm/drm_mode.h
// EXACTLY (create_dumb 32 B, map_dumb 16 B, fb_cmd2 with the arrays).

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as DumbLockClass};

use crate::{DRM_FORMAT_XRGB8888, DRM_FORMAT_ARGB8888};

pub const DRM_MODE_FB_MODIFIERS: u32 = 1 << 1;

// ============================================================
// UAPI wire structs (drm_mode.h)
// ============================================================

/// `struct drm_mode_create_dumb` — 32 bytes. # C: ABI
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeCreateDumb {
    pub height: u32,
    pub width:  u32,
    pub bpp:    u32,
    pub flags:  u32,
    // out
    pub handle: u32,
    pub pitch:  u32,
    pub size:   u64,
}

/// `struct drm_mode_map_dumb` — 16 bytes. # C: ABI
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeMapDumb {
    pub handle: u32,
    pub pad:    u32,
    // out
    pub offset: u64,
}

/// `struct drm_mode_destroy_dumb` — 4 bytes. # C: ABI
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeDestroyDumb {
    pub handle: u32,
}

/// `struct drm_mode_fb_cmd2` — 0xc06864b8, 104 bytes (modifier[4]). # C: ABI
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeFbCmd2 {
    pub fb_id:        u32,
    pub width:        u32,
    pub height:       u32,
    pub pixel_format: u32,
    pub flags:        u32,
    pub handles:      [u32; 4],
    pub pitches:      [u32; 4],
    pub offsets:      [u32; 4],
    pub modifier:     [u64; 4],
}

/// `struct drm_mode_fb_cmd` (legacy ADDFB) — 0xc01c64ae, 28 bytes.
/// # C: ABI
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeFbCmd {
    pub fb_id:  u32,
    pub width:  u32,
    pub height: u32,
    pub pitch:  u32,
    pub bpp:    u32,
    pub depth:  u32,
    pub handle: u32,
}

// ============================================================
// Pure math (hosted-testable)
// ============================================================

/// Pitch = align_up(width*bpp/8, 64) per Linux dumb-buffer convention.
/// Returns `None` on overflow / bad bpp. # C: O(1)
pub fn dumb_pitch(width: u32, bpp: u32) -> Option<u32> {
    // Linux dumb buffers support 8/16/24/32 bpp; we map to byte widths.
    if bpp == 0 || bpp > 32 || (bpp % 8) != 0 { return None; }
    let bytes_per_px = bpp / 8;
    let raw = (width as u64).checked_mul(bytes_per_px as u64)?;
    let aligned = align_up_u64(raw, 64);
    if aligned > u32::MAX as u64 { return None; }
    Some(aligned as u32)
}

/// Size = align_up(pitch*height, 4096). `None` on overflow.
/// # C: O(1)
pub fn dumb_size(pitch: u32, height: u32) -> Option<u64> {
    let raw = (pitch as u64).checked_mul(height as u64)?;
    Some(align_up_u64(raw, 4096))
}

/// align_up(v, a) for power-of-two `a`. # C: O(1)
pub fn align_up_u64(v: u64, a: u64) -> u64 { (v + (a - 1)) & !(a - 1) }

/// PMM buddy order covering `bytes`: ceil_log2(ceil(bytes/4096)).
/// # C: O(1)
pub fn order_for_bytes(bytes: u64) -> u8 {
    let frames = (bytes + 4095) / 4096;
    if frames <= 1 { return 0; }
    // ceil_log2(frames)
    let mut o = 0u8;
    let mut cap = 1u64;
    while cap < frames { cap <<= 1; o += 1; }
    o
}

/// True iff `fourcc` is a format we accept for FB objects. # C: O(1)
pub fn format_supported(fourcc: u32) -> bool {
    fourcc == DRM_FORMAT_XRGB8888 || fourcc == DRM_FORMAT_ARGB8888
}

/// Bytes per pixel for formats this dumb-buffer path can expose.
/// # C: O(1)
pub fn format_cpp(fourcc: u32) -> Option<u32> {
    match fourcc {
        DRM_FORMAT_XRGB8888 | DRM_FORMAT_ARGB8888 => Some(4),
        _ => None,
    }
}

/// True iff plane 0 describes a framebuffer fully inside `buf`.
/// # C: O(1)
pub fn fb_plane_fits_buf(
    width: u32,
    height: u32,
    pixel_format: u32,
    pitch: u32,
    offset: u32,
    buf: &DumbBuf,
) -> bool {
    if width == 0 || height == 0 {
        return false;
    }
    let Some(cpp) = format_cpp(pixel_format) else {
        return false;
    };
    let row_bytes = match (width as u64).checked_mul(cpp as u64) {
        Some(bytes) => bytes,
        None => return false,
    };
    if (pitch as u64) < row_bytes {
        return false;
    }
    let last_row = match (pitch as u64).checked_mul((height - 1) as u64) {
        Some(bytes) => bytes,
        None => return false,
    };
    let span = match last_row.checked_add(row_bytes) {
        Some(bytes) => bytes,
        None => return false,
    };
    match (offset as u64).checked_add(span) {
        Some(end) => end <= buf.size,
        None => false,
    }
}

/// DRM mmap-cookie space. Linux treats MODE_MAP_DUMB's returned offset as an
/// opaque driver token; keep the tag above every possible `u32 << PAGE_SHIFT`
/// handle value so the cookie cannot alias another handle or fbdev offset 0.
/// # C: O(1)
pub const DRM_MMAP_COOKIE_BASE: u64 = 1u64 << 48;
const DRM_MMAP_COOKIE_HANDLE_SHIFT: u64 = 12;
const DRM_MMAP_COOKIE_HANDLE_MASK: u64 = (u32::MAX as u64) << DRM_MMAP_COOKIE_HANDLE_SHIFT;
const DRM_MMAP_COOKIE_VALID_MASK: u64 = DRM_MMAP_COOKIE_BASE | DRM_MMAP_COOKIE_HANDLE_MASK;
/// Build the MAP_DUMB cookie for `handle`. # C: O(1)
pub fn cookie_for(handle: u32) -> u64 {
    DRM_MMAP_COOKIE_BASE | ((handle as u64) << DRM_MMAP_COOKIE_HANDLE_SHIFT)
}
/// Recover the handle from a cookie, or `None` if not a DRM cookie.
/// # C: O(1)
pub fn handle_of_cookie(cookie: u64) -> Option<u32> {
    if (cookie & DRM_MMAP_COOKIE_BASE) != DRM_MMAP_COOKIE_BASE { return None; }
    if (cookie & !DRM_MMAP_COOKIE_VALID_MASK) != 0 { return None; }
    let handle = ((cookie & DRM_MMAP_COOKIE_HANDLE_MASK) >> DRM_MMAP_COOKIE_HANDLE_SHIFT) as u32;
    if handle == 0 { return None; }
    Some(handle)
}

// ============================================================
// Handle + FB tables
// ============================================================

/// A dumb buffer: physically-contiguous backing + geometry + refcount.
#[derive(Copy, Clone, Debug)]
pub struct DumbBuf {
    pub card_id: u32,
    pub handle: u32,
    pub pa:     u64,
    pub size:   u64,   // 4 KiB-aligned byte size actually mapped
    pub order:  u8,     // PMM buddy order the pages were allocated at
    pub w:      u32,
    pub h:      u32,
    pub pitch:  u32,
    pub bpp:    u32,
    pub refcnt: u32,   // open handle refs + FB refs
    pub mmap_refs: u32,
    pub deleted: bool,
}

/// An FB object: metadata referencing up to 4 dumb handles.
#[derive(Copy, Clone, Debug)]
pub struct FbObj {
    pub card_id:       u32,
    pub fb_id:        u32,
    pub w:            u32,
    pub h:            u32,
    pub pixel_format: u32,
    pub handles:      [u32; 4],
    pub pitches:      [u32; 4],
    pub offsets:      [u32; 4],
    pub scanout_res_id: u32,
}

/// DRM dumb/FB object tables. Handles and FB ids are globally allocated for
/// simple unique UAPI ids, but ownership checks are keyed by stable DRM card id.
pub struct DumbTables {
    pub bufs: Vec<DumbBuf>,
    pub fbs:  Vec<FbObj>,
}

impl DumbTables {
    const fn new() -> Self { Self { bufs: Vec::new(), fbs: Vec::new() } }

    /// Insert a freshly-allocated buffer with refcount 1. # C: O(1)
    pub fn insert_buf(&mut self, b: DumbBuf) { self.bufs.push(b); }

    /// Find a buffer by card id + handle. # C: O(n)
    pub fn find_buf(&self, card_id: u32, h: u32) -> Option<&DumbBuf> {
        self.bufs.iter().find(|b| b.card_id == card_id && b.handle == h && !b.deleted)
    }
    fn find_buf_mut(&mut self, card_id: u32, h: u32) -> Option<&mut DumbBuf> {
        self.bufs.iter_mut().find(|b| b.card_id == card_id && b.handle == h && !b.deleted)
    }

    /// Find an FB by card id + FB id. # C: O(n)
    pub fn find_fb(&self, card_id: u32, id: u32) -> Option<&FbObj> {
        self.fbs.iter().find(|f| f.card_id == card_id && f.fb_id == id)
    }
    pub fn find_fb_mut(&mut self, card_id: u32, id: u32) -> Option<&mut FbObj> {
        self.fbs.iter_mut().find(|f| f.card_id == card_id && f.fb_id == id)
    }

    /// Bump a handle's refcount. `false` if unknown. # C: O(n)
    pub fn ref_handle(&mut self, card_id: u32, h: u32) -> bool {
        match self.find_buf_mut(card_id, h) { Some(b) => { b.refcnt += 1; true } None => false }
    }

    /// Decrement a handle's refcount; return `Some((pa,order))` to free
    /// when it hit zero, else `None`. `false`-equivalent (None) also for
    /// unknown handle — caller distinguishes via a prior find. # C: O(n)
    pub fn unref_handle(&mut self, card_id: u32, h: u32) -> Option<(u64, u8)> {
        let idx = self.bufs.iter().position(|b| b.card_id == card_id && b.handle == h)?;
        if self.bufs[idx].refcnt > 0 { self.bufs[idx].refcnt -= 1; }
        if self.bufs[idx].refcnt == 0 {
            let b = self.bufs.remove(idx);
            Some((b.pa, b.order))
        } else { None }
    }

    /// Pin a buffer for a userspace mmap VMA. # C: O(n)
    pub fn pin_mmap(&mut self, card_id: u32, h: u32) -> Option<DumbMmapPin> {
        let b = self.find_buf_mut(card_id, h)?;
        b.refcnt = b.refcnt.saturating_add(1);
        b.mmap_refs = b.mmap_refs.saturating_add(1);
        Some(DumbMmapPin { card_id, handle: h, pa: b.pa, size: b.size })
    }

    /// Drop one userspace mmap VMA pin. Deleted buffers remain searchable here
    /// so their final VMA can release the backing after card unregister.
    /// # C: O(n)
    pub fn unpin_mmap(&mut self, card_id: u32, h: u32) -> Option<(u64, u8)> {
        let idx = self.bufs.iter().position(|b| b.card_id == card_id && b.handle == h)?;
        if self.bufs[idx].mmap_refs > 0 { self.bufs[idx].mmap_refs -= 1; }
        if self.bufs[idx].refcnt > 0 { self.bufs[idx].refcnt -= 1; }
        if self.bufs[idx].refcnt == 0 {
            let b = self.bufs.remove(idx);
            Some((b.pa, b.order))
        } else { None }
    }

    /// Remove all live FB objects and handles owned by `card_id`, returning
    /// buffer pages whose last non-VMA reference dropped. VMA-pinned buffers
    /// are marked deleted and stay until `unpin_mmap`.
    /// # C: O(n)
    pub fn remove_card(&mut self, card_id: u32) -> (Vec<(u64, u8)>, Vec<u32>) {
        let mut freed = Vec::new();
        let mut resources = Vec::new();
        let mut fb_idx = 0usize;
        while fb_idx < self.fbs.len() {
            if self.fbs[fb_idx].card_id != card_id {
                fb_idx += 1;
                continue;
            }
            let fb = self.fbs.remove(fb_idx);
            if fb.scanout_res_id != 0 {
                resources.push(fb.scanout_res_id);
            }
            for &h in fb.handles.iter() {
                if h != 0 {
                    if let Some(f) = self.unref_handle(card_id, h) { freed.push(f); }
                }
            }
        }
        let mut idx = 0usize;
        while idx < self.bufs.len() {
            if self.bufs[idx].card_id == card_id {
                self.bufs[idx].deleted = true;
                let non_mmap_refs = self.bufs[idx].refcnt.saturating_sub(self.bufs[idx].mmap_refs);
                self.bufs[idx].refcnt = self.bufs[idx].refcnt.saturating_sub(non_mmap_refs);
                if self.bufs[idx].refcnt == 0 {
                    let b = self.bufs.remove(idx);
                    freed.push((b.pa, b.order));
                } else {
                    idx += 1;
                }
            } else {
                idx += 1;
            }
        }
        (freed, resources)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DumbMmapPin {
    pub card_id: u32,
    pub handle:  u32,
    pub pa:      u64,
    pub size:    u64,
}

pub static TABLES: Spinlock<DumbTables, DumbLockClass> = Spinlock::new(DumbTables::new());
static NEXT_DUMB_HANDLE: AtomicU32 = AtomicU32::new(1);
static NEXT_FB_ID:       AtomicU32 = AtomicU32::new(1);

/// Fresh dumb-buffer handle id (counter, starts 1). # C: O(1)
pub fn alloc_dumb_handle() -> u32 { NEXT_DUMB_HANDLE.fetch_add(1, Ordering::AcqRel) }
/// Fresh FB-object id (counter, starts 1). # C: O(1)
pub fn alloc_fb_id() -> u32 { NEXT_FB_ID.fetch_add(1, Ordering::AcqRel) }

// ============================================================
// ioctl handlers (user-copy + PMM). Return the syscall rv.
// ============================================================

use syscall::errno::Errno;

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }
fn enomem() -> i64 { -(Errno::Enomem.as_i32() as i64) }

/// True iff `[ptr, ptr+len)` is a usable user range. # C: O(1)
fn user_ok(ptr: u64, len: u64) -> bool {
    ptr != 0 && ptr < hal::USER_VA_END && ptr.checked_add(len).is_some_and(|end| end <= hal::USER_VA_END)
}

fn release_scanout_resource(card_id: u32, res_id: u32) {
    if res_id == 0 {
        return;
    }
    if let Some(ops) = crate::node::scanout_ops(card_id) {
        let _ = (ops.destroy_resource)(ops.driver_key, res_id);
    }
}

/// Bind a newly-created backend scanout resource to an FB object. Returns
/// false if the FB disappeared or already had a resource. # C: O(n)
pub fn bind_fb_scanout_resource(card_id: u32, fb_id: u32, res_id: u32) -> bool {
    if res_id == 0 {
        return false;
    }
    let mut t = TABLES.lock();
    let Some(fb) = t.find_fb_mut(card_id, fb_id) else {
        return false;
    };
    if fb.scanout_res_id != 0 {
        return false;
    }
    fb.scanout_res_id = res_id;
    true
}

/// MODE_CREATE_DUMB: allocate contiguous pages, register a handle,
/// write back handle/pitch/size. # C: O(1)
pub fn create_dumb(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeCreateDumb>() as u64) { return einval(); }
    // SAFETY: arg range validated < USER_VA_END; drm_mode_create_dumb is 32 bytes; aligned struct read through caller's AS at CPL=0.
    let mut req: DrmModeCreateDumb = unsafe { core::ptr::read_volatile(arg as *const DrmModeCreateDumb) };
    let pitch = match dumb_pitch(req.width, req.bpp) { Some(p) => p, None => return einval() };
    let size  = match dumb_size(pitch, req.height) { Some(s) if s > 0 => s, _ => return einval() };
    let order = order_for_bytes(size);
    let pa = match pmm::setup::alloc_contig_object(pmm::Order(order)) { Some(p) => p, None => return enomem() };
    let handle = alloc_dumb_handle();
    TABLES.lock().insert_buf(DumbBuf {
        card_id, handle, pa, size, order,
        w: req.width, h: req.height, pitch, bpp: req.bpp, refcnt: 1,
        mmap_refs: 0, deleted: false,
    });
    req.handle = handle;
    req.pitch  = pitch;
    req.size   = size;
    // SAFETY: arg validated above; struct is 32 bytes; aligned write of the out fields through caller's AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeCreateDumb, req); }
    0
}

/// MODE_MAP_DUMB: return the DRM mmap cookie for the handle. # C: O(n)
pub fn map_dumb(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeMapDumb>() as u64) { return einval(); }
    // SAFETY: arg range validated < USER_VA_END; drm_mode_map_dumb is 16 bytes; aligned struct read through caller's AS at CPL=0.
    let mut req: DrmModeMapDumb = unsafe { core::ptr::read_volatile(arg as *const DrmModeMapDumb) };
    if TABLES.lock().find_buf(card_id, req.handle).is_none() { return einval(); }
    req.offset = cookie_for(req.handle);
    // SAFETY: arg validated above; struct is 16 bytes; aligned write of the offset out field through caller's AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeMapDumb, req); }
    0
}

/// MODE_DESTROY_DUMB: drop the open ref; free pages iff refcount hit 0.
/// # C: O(n)
pub fn destroy_dumb(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeDestroyDumb>() as u64) { return einval(); }
    // SAFETY: arg range validated < USER_VA_END; drm_mode_destroy_dumb is 4 bytes; aligned u32 read through caller's AS at CPL=0.
    let req: DrmModeDestroyDumb = unsafe { core::ptr::read_volatile(arg as *const DrmModeDestroyDumb) };
    let freed = {
        let mut t = TABLES.lock();
        if t.find_buf(card_id, req.handle).is_none() { return einval(); }
        t.unref_handle(card_id, req.handle)
    };
    if let Some((pa, order)) = freed { free_buf_pages(pa, order); }
    0
}

/// MODE_ADDFB2: validate handles + format, create a metadata-only FB
/// object, bump each referenced handle's refcount, write fb_id back.
/// # C: O(n)
pub fn addfb2(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeFbCmd2>() as u64) { return einval(); }
    // SAFETY: arg range validated < USER_VA_END; drm_mode_fb_cmd2 is 104 bytes; aligned struct read through caller's AS at CPL=0.
    let mut req: DrmModeFbCmd2 = unsafe { core::ptr::read_volatile(arg as *const DrmModeFbCmd2) };
    if req.flags != 0 { return einval(); }
    if req.modifier.iter().any(|m| *m != 0) { return einval(); }
    if !format_supported(req.pixel_format) { return einval(); }
    if req.width == 0 || req.height == 0 { return einval(); }
    if req.handles[0] == 0 { return einval(); }
    if req.handles[1..].iter().any(|h| *h != 0) { return einval(); }
    if req.pitches[1..].iter().any(|p| *p != 0) { return einval(); }
    if req.offsets[1..].iter().any(|o| *o != 0) { return einval(); }
    {
        let t = TABLES.lock();
        let Some(buf) = t.find_buf(card_id, req.handles[0]) else { return einval(); };
        if !fb_plane_fits_buf(
            req.width,
            req.height,
            req.pixel_format,
            req.pitches[0],
            req.offsets[0],
            buf,
        ) {
            return einval();
        }
    }
    let fb_id = alloc_fb_id();
    {
        let mut t = TABLES.lock();
        t.ref_handle(card_id, req.handles[0]);
        t.fbs.push(FbObj {
            card_id, fb_id, w: req.width, h: req.height, pixel_format: req.pixel_format,
            handles: req.handles, pitches: req.pitches, offsets: req.offsets,
            scanout_res_id: 0,
        });
    }
    req.fb_id = fb_id;
    // SAFETY: arg validated above; struct is 104 bytes; aligned write of fb_id out field through caller's AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeFbCmd2, req); }
    0
}

/// MODE_ADDFB (legacy): single-handle FB, derive format from bpp/depth.
/// # C: O(n)
pub fn addfb(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeFbCmd>() as u64) { return einval(); }
    // SAFETY: arg range validated < USER_VA_END; drm_mode_fb_cmd is 28 bytes; aligned struct read through caller's AS at CPL=0.
    let mut req: DrmModeFbCmd = unsafe { core::ptr::read_volatile(arg as *const DrmModeFbCmd) };
    if req.width == 0 || req.height == 0 || req.handle == 0 { return einval(); }
    // Legacy ADDFB v1 supports 32bpp/24depth XRGB8888 and 32/32 ARGB8888.
    let fourcc = match (req.bpp, req.depth) {
        (32, 24) => DRM_FORMAT_XRGB8888,
        (32, 32) => DRM_FORMAT_ARGB8888,
        _        => return einval(),
    };
    {
        let t = TABLES.lock();
        let Some(buf) = t.find_buf(card_id, req.handle) else { return einval(); };
        if !fb_plane_fits_buf(req.width, req.height, fourcc, req.pitch, 0, buf) {
            return einval();
        }
    }
    let fb_id = alloc_fb_id();
    {
        let mut t = TABLES.lock();
        t.ref_handle(card_id, req.handle);
        t.fbs.push(FbObj {
            card_id, fb_id, w: req.width, h: req.height, pixel_format: fourcc,
            handles: [req.handle, 0, 0, 0], pitches: [req.pitch, 0, 0, 0], offsets: [0; 4],
            scanout_res_id: 0,
        });
    }
    req.fb_id = fb_id;
    // SAFETY: arg validated above; struct is 28 bytes; aligned write of fb_id out field through caller's AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeFbCmd, req); }
    0
}

/// MODE_RMFB: drop the FB object, unref its handles (free pages of any
/// that hit refcount 0). `arg` points at a `u32` fb_id. # C: O(n)
pub fn rmfb(card_id: u32, arg: u64) -> i64 {
    if !user_ok(arg, 4) { return einval(); }
    // SAFETY: arg range validated < USER_VA_END; aligned u32 read of the fb_id through caller's AS at CPL=0.
    let fb_id: u32 = unsafe { core::ptr::read_volatile(arg as *const u32) };
    let (to_free, scanout_res_id) = {
        let mut t = TABLES.lock();
        let idx = match t.fbs.iter().position(|f| f.card_id == card_id && f.fb_id == fb_id) { Some(i) => i, None => return einval() };
        let fb = t.fbs.remove(idx);
        let scanout_res_id = fb.scanout_res_id;
        let mut freed: [Option<(u64, u8)>; 4] = [None; 4];
        for (i, &h) in fb.handles.iter().enumerate() {
            if h != 0 { freed[i] = t.unref_handle(card_id, h); }
        }
        (freed, scanout_res_id)
    };
    crate::crtc::detach_fb(card_id, fb_id);
    release_scanout_resource(card_id, scanout_res_id);
    for f in to_free.iter().flatten() { free_buf_pages(f.0, f.1); }
    0
}

/// Free the `2^order` frames of a dumb buffer back to the PMM. The buddy
/// allocator owns the run as one block, freed at its allocation order.
/// # C: O(1)
fn free_buf_pages(pa: u64, order: u8) {
    // SAFETY: each page in this run was allocated through
    // alloc_contig_object(Order(order)) with one object ref. Dropping that ref
    // is safe even while VMA PTE refs still exist; the PMM returns a page only
    // after the last VMA mapping also drops.
    unsafe {
        let frames = 1u64 << order;
        for i in 0..frames {
            pmm::setup::dec_object_ref_and_maybe_free_frame(pa + i * 4096);
        }
    }
}

/// Pin a DRM dumb buffer for a userspace mmap VMA. The returned pin carries
/// the stable physical range; `unpin_mmap` must be called when the VMA drops.
/// # C: O(n)
pub fn pin_mmap(card_id: u32, cookie: u64) -> Option<DumbMmapPin> {
    let h = handle_of_cookie(cookie)?;
    TABLES.lock().pin_mmap(card_id, h)
}

/// Drop a previously acquired mmap pin.
/// # C: O(n)
pub fn unpin_mmap(pin: DumbMmapPin) {
    let freed = TABLES.lock().unpin_mmap(pin.card_id, pin.handle);
    if let Some((pa, order)) = freed { free_buf_pages(pa, order); }
}

/// mmap backing for a DRM card inode: cookie (the MAP_DUMB offset)
/// selects the dumb buffer; returns its (pa, size). Offset-keyed
/// counterpart of `fbdev::devfs::mmap_backing`. `None` if not a DRM
/// cookie or unknown handle. # C: O(n)
pub fn mmap_backing(card_id: u32, cookie: u64) -> Option<(u64, u64)> {
    let h = handle_of_cookie(cookie)?;
    let t = TABLES.lock();
    let b = t.find_buf(card_id, h)?;
    Some((b.pa, b.size))
}

/// Drop all dumb-buffer/FB state for a DRM card during backend unregister.
/// # C: O(n)
pub fn clear_card_state(card_id: u32) {
    let (freed, resources) = TABLES.lock().remove_card(card_id);
    for res_id in resources {
        release_scanout_resource(card_id, res_id);
    }
    for (pa, order) in freed { free_buf_pages(pa, order); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_dumb_layout() { assert_eq!(core::mem::size_of::<DrmModeCreateDumb>(), 32); }
    #[test]
    fn map_dumb_layout() {
        assert_eq!(core::mem::size_of::<DrmModeMapDumb>(), 16);
        assert_eq!(core::mem::offset_of!(DrmModeMapDumb, offset), 8);
    }
    #[test]
    fn fb_cmd2_layout() {
        // 5×u32 (20) + 4×u32 handles (16) + 4×u32 pitches (16)
        // + 4×u32 offsets (16) + 4×u64 modifier (32) = 100; aligned to
        // 8 → modifier needs 8-align, struct = 104.
        let sz = core::mem::size_of::<DrmModeFbCmd2>();
        assert_eq!(sz, 104);
        assert_eq!(core::mem::offset_of!(DrmModeFbCmd2, handles), 20);
        assert_eq!(core::mem::offset_of!(DrmModeFbCmd2, modifier), 72);
    }
    #[test]
    fn fb_cmd_layout() { assert_eq!(core::mem::size_of::<DrmModeFbCmd>(), 28); }

    #[test]
    fn pitch_align_64() {
        // 640 * 4 = 2560, already 64-aligned.
        assert_eq!(dumb_pitch(640, 32), Some(2560));
        // 100 * 4 = 400 → align_up(400,64) = 448.
        assert_eq!(dumb_pitch(100, 32), Some(448));
        // 16 bpp: 640*2 = 1280, 64-aligned.
        assert_eq!(dumb_pitch(640, 16), Some(1280));
        // bad bpp
        assert_eq!(dumb_pitch(640, 0), None);
        assert_eq!(dumb_pitch(640, 12), None);
        assert_eq!(dumb_pitch(640, 33), None);
    }

    #[test]
    fn size_align_4096() {
        // pitch 2560 * height 480 = 1228800, 4096-aligned (= 300 pages).
        assert_eq!(dumb_size(2560, 480), Some(1228800));
        // 448 * 100 = 44800 → align_up(44800,4096) = 45056.
        assert_eq!(dumb_size(448, 100), Some(45056));
    }

    #[test]
    fn order_math() {
        assert_eq!(order_for_bytes(0), 0);
        assert_eq!(order_for_bytes(4096), 0);
        assert_eq!(order_for_bytes(4097), 1);
        assert_eq!(order_for_bytes(8192), 1);
        assert_eq!(order_for_bytes(8193), 2);
        // 640x480x4 = 1228800 = 300 pages → ceil_log2(300) = 9 (512).
        assert_eq!(order_for_bytes(1228800), 9);
    }

    #[test]
    fn format_gate() {
        assert!(format_supported(DRM_FORMAT_XRGB8888));
        assert!(format_supported(DRM_FORMAT_ARGB8888));
        assert!(!format_supported(0xdead_beef));
        assert_eq!(format_cpp(DRM_FORMAT_XRGB8888), Some(4));
        assert_eq!(format_cpp(DRM_FORMAT_ARGB8888), Some(4));
        assert_eq!(format_cpp(0xdead_beef), None);
    }

    #[test]
    fn fb_plane_bounds_validation() {
        let buf = DumbBuf { card_id: 0, handle: 1, pa: 0x10_0000, size: 4096, order: 0,
            w: 16, h: 16, pitch: 64, bpp: 32, refcnt: 1, mmap_refs: 0, deleted: false };

        assert!(fb_plane_fits_buf(16, 16, DRM_FORMAT_XRGB8888, 64, 0, &buf));
        assert!(fb_plane_fits_buf(8, 8, DRM_FORMAT_XRGB8888, 64, 128, &buf));
        assert!(!fb_plane_fits_buf(16, 16, DRM_FORMAT_XRGB8888, 63, 0, &buf));
        assert!(!fb_plane_fits_buf(16, 16, DRM_FORMAT_XRGB8888, 64, 4090, &buf));
        assert!(!fb_plane_fits_buf(u32::MAX, 2, DRM_FORMAT_XRGB8888, u32::MAX, 0, &buf));
    }

    #[test]
    fn cookie_round_trip() {
        let c = cookie_for(1);
        assert_eq!(c, DRM_MMAP_COOKIE_BASE | (1 << DRM_MMAP_COOKIE_HANDLE_SHIFT));
        assert_eq!(handle_of_cookie(c), Some(1));
        let c7 = cookie_for(7);
        assert_eq!(handle_of_cookie(c7), Some(7));
        let high = 1 << 20;
        assert_eq!(handle_of_cookie(cookie_for(high)), Some(high));
        assert_eq!(handle_of_cookie(cookie_for(u32::MAX)), Some(u32::MAX));
        // fbdev's offset 0 is not a DRM cookie.
        assert_eq!(handle_of_cookie(0), None);
        // Handle 0 is not allocated by DRM, and malformed low/high bits are
        // rejected instead of being truncated into a valid handle.
        assert_eq!(handle_of_cookie(DRM_MMAP_COOKIE_BASE), None);
        assert_eq!(handle_of_cookie(cookie_for(1) | 1), None);
        assert_eq!(handle_of_cookie(cookie_for(1) | (1u64 << 47)), None);
    }

    #[test]
    fn table_insert_lookup_ref_unref() {
        let mut t = DumbTables::new();
        t.insert_buf(DumbBuf { card_id: 0, handle: 1, pa: 0x10_0000, size: 4096, order: 0,
            w: 4, h: 4, pitch: 16, bpp: 32, refcnt: 1, mmap_refs: 0, deleted: false });
        assert!(t.find_buf(0, 1).is_some());
        assert!(t.find_buf(1, 1).is_none());
        assert!(t.find_buf(0, 2).is_none());
        // FB takes a ref → refcnt 2.
        assert!(t.ref_handle(0, 1));
        assert_eq!(t.find_buf(0, 1).unwrap().refcnt, 2);
        assert!(!t.ref_handle(0, 99));
        // DESTROY_DUMB drops the open ref → still alive (FB holds it).
        assert_eq!(t.unref_handle(0, 1), None);
        assert_eq!(t.find_buf(0, 1).unwrap().refcnt, 1);
        // RMFB drops the FB ref → now frees, returns (pa,order).
        assert_eq!(t.unref_handle(0, 1), Some((0x10_0000, 0)));
        assert!(t.find_buf(0, 1).is_none());
        // unknown handle → None.
        assert_eq!(t.unref_handle(0, 1), None);
    }

    #[test]
    fn fb_table_insert_lookup() {
        let mut t = DumbTables::new();
        t.fbs.push(FbObj { card_id: 0, fb_id: 1, w: 640, h: 480, pixel_format: DRM_FORMAT_XRGB8888,
            handles: [3, 0, 0, 0], pitches: [2560, 0, 0, 0], offsets: [0; 4], scanout_res_id: 0 });
        assert_eq!(t.find_fb(0, 1).unwrap().handles[0], 3);
        assert!(t.find_fb(1, 1).is_none());
        assert!(t.find_fb(0, 2).is_none());
    }

    #[test]
    fn addfb2_rejects_modifier_surface_without_modifier_support() {
        use syscall::errno::Errno;

        let mut req = DrmModeFbCmd2 {
            width: 4,
            height: 4,
            pixel_format: DRM_FORMAT_XRGB8888,
            flags: DRM_MODE_FB_MODIFIERS,
            handles: [1, 0, 0, 0],
            pitches: [16, 0, 0, 0],
            offsets: [0; 4],
            modifier: [1, 0, 0, 0],
            ..Default::default()
        };
        assert_eq!(
            addfb2(0, (&mut req as *mut DrmModeFbCmd2) as u64),
            -(Errno::Einval.as_i32() as i64)
        );
    }

    fn reset_global_tables() {
        let mut t = TABLES.lock();
        t.bufs.clear();
        t.fbs.clear();
    }

    fn insert_global_buf(size: u64) {
        TABLES.lock().insert_buf(DumbBuf {
            card_id: 0,
            handle: 1,
            pa: 0x10_0000,
            size,
            order: 0,
            w: 16,
            h: 16,
            pitch: 64,
            bpp: 32,
            refcnt: 1,
            mmap_refs: 0,
            deleted: false,
        });
    }

    #[test]
    fn addfb2_validates_single_plane_bounds() {
        use syscall::errno::Errno;

        reset_global_tables();
        insert_global_buf(4096);
        let mut req = DrmModeFbCmd2 {
            width: 16,
            height: 16,
            pixel_format: DRM_FORMAT_XRGB8888,
            handles: [1, 0, 0, 0],
            pitches: [64, 0, 0, 0],
            offsets: [0; 4],
            ..Default::default()
        };
        assert_eq!(addfb2(0, (&mut req as *mut DrmModeFbCmd2) as u64), 0);
        assert!(req.fb_id != 0);
        {
            let t = TABLES.lock();
            assert_eq!(t.find_buf(0, 1).unwrap().refcnt, 2);
            assert_eq!(t.fbs.len(), 1);
        }

        reset_global_tables();
        insert_global_buf(4096);
        let mut req = DrmModeFbCmd2 {
            width: 16,
            height: 16,
            pixel_format: DRM_FORMAT_XRGB8888,
            handles: [1, 0, 0, 0],
            pitches: [63, 0, 0, 0],
            offsets: [0; 4],
            ..Default::default()
        };
        assert_eq!(
            addfb2(0, (&mut req as *mut DrmModeFbCmd2) as u64),
            -(Errno::Einval.as_i32() as i64)
        );
        assert!(TABLES.lock().fbs.is_empty());

        reset_global_tables();
        insert_global_buf(4096);
        let mut req = DrmModeFbCmd2 {
            width: 16,
            height: 1,
            pixel_format: DRM_FORMAT_XRGB8888,
            handles: [1, 0, 0, 0],
            pitches: [64, 0, 0, 0],
            offsets: [4090, 0, 0, 0],
            ..Default::default()
        };
        assert_eq!(
            addfb2(0, (&mut req as *mut DrmModeFbCmd2) as u64),
            -(Errno::Einval.as_i32() as i64)
        );
        assert!(TABLES.lock().fbs.is_empty());

        reset_global_tables();
    }

    #[test]
    fn addfb2_rejects_unused_plane_metadata_for_packed_rgb() {
        use syscall::errno::Errno;

        reset_global_tables();
        insert_global_buf(4096);
        let mut req = DrmModeFbCmd2 {
            width: 16,
            height: 16,
            pixel_format: DRM_FORMAT_XRGB8888,
            handles: [1, 1, 0, 0],
            pitches: [64, 0, 0, 0],
            offsets: [0; 4],
            ..Default::default()
        };
        assert_eq!(
            addfb2(0, (&mut req as *mut DrmModeFbCmd2) as u64),
            -(Errno::Einval.as_i32() as i64)
        );

        reset_global_tables();
        insert_global_buf(4096);
        let mut req = DrmModeFbCmd2 {
            width: 16,
            height: 16,
            pixel_format: DRM_FORMAT_XRGB8888,
            handles: [1, 0, 0, 0],
            pitches: [64, 1, 0, 0],
            offsets: [0; 4],
            ..Default::default()
        };
        assert_eq!(
            addfb2(0, (&mut req as *mut DrmModeFbCmd2) as u64),
            -(Errno::Einval.as_i32() as i64)
        );

        reset_global_tables();
    }

    #[test]
    fn legacy_addfb_validates_pitch_and_bounds() {
        use syscall::errno::Errno;

        reset_global_tables();
        insert_global_buf(4096);
        let mut req = DrmModeFbCmd {
            width: 16,
            height: 16,
            pitch: 64,
            bpp: 32,
            depth: 24,
            handle: 1,
            ..Default::default()
        };
        assert_eq!(addfb(0, (&mut req as *mut DrmModeFbCmd) as u64), 0);
        assert!(req.fb_id != 0);

        reset_global_tables();
        insert_global_buf(4096);
        let mut req = DrmModeFbCmd {
            width: 16,
            height: 16,
            pitch: 63,
            bpp: 32,
            depth: 24,
            handle: 1,
            ..Default::default()
        };
        assert_eq!(
            addfb(0, (&mut req as *mut DrmModeFbCmd) as u64),
            -(Errno::Einval.as_i32() as i64)
        );
        assert!(TABLES.lock().fbs.is_empty());

        reset_global_tables();
    }

    #[test]
    fn card_state_isolated() {
        let mut t = DumbTables::new();
        t.insert_buf(DumbBuf { card_id: 0, handle: 1, pa: 0x10_0000, size: 4096, order: 0,
            w: 4, h: 4, pitch: 16, bpp: 32, refcnt: 1, mmap_refs: 0, deleted: false });
        t.insert_buf(DumbBuf { card_id: 1, handle: 1, pa: 0x20_0000, size: 4096, order: 0,
            w: 4, h: 4, pitch: 16, bpp: 32, refcnt: 1, mmap_refs: 0, deleted: false });
        t.fbs.push(FbObj { card_id: 0, fb_id: 7, w: 4, h: 4, pixel_format: DRM_FORMAT_XRGB8888,
            handles: [1, 0, 0, 0], pitches: [16, 0, 0, 0], offsets: [0; 4], scanout_res_id: 0 });
        assert_eq!(t.find_buf(0, 1).unwrap().pa, 0x10_0000);
        assert_eq!(t.find_buf(1, 1).unwrap().pa, 0x20_0000);
        assert!(t.find_fb(1, 7).is_none());
        assert_eq!(t.remove_card(0), (alloc::vec![(0x10_0000, 0)], Vec::new()));
        assert!(t.find_buf(0, 1).is_none());
        assert!(t.find_buf(1, 1).is_some());
        assert!(t.find_fb(0, 7).is_none());
    }

    #[test]
    fn card_remove_returns_scanout_resources() {
        let mut t = DumbTables::new();
        t.insert_buf(DumbBuf { card_id: 0, handle: 1, pa: 0x10_0000, size: 4096, order: 0,
            w: 4, h: 4, pitch: 16, bpp: 32, refcnt: 2, mmap_refs: 0, deleted: false });
        t.fbs.push(FbObj { card_id: 0, fb_id: 7, w: 4, h: 4, pixel_format: DRM_FORMAT_XRGB8888,
            handles: [1, 0, 0, 0], pitches: [16, 0, 0, 0], offsets: [0; 4], scanout_res_id: 42 });

        assert_eq!(t.remove_card(0), (alloc::vec![(0x10_0000, 0)], alloc::vec![42]));
        assert!(t.find_fb(0, 7).is_none());
        assert!(t.find_buf(0, 1).is_none());
    }

    #[test]
    fn mmap_pin_survives_card_remove_until_unpin() {
        let mut t = DumbTables::new();
        t.insert_buf(DumbBuf { card_id: 0, handle: 1, pa: 0x10_0000, size: 4096, order: 0,
            w: 4, h: 4, pitch: 16, bpp: 32, refcnt: 1, mmap_refs: 0, deleted: false });
        let pin = t.pin_mmap(0, 1).unwrap();
        assert_eq!(pin.pa, 0x10_0000);
        assert_eq!(t.find_buf(0, 1).unwrap().refcnt, 2);
        assert_eq!(t.find_buf(0, 1).unwrap().mmap_refs, 1);

        assert_eq!(t.remove_card(0), (Vec::<(u64, u8)>::new(), Vec::new()));
        assert!(t.find_buf(0, 1).is_none());
        assert_eq!(t.bufs.len(), 1);
        assert!(t.bufs[0].deleted);
        assert_eq!(t.bufs[0].refcnt, 1);
        assert_eq!(t.bufs[0].mmap_refs, 1);

        assert_eq!(t.unpin_mmap(0, 1), Some((0x10_0000, 0)));
        assert!(t.bufs.is_empty());
    }
}
