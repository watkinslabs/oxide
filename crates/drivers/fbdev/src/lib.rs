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

// ============================================================
// FBIO* ioctl numbers (per linux/include/uapi/linux/fb.h)
// ============================================================
pub const FBIOGET_VSCREENINFO:  u64 = 0x4600;
pub const FBIOPUT_VSCREENINFO:  u64 = 0x4601;
pub const FBIOGET_FSCREENINFO:  u64 = 0x4602;
pub const FBIOGETCMAP:          u64 = 0x4604;
pub const FBIOPUTCMAP:          u64 = 0x4605;
pub const FBIOPAN_DISPLAY:      u64 = 0x4606;
pub const FBIOBLANK:            u64 = 0x4611;
pub const FBIOGET_VBLANK:       u64 = 0x80204612;
pub const FBIO_WAITFORVSYNC:    u64 = 0x40044620;

// fb_fix_screeninfo.type
pub const FB_TYPE_PACKED_PIXELS:        u32 = 0;
pub const FB_TYPE_PLANES:               u32 = 1;
pub const FB_TYPE_INTERLEAVED_PLANES:   u32 = 2;
pub const FB_TYPE_TEXT:                 u32 = 3;
pub const FB_TYPE_VGA_PLANES:           u32 = 4;
pub const FB_TYPE_FOURCC:               u32 = 5;

// fb_fix_screeninfo.visual
pub const FB_VISUAL_MONO01:             u32 = 0;
pub const FB_VISUAL_MONO10:             u32 = 1;
pub const FB_VISUAL_TRUECOLOR:          u32 = 2;
pub const FB_VISUAL_PSEUDOCOLOR:        u32 = 3;
pub const FB_VISUAL_DIRECTCOLOR:        u32 = 4;
pub const FB_VISUAL_STATIC_PSEUDOCOLOR: u32 = 5;

pub const FB_ACCEL_NONE:                u32 = 0;

// FBIOBLANK levels (DPMS-equivalent)
pub const FB_BLANK_UNBLANK:             u32 = 0;
pub const FB_BLANK_NORMAL:              u32 = 1;
pub const FB_BLANK_VSYNC_SUSPEND:       u32 = 2;
pub const FB_BLANK_HSYNC_SUSPEND:       u32 = 3;
pub const FB_BLANK_POWERDOWN:           u32 = 4;

// fb_var_screeninfo.activate
pub const FB_ACTIVATE_NOW:              u32 = 0;
pub const FB_ACTIVATE_NXTOPEN:          u32 = 1;
pub const FB_ACTIVATE_TEST:             u32 = 2;
pub const FB_ACTIVATE_MASK:             u32 = 0x0f;
pub const FB_ACTIVATE_VBL:              u32 = 0x10;
pub const FB_CHANGE_CMAP_VBL:           u32 = 0x20;
pub const FB_ACTIVATE_ALL:              u32 = 0x40;
pub const FB_ACTIVATE_FORCE:            u32 = 0x80;
pub const FB_ACTIVATE_INV_MODE:         u32 = 0x100;

// fb_vblank.flags (per linux/include/uapi/linux/fb.h)
pub const FB_VBLANK_VBLANKING:  u32 = 0x001;
pub const FB_VBLANK_HBLANKING:  u32 = 0x002;
pub const FB_VBLANK_HAVE_VBLANK:u32 = 0x004;
pub const FB_VBLANK_HAVE_HBLANK:u32 = 0x008;
pub const FB_VBLANK_HAVE_COUNT: u32 = 0x010;
pub const FB_VBLANK_HAVE_VCOUNT:u32 = 0x020;
pub const FB_VBLANK_HAVE_HCOUNT:u32 = 0x040;
pub const FB_VBLANK_VSYNCING:   u32 = 0x080;
pub const FB_VBLANK_HAVE_VSYNC: u32 = 0x100;

// ============================================================
// Wire structs (verbatim from linux/include/uapi/linux/fb.h)
// ============================================================

/// `struct fb_vblank` — FBIOGET_VBLANK result (32 B). count/vcount/hcount
/// are the running vblank/scanline counters; `flags` declares which fields
/// are valid.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct FbVblank {
    pub flags:    u32,
    pub count:    u32,
    pub vcount:   u32,
    pub hcount:   u32,
    pub reserved: [u32; 4],
}

/// `struct fb_cmap` (per linux/include/uapi/linux/fb.h) — palette transfer
/// descriptor. `red`/`green`/`blue`/`transp` are USER pointers to arrays of
/// `len` u16 entries each (`transp` may be NULL). On a truecolor visual the
/// driver maps these into a 16-entry pseudo-palette.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FbCmap {
    pub start:  u32,
    pub len:    u32,
    pub red:    u64, // __u16 *
    pub green:  u64, // __u16 *
    pub blue:   u64, // __u16 *
    pub transp: u64, // __u16 *
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct FbBitfield { pub offset: u32, pub length: u32, pub msb_right: u32 }

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FbVarScreeninfo {
    pub xres:           u32, pub yres: u32,
    pub xres_virtual:   u32, pub yres_virtual: u32,
    pub xoffset:        u32, pub yoffset: u32,
    pub bits_per_pixel: u32,
    pub grayscale:      u32,
    pub red:            FbBitfield,
    pub green:          FbBitfield,
    pub blue:           FbBitfield,
    pub transp:         FbBitfield,
    pub nonstd:         u32,
    pub activate:       u32,
    pub height:         u32, pub width: u32,
    pub accel_flags:    u32,
    pub pixclock:       u32,
    pub left_margin:    u32, pub right_margin: u32,
    pub upper_margin:   u32, pub lower_margin: u32,
    pub hsync_len:      u32, pub vsync_len: u32,
    pub sync:           u32, pub vmode: u32, pub rotate: u32,
    pub colorspace:     u32,
    pub reserved:       [u32; 4],
}

impl Default for FbVarScreeninfo {
    fn default() -> Self {
        Self {
            xres: 0, yres: 0, xres_virtual: 0, yres_virtual: 0,
            xoffset: 0, yoffset: 0, bits_per_pixel: 32, grayscale: 0,
            red:    FbBitfield { offset: 16, length: 8, msb_right: 0 },
            green:  FbBitfield { offset:  8, length: 8, msb_right: 0 },
            blue:   FbBitfield { offset:  0, length: 8, msb_right: 0 },
            transp: FbBitfield { offset: 24, length: 8, msb_right: 0 },
            nonstd: 0, activate: 0, height: 0, width: 0,
            accel_flags: 0, pixclock: 0,
            left_margin: 0, right_margin: 0, upper_margin: 0, lower_margin: 0,
            hsync_len: 0, vsync_len: 0, sync: 0, vmode: 0, rotate: 0,
            colorspace: 0, reserved: [0; 4],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FbFixScreeninfo {
    pub id:           [u8; 16],
    pub smem_start:   u64,
    pub smem_len:     u32,
    pub ty:           u32,
    pub type_aux:     u32,
    pub visual:       u32,
    pub xpanstep:     u16, pub ypanstep: u16, pub ywrapstep: u16,
    pub line_length:  u32,
    pub mmio_start:   u64,
    pub mmio_len:     u32,
    pub accel:        u32,
    pub capabilities: u16,
    pub reserved:     [u16; 2],
}

impl Default for FbFixScreeninfo {
    fn default() -> Self {
        Self {
            id: *b"oxide-fbdev    \0",
            smem_start: 0, smem_len: 0, ty: FB_TYPE_PACKED_PIXELS,
            type_aux: 0, visual: FB_VISUAL_TRUECOLOR,
            xpanstep: 0, ypanstep: 1, ywrapstep: 0,
            line_length: 0, mmio_start: 0, mmio_len: 0,
            accel: FB_ACCEL_NONE, capabilities: 0, reserved: [0; 2],
        }
    }
}

// ============================================================
// Per-fb device + registry
// ============================================================

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, Again, Busy, IoErr, Perm }

pub type KResult<T> = core::result::Result<T, Error>;

pub struct FbDev {
    pub idx:          u32,
    pub var:          FbVarScreeninfo,
    pub fix:          FbFixScreeninfo,
    /// Contiguous physical base of the scanout backing (smem_start) —
    /// what `/dev/fbN` mmaps into userspace. 0 ⇒ no real backing yet.
    pub base_pa:      u64,
    /// HHDM kernel VA of the same backing — for the read()/write() path.
    pub fb_va:        u64,
    pub fb_bytes:     u64,
    /// Backing DRM `MODE_CREATE_DUMB` handle on `card_id`. 0 ⇒ none yet.
    pub card_id:      u32,
    pub crtc_id:      u32,
    pub fb_id:        u32,
    pub dumb_handle:  u32,
    /// Current FB_BLANK_* level (0 = unblanked). Stored so FBIOBLANK is a
    /// real, observable state change (the image is cleared/restored), not a
    /// silent no-op.
    pub blank:        u32,
    /// 16-entry truecolor pseudo-palette (packed pixels in the visual's
    /// format). Linux fbcon writes these via FBIOPUTCMAP to recolour the 16
    /// console colours on a truecolor fb.
    pub pseudo_palette: [u32; 16],
    /// Driver-owned display operations for this fbdev instance. The key is
    /// opaque to fbdev and is passed back to the owning driver.
    pub ops:          Option<FbOps>,
}

static FBS: Spinlock<Vec<FbDev>, DriverLockClass> = Spinlock::new(Vec::new());

#[derive(Copy, Clone)]
pub struct FbOps {
    pub driver_key: u32,
    pub flush:      fn(u32),
    pub blank:      fn(u32),
    pub unblank:    fn(u32),
}

const INVALID_FB_INDEX: u32 = u32::MAX;

fn lowest_free_fb_idx(fbs: &[FbDev]) -> u32 {
    let mut idx = 0u32;
    loop {
        if fbs.iter().all(|f| f.idx != idx) {
            return idx;
        }
        idx = idx.saturating_add(1);
    }
}

/// Publish the model-owned `/dev/fbN` node for a newly inserted framebuffer.
/// On failure, remove the framebuffer record so fb-visible state cannot
/// outlive its owned devtmpfs publication.
/// # C: O(N + depth)
fn publish_or_unwind(idx: u32) -> Option<u32> {
    #[cfg(target_os = "oxide-kernel")]
    if !devfs::register_node(idx) {
        let mut g = FBS.lock();
        if let Some(pos) = g.iter().position(|f| f.idx == idx) {
            g.remove(pos);
        }
        return None;
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = idx;
    Some(idx)
}

/// Register display operations for one fbdev instance.
/// # C: O(N)
pub fn set_ops(idx: u32, ops: FbOps) -> bool {
    let mut g = FBS.lock();
    let Some(fb) = g.iter_mut().find(|f| f.idx == idx) else {
        return false;
    };
    fb.ops = Some(ops);
    true
}

/// Clear display operations for one fbdev instance.
/// # C: O(N)
pub fn clear_ops(idx: u32) -> bool {
    let mut g = FBS.lock();
    let Some(fb) = g.iter_mut().find(|f| f.idx == idx) else {
        return false;
    };
    fb.ops = None;
    true
}

fn ops_of(idx: u32) -> Option<FbOps> {
    FBS.lock().iter().find(|f| f.idx == idx).and_then(|f| f.ops)
}

/// Push written pixels for `/dev/fb<idx>` to the display via that fb's
/// registered owner hook. # C: O(N) + host transfer.
pub fn flush(idx: u32) {
    if let Some(ops) = ops_of(idx) {
        (ops.flush)(ops.driver_key);
    }
}

// ============================================================
// Pseudo-vblank source + WAITFORVSYNC wait plumbing
//
// The virtio-gpu has no scanout vblank IRQ, so the honest virtual-GPU
// vsync cadence is the kernel timer tick: `vblank_tick()` (called from
// the timer-ISR tick path) advances VBLANK_SEQ at the tick rate. That is
// a REAL, monotonically advancing counter — FBIO_WAITFORVSYNC blocks on
// it rather than returning a fake immediate success, and FBIOGET_VBLANK
// reports it as the running frame count.
// ============================================================

/// Pseudo-vblank sequence counter. Bumped once per timer tick by
/// `vblank_tick()`; the virtual-GPU's vsync cadence.
static VBLANK_SEQ: AtomicU64 = AtomicU64::new(0);

/// Yield hook (cooperative reschedule) used by FBIO_WAITFORVSYNC's wait
/// loop so the waiter doesn't hot-spin the CPU. `None` ⇒ busy `spin_loop`.
static YIELD_HOOK: Spinlock<Option<fn()>, DriverLockClass> = Spinlock::new(None);

/// Monotonic-now hook (ns) for the WAITFORVSYNC bounded deadline. `None` ⇒
/// fall back to a fixed spin-count bound.
static NOW_HOOK: Spinlock<Option<fn() -> u64>, DriverLockClass> = Spinlock::new(None);

/// Advance the pseudo-vblank counter. Called once per timer tick from the
/// kernel tick path (`tick_poll_combined`); this IS the virtual-GPU vsync.
/// # C: O(1)
pub fn vblank_tick() { VBLANK_SEQ.fetch_add(1, Ordering::Relaxed); }

/// Read the current pseudo-vblank sequence. # C: O(1)
pub fn vblank_seq() -> u64 { VBLANK_SEQ.load(Ordering::Relaxed) }

/// Register the cooperative-yield hook for the WAITFORVSYNC wait loop
/// (boot wiring, once). # C: O(1)
pub fn set_yield_hook(f: fn()) { *YIELD_HOOK.lock() = Some(f); }

/// Register the monotonic-clock hook (ns) used for the WAITFORVSYNC
/// deadline (boot wiring, once). # C: O(1)
pub fn set_now_hook(f: fn() -> u64) { *NOW_HOOK.lock() = Some(f); }

/// Clear wait hooks during framebuffer driver teardown.
/// # C: O(1)
pub fn clear_wait_hooks() {
    *YIELD_HOOK.lock() = None;
    *NOW_HOOK.lock() = None;
}

/// Default WAITFORVSYNC deadline: 100 ms. One tick is the vsync cadence;
/// 100 ms is a generous upper bound that survives a slow tick rate without
/// hanging a misbehaving caller forever.
pub const VSYNC_DEADLINE_NS: u64 = 100_000_000;

/// Block until the pseudo-vblank counter advances past `start_seq`, bounded
/// by `VSYNC_DEADLINE_NS`. Returns the new sequence once it advances (or the
/// current value at the deadline). Yields via the registered hook each spin.
/// This is the real wait FBIO_WAITFORVSYNC performs — it returns only after a
/// tick (vsync) actually happened, or after the bounded deadline. # C: O(ticks)
pub fn wait_vblank(start_seq: u64) -> u64 {
    let now = *NOW_HOOK.lock();
    let yield_f = *YIELD_HOOK.lock();
    let deadline = now.map(|f| f().wrapping_add(VSYNC_DEADLINE_NS));
    let mut spins: u32 = 0;
    loop {
        let cur = VBLANK_SEQ.load(Ordering::Relaxed);
        if cur != start_seq { return cur; }
        match (deadline, now) {
            (Some(d), Some(f)) => if f() >= d { return VBLANK_SEQ.load(Ordering::Relaxed); },
            // No clock hook: bound by a fixed spin budget so we never hang.
            _ => { spins += 1; if spins >= 1_000_000 { return VBLANK_SEQ.load(Ordering::Relaxed); } }
        }
        match yield_f { Some(y) => y(), None => core::hint::spin_loop() }
    }
}

/// Decide a FBIOPAN_DISPLAY result: validate `(xoffset,yoffset)` against the
/// allocated virtual canvas. `Ok(())` if the panned window fits, `Err` (→
/// EINVAL) otherwise. Pure for host test.
/// # C: O(1)
pub fn pan_check(v: &FbVarScreeninfo, xoffset: u32, yoffset: u32) -> KResult<()> {
    let xr = xoffset.checked_add(v.xres).ok_or(Error::Inval)?;
    let yr = yoffset.checked_add(v.yres).ok_or(Error::Inval)?;
    if xr <= v.xres_virtual && yr <= v.yres_virtual { Ok(()) } else { Err(Error::Inval) }
}

/// Pack an (r,g,b) cmap entry (Linux passes 16-bit-per-channel values) into a
/// pixel in the fb's truecolor visual using its `red`/`green`/`blue`
/// bitfields. Mirrors fbcon's `setcolreg` pseudo-palette write. Pure for host
/// test. # C: O(1)
pub fn pack_pseudo(v: &FbVarScreeninfo, r16: u16, g16: u16, b16: u16) -> u32 {
    let chan = |val16: u16, bf: &FbBitfield| -> u32 {
        if bf.length == 0 { return 0; }
        // Linux cmap entries are 16-bit; downshift to the field width.
        let v = (val16 as u32) >> (16 - bf.length);
        (v & ((1u32 << bf.length) - 1)) << bf.offset
    };
    chan(r16, &v.red) | chan(g16, &v.green) | chan(b16, &v.blue)
}

/// Unpack a stored pseudo-palette pixel back into Linux 16-bit-per-channel
/// (r,g,b) for FBIOGETCMAP readback. Inverse of `pack_pseudo`. Pure for host
/// test. # C: O(1)
pub fn unpack_pseudo(v: &FbVarScreeninfo, px: u32) -> (u16, u16, u16) {
    let chan = |bf: &FbBitfield| -> u16 {
        if bf.length == 0 { return 0; }
        let raw = (px >> bf.offset) & ((1u32 << bf.length) - 1);
        // Up-scale the field-width value back to 16 bits by bit-replication
        // (Linux fb cmap convention): fill the 16-bit channel with the field
        // value repeated, so e.g. an 8-bit 0xAB → 0xABAB. Exact inverse of
        // `pack_pseudo` for inputs of the form 0xVVVV (low byte == high byte).
        let mut out = 0u32;
        let mut filled = 0u32;
        while filled < 16 {
            let shift = 16i32 - filled as i32 - bf.length as i32;
            if shift >= 0 { out |= raw << shift; } else { out |= raw >> (-shift); }
            filled += bf.length;
        }
        (out & 0xFFFF) as u16
    };
    (chan(&v.red), chan(&v.green), chan(&v.blue))
}

/// Register `/dev/fbN` backed by the real scanout: `base_pa`/`fb_va` =
/// physical + HHDM-kernel address of the contiguous BGRA32 framebuffer,
/// `pitch` = bytes/line, `w`×`h` = resolution. Builds var/fix (smem_start =
/// base_pa, line_length = pitch, 32bpp BGRA truecolor), registers it, and
/// publishes its devtmpfs node.
/// # C: O(N + depth)
pub fn init_scanout(base_pa: u64, fb_va: u64, fb_bytes: u64, pitch: u32, w: u32, h: u32) -> u32 {
    let mut var = FbVarScreeninfo::default();
    var.xres = w; var.yres = h; var.xres_virtual = w; var.yres_virtual = h;
    let mut fix = FbFixScreeninfo::default();
    fix.smem_start = base_pa;
    fix.smem_len = fb_bytes as u32;
    fix.line_length = pitch;
    let idx = {
        let mut g = FBS.lock();
        let idx = lowest_free_fb_idx(&g);
        g.push(FbDev {
            idx, var, fix, base_pa, fb_va, fb_bytes,
            card_id: 0, crtc_id: 0, fb_id: 0, dumb_handle: 0,
            blank: FB_BLANK_UNBLANK, pseudo_palette: [0; 16], ops: None,
        });
        idx
    };
    publish_or_unwind(idx).unwrap_or(INVALID_FB_INDEX)
}

/// Unregister an fbdev instance and remove its devtmpfs node before the
/// backing storage is released.
/// # C: O(N + depth)
pub fn unregister(idx: u32) -> bool {
    #[cfg(target_os = "oxide-kernel")]
    let _ = devfs::unregister_node(idx);
    let mut g = FBS.lock();
    let Some(pos) = g.iter().position(|f| f.idx == idx) else {
        return false;
    };
    g.remove(pos);
    true
}

/// Unregister the fbdev instance that owns `base_pa`.
/// # C: O(N + depth)
pub fn unregister_by_base(base_pa: u64) -> bool {
    let idx = {
        let g = FBS.lock();
        let Some(fb) = g.iter().find(|f| f.base_pa == base_pa) else {
            return false;
        };
        fb.idx
    };
    unregister(idx)
}

/// `(base_pa, fb_bytes)` of `/dev/fb<idx>` for mmap (Linux remap_pfn_range).
/// `None` if the fb has no real backing. # C: O(N)
pub fn backing_of(idx: u32) -> Option<(u64, u64)> {
    FBS.lock().iter().find(|f| f.idx == idx && f.base_pa != 0).map(|f| (f.base_pa, f.fb_bytes))
}

/// `(fb_va, fb_bytes)` of `/dev/fb<idx>` for the read()/write() path.
/// # C: O(N)
pub fn kva_of(idx: u32) -> Option<(u64, u64)> {
    FBS.lock().iter().find(|f| f.idx == idx && f.fb_va != 0).map(|f| (f.fb_va, f.fb_bytes))
}

/// Register a per-CRTC fbdev backed by a DRM card. Returns the fb
/// index (0 ⇒ /dev/fb0).
/// # C: O(1)
pub fn register(card_id: u32, crtc_id: u32, var: FbVarScreeninfo, fix: FbFixScreeninfo) -> u32 {
    let idx = {
        let mut g = FBS.lock();
        let idx = lowest_free_fb_idx(&g);
        g.push(FbDev {
            idx, var, fix, base_pa: 0, fb_va: 0, fb_bytes: 0,
            card_id, crtc_id, fb_id: 0, dumb_handle: 0,
            blank: FB_BLANK_UNBLANK, pseudo_palette: [0; 16], ops: None,
        });
        idx
    };
    publish_or_unwind(idx).unwrap_or(INVALID_FB_INDEX)
}

/// Number of registered fbdev devices (count of /dev/fbN inodes).
/// # C: O(1)
pub fn count() -> usize { FBS.lock().len() }

/// Snapshot the var screeninfo for `/dev/fb<idx>`.
/// # C: O(N)
pub fn var_of(idx: u32) -> Option<FbVarScreeninfo> {
    FBS.lock().iter().find(|f| f.idx == idx).map(|f| f.var)
}

/// Replace the var screeninfo for `/dev/fb<idx>` (PUT_VSCREENINFO virtual-res
/// / PAN_DISPLAY offset updates). # C: O(N)
pub fn set_var(idx: u32, var: FbVarScreeninfo) {
    if let Some(f) = FBS.lock().iter_mut().find(|f| f.idx == idx) { f.var = var; }
}

/// Snapshot the fix screeninfo for `/dev/fb<idx>`.
/// # C: O(N)
pub fn fix_of(idx: u32) -> Option<FbFixScreeninfo> {
    FBS.lock().iter().find(|f| f.idx == idx).map(|f| f.fix)
}

/// Compute `line_length` for a given (xres, bpp) per Linux fbdev:
/// row stride in bytes, aligned up to 64-byte cache line for typical
/// DRM dumb-buffer pitch.
/// # C: O(1)
pub fn line_length(xres: u32, bpp: u32) -> u32 {
    let raw = xres.saturating_mul(bpp / 8);
    (raw + 63) & !63
}

/// Validate an `FBIOBLANK` level argument.
/// # C: O(1)
pub fn is_blank_level(level: u32) -> bool { level <= FB_BLANK_POWERDOWN }

/// Current FB_BLANK_* level of `/dev/fb<idx>`. # C: O(N)
pub fn blank_of(idx: u32) -> Option<u32> {
    FBS.lock().iter().find(|f| f.idx == idx).map(|f| f.blank)
}

/// Store the FB_BLANK_* level for `/dev/fb<idx>`. # C: O(N)
pub fn set_blank(idx: u32, level: u32) {
    if let Some(f) = FBS.lock().iter_mut().find(|f| f.idx == idx) { f.blank = level; }
}

/// Store `entry` into the pseudo-palette slot `i` (0..16). # C: O(N)
pub fn set_palette(idx: u32, i: usize, entry: u32) {
    if i >= 16 { return; }
    if let Some(f) = FBS.lock().iter_mut().find(|f| f.idx == idx) { f.pseudo_palette[i] = entry; }
}

/// Read pseudo-palette slot `i` (0..16) of `/dev/fb<idx>`. # C: O(N)
pub fn palette_at(idx: u32, i: usize) -> Option<u32> {
    if i >= 16 { return None; }
    FBS.lock().iter().find(|f| f.idx == idx).map(|f| f.pseudo_palette[i])
}

/// Apply a blank-level transition for `/dev/fb<idx>`: store the level, then
/// (level ≥ NORMAL) clear the displayed image to black, or (UNBLANK) repaint
/// the console. Returns the prior level. Honest: no real DPMS power-down — the
/// image is blanked, documented as such. # C: O(1) + flush.
pub fn apply_blank(idx: u32, level: u32) {
    let prev = blank_of(idx).unwrap_or(FB_BLANK_UNBLANK);
    set_blank(idx, level);
    let ops = ops_of(idx);
    if level == FB_BLANK_UNBLANK {
        if prev != FB_BLANK_UNBLANK {
            if let Some(ops) = ops {
                (ops.unblank)(ops.driver_key);
            }
        }
    } else if let Some(ops) = ops {
        (ops.blank)(ops.driver_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

    static LAST_FLUSH: AtomicU32 = AtomicU32::new(u32::MAX);
    static LAST_BLANK: AtomicU32 = AtomicU32::new(u32::MAX);
    static LAST_UNBLANK: AtomicU32 = AtomicU32::new(u32::MAX);

    fn record_flush(key: u32) { LAST_FLUSH.store(key, AtomicOrdering::SeqCst); }
    fn record_blank(key: u32) { LAST_BLANK.store(key, AtomicOrdering::SeqCst); }
    fn record_unblank(key: u32) { LAST_UNBLANK.store(key, AtomicOrdering::SeqCst); }

    #[test]
    fn fb_var_default_bgra32() {
        let v = FbVarScreeninfo::default();
        assert_eq!(v.bits_per_pixel, 32);
        assert_eq!(v.red.offset,   16);
        assert_eq!(v.green.offset,  8);
        assert_eq!(v.blue.offset,   0);
        assert_eq!(v.transp.offset, 24);
    }

    #[test]
    fn fb_fix_default_truecolor() {
        let f = FbFixScreeninfo::default();
        assert_eq!(f.ty, FB_TYPE_PACKED_PIXELS);
        assert_eq!(f.visual, FB_VISUAL_TRUECOLOR);
        assert_eq!(f.accel, FB_ACCEL_NONE);
    }

    #[test]
    fn fb_var_layout() {
        // Linux fb_var_screeninfo is 160 bytes
        // (matches `man 5 framebuffer.h`).
        let sz = core::mem::size_of::<FbVarScreeninfo>();
        assert_eq!(sz, 160);
    }

    #[test]
    fn fb_vblank_layout() {
        assert_eq!(core::mem::size_of::<FbVblank>(), 32);
    }

    #[test]
    fn fb_cmap_layout() {
        // start u32, len u32, then 4 pointers (8 B each on LP64): 8 + 32 = 40.
        assert_eq!(core::mem::size_of::<FbCmap>(), 40);
    }

    #[test]
    fn cmap_pack_unpack_roundtrip_bgra32() {
        // Default truecolor BGRA32 visual: 8-bit channels. Roundtrip holds for
        // entries of the form 0xVVVV (Linux cmap convention: low byte == high).
        let v = FbVarScreeninfo::default();
        for &(r, g, b) in &[(0xFFFFu16, 0x0000u16, 0x0000u16),
                             (0x0000, 0xFFFF, 0x0000),
                             (0xABAB, 0xCDCD, 0xEFEF),
                             (0x1212, 0x3434, 0x5656)] {
            let px = pack_pseudo(&v, r, g, b);
            assert_eq!(unpack_pseudo(&v, px), (r, g, b), "px={px:#010x}");
        }
    }

    #[test]
    fn cmap_pack_places_channels_in_bgra_fields() {
        let v = FbVarScreeninfo::default(); // R@16 G@8 B@0, 8 bits each
        // Pure red 0xFFFF → 0xFF in the red field (bits 16..24).
        assert_eq!(pack_pseudo(&v, 0xFFFF, 0, 0), 0x00FF_0000);
        assert_eq!(pack_pseudo(&v, 0, 0xFFFF, 0), 0x0000_FF00);
        assert_eq!(pack_pseudo(&v, 0, 0, 0xFFFF), 0x0000_00FF);
    }

    #[test]
    fn pan_check_validates_against_virtual() {
        let mut v = FbVarScreeninfo::default();
        v.xres = 800; v.yres = 600;
        // Single-buffer: virtual == visible → only (0,0) fits.
        v.xres_virtual = 800; v.yres_virtual = 600;
        assert!(pan_check(&v, 0, 0).is_ok());
        assert!(pan_check(&v, 0, 1).is_err());
        assert!(pan_check(&v, 1, 0).is_err());
        // Double-height virtual canvas → panning down by yres fits, +1 doesn't.
        v.yres_virtual = 1200;
        assert!(pan_check(&v, 0, 600).is_ok());
        assert!(pan_check(&v, 0, 601).is_err());
        assert!(pan_check(&v, 0, 0).is_ok());
    }

    #[test]
    fn vblank_wait_returns_when_seq_advances() {
        // No clock/yield hook registered → falls back to the spin-budget bound.
        // Pre-advance the counter so the wait sees seq != start immediately.
        let start = VBLANK_SEQ.load(Ordering::Relaxed);
        vblank_tick();
        let got = wait_vblank(start);
        assert_ne!(got, start);
        assert!(got >= start + 1);
    }

    #[test]
    fn vblank_wait_bounded_when_no_advance() {
        // Counter does NOT advance from THIS thread and no clock hook → the
        // wait must TERMINATE (at the spin budget) rather than hang forever —
        // the honest bounded deadline. (VBLANK_SEQ is a shared static across
        // tests, so we only assert termination + monotonicity, not equality.)
        let start = VBLANK_SEQ.load(Ordering::Relaxed);
        let got = wait_vblank(start);
        assert!(got >= start);
    }

    #[test]
    fn line_length_alignment() {
        // 800px × 32bpp = 3200 → already aligned to 64
        assert_eq!(line_length(800, 32), 3200);
        // 1366px × 32bpp = 5464 → round up to 5504
        assert_eq!(line_length(1366, 32), 5504);
        // 1024 × 16 = 2048 → aligned
        assert_eq!(line_length(1024, 16), 2048);
    }

    #[test]
    fn blank_level_validation() {
        assert!(is_blank_level(FB_BLANK_UNBLANK));
        assert!(is_blank_level(FB_BLANK_POWERDOWN));
        assert!(!is_blank_level(99));
    }

    #[test]
    fn init_scanout_populates_geometry_and_backing() {
        FBS.lock().clear();
        let bytes = 800u64 * 600 * 4;
        let idx = init_scanout(0xdead_0000, 0xffff_8000_dead_0000, bytes, 800 * 4, 800, 600);
        assert_eq!(idx, 0);
        let v = var_of(0).unwrap();
        assert_eq!((v.xres, v.yres, v.bits_per_pixel), (800, 600, 32));
        let f = fix_of(0).unwrap();
        assert_eq!(f.smem_start, 0xdead_0000);
        assert_eq!(f.smem_len, bytes as u32);
        assert_eq!(f.line_length, 800 * 4);
        assert_eq!(backing_of(0), Some((0xdead_0000, bytes)));
        assert_eq!(kva_of(0), Some((0xffff_8000_dead_0000, bytes)));
        FBS.lock().clear();
    }

    #[test]
    fn backing_none_without_real_fb() {
        FBS.lock().clear();
        // A plain register() (no scanout) has base_pa=0 → not mmap-able.
        register(0, 1, FbVarScreeninfo::default(), FbFixScreeninfo::default());
        assert_eq!(backing_of(0), None);
        assert_eq!(kva_of(0), None);
        FBS.lock().clear();
    }

    #[test]
    fn register_count_roundtrip() {
        FBS.lock().clear();
        let mut v = FbVarScreeninfo::default();
        v.xres = 800; v.yres = 600;
        let idx = register(0, 1, v, FbFixScreeninfo::default());
        assert_eq!(idx, 0);
        assert_eq!(count(), 1);
        assert_eq!(var_of(0).unwrap().xres, 800);
        FBS.lock().clear();
    }

    #[test]
    fn fb_ops_are_per_instance() {
        FBS.lock().clear();
        LAST_FLUSH.store(u32::MAX, AtomicOrdering::SeqCst);
        LAST_BLANK.store(u32::MAX, AtomicOrdering::SeqCst);
        LAST_UNBLANK.store(u32::MAX, AtomicOrdering::SeqCst);

        let bytes = 16u64;
        let fb0 = init_scanout(0x1000, 0xffff_8000_0000_1000, bytes, 16, 1, 1);
        let fb1 = init_scanout(0x2000, 0xffff_8000_0000_2000, bytes, 16, 1, 1);
        assert_ne!(fb0, fb1);
        assert!(set_ops(fb0, FbOps {
            driver_key: 11,
            flush: record_flush,
            blank: record_blank,
            unblank: record_unblank,
        }));
        assert!(set_ops(fb1, FbOps {
            driver_key: 22,
            flush: record_flush,
            blank: record_blank,
            unblank: record_unblank,
        }));

        flush(fb1);
        assert_eq!(LAST_FLUSH.load(AtomicOrdering::SeqCst), 22);
        apply_blank(fb0, FB_BLANK_NORMAL);
        assert_eq!(LAST_BLANK.load(AtomicOrdering::SeqCst), 11);
        apply_blank(fb1, FB_BLANK_NORMAL);
        assert_eq!(LAST_BLANK.load(AtomicOrdering::SeqCst), 22);
        apply_blank(fb1, FB_BLANK_UNBLANK);
        assert_eq!(LAST_UNBLANK.load(AtomicOrdering::SeqCst), 22);

        assert!(clear_ops(fb1));
        LAST_FLUSH.store(u32::MAX, AtomicOrdering::SeqCst);
        flush(fb1);
        assert_eq!(LAST_FLUSH.load(AtomicOrdering::SeqCst), u32::MAX);
        FBS.lock().clear();
    }
}


#[cfg(any(target_os = "oxide-kernel", test))]
pub mod devfs;
