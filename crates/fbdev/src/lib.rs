// Linux fbdev compat shim per docs/48. /dev/fb0..fbN over a DRM
// dumb-buffer + scanout. Full FBIO* ioctl surface per
// linux/include/uapi/linux/fb.h. No DRM modeset privileges
// needed; this crate is a thin presenter on top of `47`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
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

// ============================================================
// Wire structs (verbatim from linux/include/uapi/linux/fb.h)
// ============================================================

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
    /// Backing DRM `MODE_CREATE_DUMB` handle on `card_id`. 0 ⇒ none yet.
    pub card_id:      u32,
    pub crtc_id:      u32,
    pub fb_id:        u32,
    pub dumb_handle:  u32,
}

static FBS: Spinlock<Vec<FbDev>, DriverLockClass> = Spinlock::new(Vec::new());

/// Register a per-CRTC fbdev backed by a DRM card. Returns the fb
/// index (0 ⇒ /dev/fb0).
/// # C: O(1)
pub fn register(card_id: u32, crtc_id: u32, var: FbVarScreeninfo, fix: FbFixScreeninfo) -> u32 {
    let mut g = FBS.lock();
    let idx = g.len() as u32;
    g.push(FbDev {
        idx, var, fix, card_id, crtc_id, fb_id: 0, dumb_handle: 0,
    });
    idx
}

/// Number of registered fbdev devices (count of /dev/fbN inodes).
/// # C: O(1)
pub fn count() -> usize { FBS.lock().len() }

/// Snapshot the var screeninfo for `/dev/fb<idx>`.
/// # C: O(N)
pub fn var_of(idx: u32) -> Option<FbVarScreeninfo> {
    FBS.lock().iter().find(|f| f.idx == idx).map(|f| f.var)
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
