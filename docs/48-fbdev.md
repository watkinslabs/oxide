# 48 fbdev (legacy framebuffer)

FROZEN 2026-08-06. Dep:`01`,`02`,`07`,`13`,`15`,`16`,`19`,`35`,`36`,`45`,`47`. Provides:`/dev/fb0..fbN`,`49` (fbcon backend),legacy SDL/efifb/`Xorg fbdev` userspace.

Full Linux fbdev UAPI per `linux/include/uapi/linux/fb.h`. No deferrals.

## 1 Purpose

Linux fbdev UAPI per `linux/include/uapi/linux/fb.h`. `/dev/fb0` is a memory-mapped linear framebuffer with `FBIOGET_FSCREENINFO`/`VSCREENINFO`/`PUT_VSCREENINFO`/`PAN_DISPLAY`/`BLANK` ioctls. Backed by a driver-owned scanout: DRM/virtio guest RAM or the firmware linear framebuffer fallback (`36`).

## 2 Invariants (frozen)

1. `/dev/fb0` ino = `0x70010000`. devfs registers when the first scanout owner binds.
2. One `/dev/fbN` per active scanout (CRTC). Multi-head display exposes `/dev/fb0`, `/dev/fb1`, ... in scanout-id order.
3. Pixel-memory and cache policy belong to the registering driver; fbdev holds only the physical extent, kernel alias, geometry, and operations.
4. `mmap(/dev/fbN)` returns the registering driver's physical range: the same PMM pages as DRM MAP_DUMB or the firmware aperture from `BootInfo.framebuffer`.
5. Pixel formats: every fb_var_screeninfo configuration that maps to a `45§6` format is accepted: 8/15/16/24/32 bpp; pseudocolor (CMAP) for 8 bpp; truecolor for 15/16/24/32. `FBIOPUT_VSCREENINFO` reallocates the backing dumb-buffer if bpp or resolution changes.
6. Resolution change via `PUT_VSCREENINFO` performs a DRM modeset; rejected with `EINVAL` only if the requested mode isn't in the connector's mode list.

## 3 Public ifc

```rust
// crates/fbdev/src/lib.rs
pub fn register_from_drm(drm: &dyn DrmDriver, fb_id: u32, crtc_id: u32);

pub struct FbInode { /* DRM fb_id + crtc_id + resolved pa/len/pitch */ }

impl vfs::Inode for FbInode {
    fn read(...);    // direct copy from backing pa
    fn write(...);   // direct copy to backing pa
    fn ioctl(...);   // dispatch FBIO* per §5
    fn mmap(...);    // returns the backing pa pages
}
```

## 4 fb_var_screeninfo + fb_fix_screeninfo

```c
// from linux/uapi/linux/fb.h
struct fb_bitfield { __u32 offset, length, msb_right; };

struct fb_var_screeninfo {
    __u32 xres, yres;
    __u32 xres_virtual, yres_virtual;
    __u32 xoffset, yoffset;
    __u32 bits_per_pixel;
    __u32 grayscale;
    struct fb_bitfield red, green, blue, transp;
    __u32 nonstd;
    __u32 activate;
    __u32 height, width;       // physical mm
    __u32 accel_flags;
    __u32 pixclock;
    __u32 left_margin, right_margin, upper_margin, lower_margin;
    __u32 hsync_len, vsync_len;
    __u32 sync, vmode, rotate;
    __u32 colorspace;
    __u32 reserved[4];
};

struct fb_fix_screeninfo {
    char id[16];               // e.g. "virtio_gpufb"
    unsigned long smem_start;  // physical
    __u32 smem_len;
    __u32 type;                // FB_TYPE_PACKED_PIXELS = 0
    __u32 type_aux;
    __u32 visual;              // FB_VISUAL_TRUECOLOR = 2
    __u16 xpanstep, ypanstep, ywrapstep;
    __u32 line_length;         // pitch
    unsigned long mmio_start;
    __u32 mmio_len;
    __u32 accel;               // FB_ACCEL_NONE = 0
    __u16 capabilities;
    __u16 reserved[2];
};
```

Bitfields for 32 bpp BGRA on v1:
- `red    = { offset: 16, length: 8, msb_right: 0 }`
- `green  = { offset:  8, length: 8, msb_right: 0 }`
- `blue   = { offset:  0, length: 8, msb_right: 0 }`
- `transp = { offset: 24, length: 8, msb_right: 0 }`

## 5 ioctl set

| Name | Code | Behavior |
|---|---|---|
| `FBIOGET_VSCREENINFO` | `0x4600` | copy `fb_var_screeninfo` to user |
| `FBIOPUT_VSCREENINFO` | `0x4601` | accept matching res+bpp; reject everything else with `EINVAL` |
| `FBIOGET_FSCREENINFO` | `0x4602` | copy `fb_fix_screeninfo` to user |
| `FBIOGETCMAP` | `0x4604` | colormap (truecolor: returns identity) |
| `FBIOPUTCMAP` | `0x4605` | colormap set (truecolor: ignored, returns 0) |
| `FBIOPAN_DISPLAY` | `0x4606` | adjust `xoffset/yoffset` (single-buffer v1 → reject `EINVAL` if non-zero) |
| `FBIOBLANK` | `0x4611` | DPMS-equivalent blank levels (0=unblank, 1=normal, 4=off) |
| `FBIOGET_VBLANK` | `0x80204612` | vblank counter; v1 reports `count=0`, `flags=0` |
| `FBIO_WAITFORVSYNC` | `0x40044620` | block until next vsync; v1 uses 60Hz fake interval |

## 6 Visual + type constants

| Constant | Value |
|---|---|
| `FB_TYPE_PACKED_PIXELS` | `0` |
| `FB_TYPE_PLANES` | `1` |
| `FB_VISUAL_MONO01` | `0` |
| `FB_VISUAL_MONO10` | `1` |
| `FB_VISUAL_TRUECOLOR` | `2` |
| `FB_VISUAL_PSEUDOCOLOR` | `3` |
| `FB_VISUAL_DIRECTCOLOR` | `4` |
| `FB_VISUAL_STATIC_PSEUDOCOLOR` | `5` |
| `FB_ACCEL_NONE` | `0` |

Visual reported per current fb_var bpp: 8 bpp = `FB_VISUAL_PSEUDOCOLOR`, 15/16/24/32 bpp = `FB_VISUAL_TRUECOLOR`. `FB_TYPE_PACKED_PIXELS` always; `FB_ACCEL_NONE` (acceleration ioctls handled by DRM render-node).

## 7 mmap semantics

`mmap(fd, len, PROT_RW, MAP_SHARED, /dev/fb0_fd, off=0)`:
1. Map the driver-owned physical range into the caller's user VA.
2. PTE flags: read+write+user with the driver-owned cache mode. PMM-backed virtio scanouts are write-back; firmware/MMIO apertures are write-combined.
3. Length must equal `smem_len`; partial mappings rejected with `EINVAL`.

## 8 read/write

`read(/dev/fb0, buf, n)` copies pixel bytes starting at `pos` from the backing pa.
`write(/dev/fb0, buf, n)` copies into the backing pa and invokes the driver's flush operation when one exists; direct linear framebuffers need no command.
`pos` advances by the byte count; supports `lseek(SEEK_SET/CUR/END)`.

## 9 Concurrency

- Single global `Spinlock<FbState>` (lock class `Driver`).
- mmap'd userspace writes don't take the lock; the kernel-side fbcon scroller takes it briefly to issue a flush after each scroll line.

## 10 Failure modes

- Scanout registration still in progress: `EAGAIN`.
- Requested resolution not in connector mode list: `EINVAL`.
- mmap len mismatch: `EINVAL`.

## 11 Test contract (frozen)

- VSCREENINFO smoke: open `/dev/fb0`, `FBIOGET_VSCREENINFO` returns `xres>0`, `yres>0`, `bits_per_pixel=32`.
- FSCREENINFO smoke: `FBIOGET_FSCREENINFO` returns `id="virtio_gpufb"`, `visual=FB_VISUAL_TRUECOLOR`, `line_length=xres*4`.
- mmap smoke: mmap the fb, fill with white (0xFFFFFFFF), close, reopen, read back the first page → all 0xFF.
- write smoke: `dd if=red.bgra of=/dev/fb0 bs=1024 count=1` shows a red strip top-left of host display.
- Coverage ≥80%.

## 16 Cross-spec

`47` (DRM scanout), `45` (virtio-gpu transfer), `36` (firmware framebuffer handoff), `35` (`drv-simplefb`), `49` (fbcon), `19` (devfs node).

## 13 Pan-display + double-buffering

`FBIOPAN_DISPLAY` accepts `(xoffset, yoffset)` pairs that adjust where the visible window starts within the larger virtual framebuffer. Allocators set `yres_virtual = 2 * yres` to enable double-buffering: render to `[yres..2*yres]`, pan to view, then swap roles. Pan completion synced to host vblank via the underlying `47` PAGE_FLIP path.

## 14 CMAP for pseudocolor

`FBIOGETCMAP` / `FBIOPUTCMAP` operate on a 256-entry `fb_cmap`:
```c
struct fb_cmap {
    __u32 start, len;
    __u16 *red, *green, *blue, *transp;   // 16-bit values
};
```

In `FB_VISUAL_PSEUDOCOLOR` mode (8 bpp), the cmap is the active palette. In truecolor visuals (15/16/24/32 bpp) the cmap is identity and writes are stored but ignored at scanout.
