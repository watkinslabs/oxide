// DRM/KMS UAPI core per docs/47. Owns:
//   - DrmDriver trait (per-device backend; 45 virtio-gpu plugs in)
//   - master/render fd handle table
//   - ioctl number table per linux/include/uapi/drm/{drm,drm_mode}.h
//   - atomic modeset + sync object book-keeping

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

// ============================================================
// Core ioctl numbers (per linux/include/uapi/drm/drm.h)
// ============================================================
pub const DRM_IOCTL_VERSION:        u64 = 0xc0406400;
pub const DRM_IOCTL_GET_UNIQUE:     u64 = 0xc0106401;
pub const DRM_IOCTL_GET_MAGIC:      u64 = 0x80046402;
pub const DRM_IOCTL_IRQ_BUSID:      u64 = 0xc0106403;
pub const DRM_IOCTL_GET_MAP:        u64 = 0xc0286404;
pub const DRM_IOCTL_GET_CLIENT:     u64 = 0xc01c6405;
pub const DRM_IOCTL_GET_STATS:      u64 = 0x807c6406;
pub const DRM_IOCTL_SET_VERSION:    u64 = 0xc0106407;
pub const DRM_IOCTL_MODESET_CTL:    u64 = 0x40086408;
pub const DRM_IOCTL_GEM_CLOSE:      u64 = 0x40086409;
pub const DRM_IOCTL_GEM_FLINK:      u64 = 0xc008640a;
pub const DRM_IOCTL_GEM_OPEN:       u64 = 0xc010640b;
pub const DRM_IOCTL_GET_CAP:        u64 = 0xc010640c;
pub const DRM_IOCTL_SET_CLIENT_CAP: u64 = 0x4010640d;
pub const DRM_IOCTL_AUTH_MAGIC:     u64 = 0x40046411;
pub const DRM_IOCTL_SET_MASTER:     u64 = 0x0000641e;
pub const DRM_IOCTL_DROP_MASTER:    u64 = 0x0000641f;

// Mode ioctls (drm_mode.h)
pub const DRM_IOCTL_MODE_GETRESOURCES:    u64 = 0xc04064a0;
pub const DRM_IOCTL_MODE_GETCRTC:         u64 = 0xc06864a1;
pub const DRM_IOCTL_MODE_SETCRTC:         u64 = 0xc06864a2;
pub const DRM_IOCTL_MODE_CURSOR:          u64 = 0xc01c64a3;
pub const DRM_IOCTL_MODE_GETGAMMA:        u64 = 0xc01864a4;
pub const DRM_IOCTL_MODE_SETGAMMA:        u64 = 0xc01864a5;
pub const DRM_IOCTL_MODE_GETENCODER:      u64 = 0xc01464a6;
pub const DRM_IOCTL_MODE_GETCONNECTOR:    u64 = 0xc05064a7;
pub const DRM_IOCTL_MODE_ATTACHMODE:      u64 = 0xc05064a8;
pub const DRM_IOCTL_MODE_DETACHMODE:      u64 = 0xc05064a9;
pub const DRM_IOCTL_MODE_GETPROPERTY:     u64 = 0xc04064aa;
pub const DRM_IOCTL_MODE_SETPROPERTY:     u64 = 0xc01064ab;
pub const DRM_IOCTL_MODE_GETPROPBLOB:     u64 = 0xc01064ac;
pub const DRM_IOCTL_MODE_GETFB:           u64 = 0xc01c64ad;
pub const DRM_IOCTL_MODE_ADDFB:           u64 = 0xc01c64ae;
pub const DRM_IOCTL_MODE_RMFB:            u64 = 0xc00464af;
pub const DRM_IOCTL_MODE_PAGE_FLIP:       u64 = 0xc01864b0;
pub const DRM_IOCTL_MODE_DIRTYFB:         u64 = 0xc01864b1;
pub const DRM_IOCTL_MODE_CREATE_DUMB:     u64 = 0xc02064b2;
pub const DRM_IOCTL_MODE_MAP_DUMB:        u64 = 0xc01064b3;
pub const DRM_IOCTL_MODE_DESTROY_DUMB:    u64 = 0xc00464b4;
pub const DRM_IOCTL_MODE_GETPLANERESOURCES: u64 = 0xc00864b5;
pub const DRM_IOCTL_MODE_GETPLANE:        u64 = 0xc02064b6;
pub const DRM_IOCTL_MODE_SETPLANE:        u64 = 0xc03064b7;
// _IOWR(0x64, 0xb8, struct drm_mode_fb_cmd2): the modern struct carries
// modifier[4] (u64) so sizeof = 104 (0x68), NOT the pre-modifier 68 (0x44).
pub const DRM_IOCTL_MODE_ADDFB2:          u64 = 0xc06864b8;
pub const DRM_IOCTL_MODE_OBJ_GETPROPERTIES:u64 = 0xc02064b9;
pub const DRM_IOCTL_MODE_OBJ_SETPROPERTY: u64 = 0xc01864ba;
pub const DRM_IOCTL_MODE_CURSOR2:         u64 = 0xc02464bf;
pub const DRM_IOCTL_MODE_ATOMIC:          u64 = 0xc03864bc;
pub const DRM_IOCTL_MODE_CREATEPROPBLOB:  u64 = 0xc01064bd;
pub const DRM_IOCTL_MODE_DESTROYPROPBLOB: u64 = 0xc00464be;

// Sync-object ioctls (per `47§19`)
pub const DRM_IOCTL_SYNCOBJ_CREATE:           u64 = 0xc00864bf;
pub const DRM_IOCTL_SYNCOBJ_DESTROY:          u64 = 0xc00864c0;
pub const DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD:     u64 = 0xc00c64c1;
pub const DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE:     u64 = 0xc00c64c2;
pub const DRM_IOCTL_SYNCOBJ_WAIT:             u64 = 0xc01864c3;
pub const DRM_IOCTL_SYNCOBJ_RESET:            u64 = 0xc00864c4;
pub const DRM_IOCTL_SYNCOBJ_SIGNAL:           u64 = 0xc00864c5;
pub const DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT:    u64 = 0xc02864ca;
pub const DRM_IOCTL_SYNCOBJ_QUERY:            u64 = 0xc01864cb;
pub const DRM_IOCTL_SYNCOBJ_TRANSFER:         u64 = 0xc02064cc;
pub const DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL:  u64 = 0xc01864cd;

// PRIME (DMA-BUF)
pub const DRM_IOCTL_PRIME_HANDLE_TO_FD: u64 = 0xc00c642d;
pub const DRM_IOCTL_PRIME_FD_TO_HANDLE: u64 = 0xc00c642e;

// DRM_CAP_*
pub const DRM_CAP_DUMB_BUFFER:             u64 = 0x01;
pub const DRM_CAP_VBLANK_HIGH_CRTC:        u64 = 0x02;
pub const DRM_CAP_DUMB_PREFERRED_DEPTH:    u64 = 0x03;
pub const DRM_CAP_DUMB_PREFER_SHADOW:      u64 = 0x04;
pub const DRM_CAP_PRIME:                   u64 = 0x05;
pub const DRM_CAP_TIMESTAMP_MONOTONIC:     u64 = 0x06;
pub const DRM_CAP_ASYNC_PAGE_FLIP:         u64 = 0x07;
pub const DRM_CAP_CURSOR_WIDTH:            u64 = 0x08;
pub const DRM_CAP_CURSOR_HEIGHT:           u64 = 0x09;
pub const DRM_CAP_ADDFB2_MODIFIERS:        u64 = 0x10;
pub const DRM_CAP_PAGE_FLIP_TARGET:        u64 = 0x11;
pub const DRM_CAP_CRTC_IN_VBLANK_EVENT:    u64 = 0x12;
pub const DRM_CAP_SYNCOBJ:                 u64 = 0x13;
pub const DRM_CAP_SYNCOBJ_TIMELINE:        u64 = 0x14;

// DRM_CLIENT_CAP_*
pub const DRM_CLIENT_CAP_STEREO_3D:             u64 = 1;
pub const DRM_CLIENT_CAP_UNIVERSAL_PLANES:      u64 = 2;
pub const DRM_CLIENT_CAP_ATOMIC:                u64 = 3;
pub const DRM_CLIENT_CAP_ASPECT_RATIO:          u64 = 4;
pub const DRM_CLIENT_CAP_WRITEBACK_CONNECTORS:  u64 = 5;
pub const DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT:  u64 = 6;

// Object types (atomic-modeset)
pub const DRM_MODE_OBJECT_CRTC:      u32 = 0xcccccccc;
pub const DRM_MODE_OBJECT_CONNECTOR: u32 = 0xc0c0c0c0;
pub const DRM_MODE_OBJECT_ENCODER:   u32 = 0xe0e0e0e0;
pub const DRM_MODE_OBJECT_MODE:      u32 = 0xdededede;
pub const DRM_MODE_OBJECT_PROPERTY:  u32 = 0xb0b0b0b0;
pub const DRM_MODE_OBJECT_FB:        u32 = 0xfbfbfbfb;
pub const DRM_MODE_OBJECT_BLOB:      u32 = 0xbbbbbbbb;
pub const DRM_MODE_OBJECT_PLANE:     u32 = 0xeeeeeeee;
pub const DRM_MODE_OBJECT_ANY:       u32 = 0;

// Atomic-commit flags
pub const DRM_MODE_PAGE_FLIP_EVENT:        u32 = 0x01;
pub const DRM_MODE_PAGE_FLIP_ASYNC:        u32 = 0x02;
pub const DRM_MODE_ATOMIC_TEST_ONLY:       u32 = 0x0100;
pub const DRM_MODE_ATOMIC_NONBLOCK:        u32 = 0x0200;
pub const DRM_MODE_ATOMIC_ALLOW_MODESET:   u32 = 0x0400;

// drm_event types (per linux/include/uapi/drm/drm.h)
pub const DRM_EVENT_VBLANK:          u32 = 0x01;
pub const DRM_EVENT_FLIP_COMPLETE:   u32 = 0x02;
pub const DRM_EVENT_CRTC_SEQUENCE:   u32 = 0x03;
pub const DRM_EVENT_HOTPLUG:         u32 = 0x80000004;

// ============================================================
// Wire structs (drm_mode_card_res, drm_event, etc.)
// ============================================================

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeCardRes {
    pub fb_id_ptr:        u64,
    pub crtc_id_ptr:      u64,
    pub connector_id_ptr: u64,
    pub encoder_id_ptr:   u64,
    pub count_fbs:        u32,
    pub count_crtcs:      u32,
    pub count_connectors: u32,
    pub count_encoders:   u32,
    pub min_width:        u32,
    pub max_width:        u32,
    pub min_height:       u32,
    pub max_height:       u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DrmModeModeinfo {
    pub clock:       u32,
    pub hdisplay:    u16, pub hsync_start: u16, pub hsync_end: u16, pub htotal: u16,
    pub hskew:       u16,
    pub vdisplay:    u16, pub vsync_start: u16, pub vsync_end: u16, pub vtotal: u16,
    pub vscan:       u16,
    pub vrefresh:    u32,
    pub flags:       u32,
    pub ty:          u32,
    pub name:        [u8; 32],
}

impl Default for DrmModeModeinfo {
    fn default() -> Self {
        Self { clock: 0, hdisplay: 0, hsync_start: 0, hsync_end: 0, htotal: 0,
               hskew: 0, vdisplay: 0, vsync_start: 0, vsync_end: 0, vtotal: 0,
               vscan: 0, vrefresh: 0, flags: 0, ty: 0, name: [0; 32] }
    }
}

// `struct drm_mode_crtc` (drm_mode.h) — 0xc06864a1, 104 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DrmModeCrtc {
    pub set_connectors_ptr: u64,
    pub count_connectors:   u32,
    pub crtc_id:            u32,
    pub fb_id:              u32,
    pub x:                  u32,
    pub y:                  u32,
    pub gamma_size:         u32,
    pub mode_valid:         u32,
    pub mode:               DrmModeModeinfo,
}

impl Default for DrmModeCrtc {
    fn default() -> Self {
        Self { set_connectors_ptr: 0, count_connectors: 0, crtc_id: 0, fb_id: 0,
               x: 0, y: 0, gamma_size: 0, mode_valid: 0, mode: DrmModeModeinfo::default() }
    }
}

// `struct drm_mode_get_encoder` (drm_mode.h) — 0xc01464a6, 20 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeGetEncoder {
    pub encoder_id:      u32,
    pub encoder_type:    u32,
    pub crtc_id:         u32,
    pub possible_crtcs:  u32,
    pub possible_clones: u32,
}

// `struct drm_mode_get_connector` (drm_mode.h) — 0xc05064a7, 80 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeGetConnector {
    pub encoders_ptr:           u64,
    pub modes_ptr:              u64,
    pub props_ptr:              u64,
    pub prop_values_ptr:        u64,
    pub count_modes:            u32,
    pub count_props:            u32,
    pub count_encoders:         u32,
    pub encoder_id:             u32,
    pub connector_id:           u32,
    pub connector_type:         u32,
    pub connector_type_id:      u32,
    pub connection:             u32,
    pub mm_width:               u32,
    pub mm_height:              u32,
    pub subpixel:               u32,
    pub pad:                    u32,
}

// `struct drm_mode_get_plane_res` (drm_mode.h) — 0xc00864b5, 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeGetPlaneRes {
    pub plane_id_ptr: u64,
    pub count_planes: u32,
    pub pad:          u32,
}

// `struct drm_mode_get_plane` (drm_mode.h) — 0xc02064b6, 32 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeGetPlane {
    pub plane_id:        u32,
    pub crtc_id:         u32,
    pub fb_id:           u32,
    pub possible_crtcs:  u32,
    pub gamma_size:      u32,
    pub count_format_types: u32,
    pub format_type_ptr: u64,
}

// drm_mode connection status (drm_mode.h)
pub const DRM_MODE_CONNECTED:         u32 = 1;
pub const DRM_MODE_DISCONNECTED:      u32 = 2;
pub const DRM_MODE_UNKNOWNCONNECTION: u32 = 3;

// drm_mode connector types (drm_mode.h)
pub const DRM_MODE_CONNECTOR_VIRTUAL: u32 = 15;

// drm_mode encoder types (drm_mode.h)
pub const DRM_MODE_ENCODER_VIRTUAL: u32 = 5;

// drm_mode subpixel order (drm_mode.h)
pub const DRM_MODE_SUBPIXEL_UNKNOWN: u32 = 1;

// drm_mode mode type / flags (drm_mode.h)
pub const DRM_MODE_TYPE_PREFERRED: u32 = 1 << 3;
pub const DRM_MODE_TYPE_DRIVER:    u32 = 1 << 6;
pub const DRM_MODE_FLAG_PHSYNC:    u32 = 1 << 0;
pub const DRM_MODE_FLAG_PVSYNC:    u32 = 1 << 2;

// fourcc pixel formats (drm_fourcc.h)
pub const DRM_FORMAT_XRGB8888: u32 = 0x3432_5258; // 'XR24'
pub const DRM_FORMAT_ARGB8888: u32 = 0x3432_5241; // 'AR24'

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmEvent { pub ty: u32, pub length: u32 }

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmEventVblank {
    pub base: DrmEvent,
    pub user_data: u64,
    pub tv_sec:    u32,
    pub tv_usec:   u32,
    pub sequence:  u32,
    pub crtc_id:   u32,
}

// ============================================================
// DrmDriver trait — per-device backend
// ============================================================

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, NoMem, Busy, NoSpc, OpNotSupp, Perm, NoEnt }

pub type KResult<T> = core::result::Result<T, Error>;

/// Per-connector modeset facts the DRM core encodes into the
/// `drm_mode_get_connector` wire struct.
#[derive(Copy, Clone, Debug)]
pub struct ConnectorInfo {
    pub connection:     u32,   // DRM_MODE_CONNECTED / DISCONNECTED
    pub connector_type: u32,   // DRM_MODE_CONNECTOR_*
    pub encoder_id:     u32,   // currently-attached encoder
    pub mm_width:       u32,
    pub mm_height:      u32,
    pub mode_count:     u32,   // number of modes (v1: always 1)
}

/// Per-CRTC modeset facts for `drm_mode_crtc`.
#[derive(Copy, Clone, Debug)]
pub struct CrtcInfo {
    pub mode_valid: u32,
    pub fb_id:      u32,
    pub x:          u32,
    pub y:          u32,
    pub gamma_size: u32,
    pub mode:       DrmModeModeinfo,
}

/// Per-encoder modeset facts for `drm_mode_get_encoder`.
#[derive(Copy, Clone, Debug)]
pub struct EncoderInfo {
    pub encoder_type:    u32,   // DRM_MODE_ENCODER_*
    pub crtc_id:         u32,
    pub possible_crtcs:  u32,
    pub possible_clones: u32,
}

/// Per-plane modeset facts for `drm_mode_get_plane`.
#[derive(Copy, Clone, Debug)]
pub struct PlaneInfo {
    pub crtc_id:        u32,
    pub fb_id:          u32,
    pub possible_crtcs: u32,
}

pub trait DrmDriver: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> (u32, u32, u32);
    fn date(&self) -> &'static str;
    fn desc(&self) -> &'static str;
    fn unique(&self) -> &str;
    /// `(count_fbs, count_crtcs, count_connectors, count_encoders)`
    fn resource_counts(&self) -> (u32, u32, u32, u32);
    /// Min/max width/height per `MODE_GETRESOURCES`.
    fn dim_bounds(&self) -> (u32, u32, u32, u32);
    fn cap(&self, cap: u64) -> u64;

    // ---- D5a read-only modeset object enumeration ----
    // V1 1:1:1 model: each enabled scanout i (0-based) →
    //   CRTC id        = i + 1
    //   connector id   = 0x100 + i
    //   encoder id     = 0x200 + i
    //   primary plane  = 0x300 + i
    // Defaults below give an empty card; virtio-gpu overrides them.

    /// Real CRTC object ids (one per enabled scanout). # C: O(n)
    fn crtc_ids(&self) -> Vec<u32> { Vec::new() }
    /// Real connector object ids. # C: O(n)
    fn connector_ids(&self) -> Vec<u32> { Vec::new() }
    /// Real encoder object ids. # C: O(n)
    fn encoder_ids(&self) -> Vec<u32> { Vec::new() }
    /// Real primary-plane object ids (one per CRTC). # C: O(n)
    fn plane_ids(&self) -> Vec<u32> { Vec::new() }

    /// Mode for connector `idx` built from the scanout rectangle.
    /// # C: O(1)
    fn mode_for(&self, _idx: usize) -> DrmModeModeinfo { DrmModeModeinfo::default() }
    /// Connector facts for `idx`. `None` ⇒ no such connector.
    /// # C: O(1)
    fn connector_info(&self, _idx: usize) -> Option<ConnectorInfo> { None }
    /// CRTC facts for `idx`. `None` ⇒ no such CRTC. # C: O(1)
    fn crtc_info(&self, _idx: usize) -> Option<CrtcInfo> { None }
    /// Encoder facts for `idx`. `None` ⇒ no such encoder. # C: O(1)
    fn encoder_info(&self, _idx: usize) -> Option<EncoderInfo> { None }
    /// Plane facts for `idx`. `None` ⇒ no such plane. # C: O(1)
    fn plane_info(&self, _idx: usize) -> Option<PlaneInfo> { None }
}

// V1 1:1:1 id-model helpers — pure, hosted-testable.

/// CRTC object id for the `i`-th enabled scanout. # C: O(1)
pub const fn crtc_id_for(i: usize) -> u32 { (i + 1) as u32 }
/// Connector object id for the `i`-th enabled scanout. # C: O(1)
pub const fn connector_id_for(i: usize) -> u32 { 0x100 + i as u32 }
/// Encoder object id for the `i`-th enabled scanout. # C: O(1)
pub const fn encoder_id_for(i: usize) -> u32 { 0x200 + i as u32 }
/// Primary-plane object id for the `i`-th CRTC. # C: O(1)
pub const fn plane_id_for(i: usize) -> u32 { 0x300 + i as u32 }

/// Invert `crtc_id_for`: id → scanout index, if valid for `count`.
/// # C: O(1)
pub fn crtc_idx_of(id: u32, count: usize) -> Option<usize> {
    if id == 0 { return None; }
    let i = (id - 1) as usize;
    if i < count { Some(i) } else { None }
}
/// Invert `connector_id_for`. # C: O(1)
pub fn connector_idx_of(id: u32, count: usize) -> Option<usize> {
    if id < 0x100 { return None; }
    let i = (id - 0x100) as usize;
    if i < count { Some(i) } else { None }
}
/// Invert `encoder_id_for`. # C: O(1)
pub fn encoder_idx_of(id: u32, count: usize) -> Option<usize> {
    if id < 0x200 || id >= 0x300 { return None; }
    let i = (id - 0x200) as usize;
    if i < count { Some(i) } else { None }
}
/// Invert `plane_id_for`. # C: O(1)
pub fn plane_idx_of(id: u32, count: usize) -> Option<usize> {
    if id < 0x300 || id >= 0x400 { return None; }
    let i = (id - 0x300) as usize;
    if i < count { Some(i) } else { None }
}

/// Build a `DrmModeModeinfo` from a scanout `w`×`h` rectangle at
/// 60 Hz. Sane CVT-ish timings so libdrm's mode list is non-empty.
/// # C: O(1)
pub fn mode_from_rect(w: u32, h: u32) -> DrmModeModeinfo {
    let w16 = w as u16;
    let h16 = h as u16;
    // Simple synthesized timings: hsync ~ +6%, htotal ~ +25%; same
    // for vertical. clock = htotal*vtotal*60 / 1000 (kHz).
    let hsync_start = w16.saturating_add(w16 / 20);
    let hsync_end   = w16.saturating_add(w16 / 10);
    let htotal      = w16.saturating_add(w16 / 4);
    let vsync_start = h16.saturating_add(3);
    let vsync_end   = h16.saturating_add(9);
    let vtotal      = h16.saturating_add(h16 / 40).saturating_add(20);
    let clock = ((htotal as u64) * (vtotal as u64) * 60 / 1000) as u32;
    let mut name = [0u8; 32];
    write_mode_name(&mut name, w, h);
    DrmModeModeinfo {
        clock,
        hdisplay: w16, hsync_start, hsync_end, htotal, hskew: 0,
        vdisplay: h16, vsync_start, vsync_end, vtotal, vscan: 0,
        vrefresh: 60,
        flags: DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC,
        ty: DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED,
        name,
    }
}

/// Write a "<w>x<h>" NUL-terminated mode name into `out[32]`.
/// # C: O(len)
fn write_mode_name(out: &mut [u8; 32], w: u32, h: u32) {
    let mut p = 0usize;
    p += write_dec(&mut out[p..], w);
    if p < 31 { out[p] = b'x'; p += 1; }
    let _ = write_dec(&mut out[p..], h);
}

fn write_dec(out: &mut [u8], mut v: u32) -> usize {
    let mut tmp = [0u8; 10];
    let mut n = 0;
    if v == 0 { tmp[n] = b'0'; n += 1; }
    while v > 0 { tmp[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
    let mut w = 0;
    while w < n && w < out.len() { out[w] = tmp[n - 1 - w]; w += 1; }
    w
}

// ============================================================
// Card registry
// ============================================================

static CARDS: Spinlock<Vec<Arc<dyn DrmDriver>>, DriverLockClass>
    = Spinlock::new(Vec::new());
static NEXT_HANDLE: AtomicU32 = AtomicU32::new(1);

/// Register a per-device backend. Returns the card index (0 ⇒ card0).
/// # C: O(1)
pub fn register(driver: Arc<dyn DrmDriver>) -> u32 {
    let mut g = CARDS.lock();
    if g.is_empty() {
        node::register();
    }
    g.push(driver);
    (g.len() - 1) as u32
}

/// Unregister a per-device backend. Returns true if a live card was removed.
/// # C: O(N)
pub fn unregister(card_id: u32) -> bool {
    let mut g = CARDS.lock();
    let idx = card_id as usize;
    if idx >= g.len() {
        return false;
    }
    g.remove(idx);
    let empty = g.is_empty();
    drop(g);
    if empty {
        node::unregister();
    }
    true
}

/// Snapshot of registered cards.
/// # C: O(1)
pub fn cards() -> Vec<Arc<dyn DrmDriver>> {
    CARDS.lock().clone()
}

/// Return the count of registered cards.
/// # C: O(1)
pub fn card_count() -> usize { CARDS.lock().len() }

/// Allocate a fresh per-fd handle id (GEM handle, syncobj handle, etc.)
/// # C: O(1)
pub fn alloc_handle() -> u32 { NEXT_HANDLE.fetch_add(1, Ordering::AcqRel) }

/// Return the v1 default `cap` value table for `47§7`.
/// # C: O(1)
pub fn default_cap(cap: u64) -> u64 {
    match cap {
        DRM_CAP_DUMB_BUFFER             => 1,
        DRM_CAP_VBLANK_HIGH_CRTC        => 1,
        DRM_CAP_DUMB_PREFERRED_DEPTH    => 32,
        DRM_CAP_DUMB_PREFER_SHADOW      => 0,
        DRM_CAP_PRIME                   => 3,
        DRM_CAP_TIMESTAMP_MONOTONIC     => 1,
        DRM_CAP_ASYNC_PAGE_FLIP         => 1,
        DRM_CAP_CURSOR_WIDTH            => 64,
        DRM_CAP_CURSOR_HEIGHT           => 64,
        DRM_CAP_ADDFB2_MODIFIERS        => 1,
        DRM_CAP_PAGE_FLIP_TARGET        => 1,
        DRM_CAP_CRTC_IN_VBLANK_EVENT    => 1,
        DRM_CAP_SYNCOBJ                 => 1,
        DRM_CAP_SYNCOBJ_TIMELINE        => 1,
        _                               => 0,
    }
}

/// Classify an ioctl by master/render policy per `47§4`.
/// `true` = master-only (modesetting); `false` = render-allowed.
/// # C: O(1)
pub fn is_master_only(req: u64) -> bool {
    matches!(req,
        DRM_IOCTL_MODE_SETCRTC | DRM_IOCTL_MODE_PAGE_FLIP
        | DRM_IOCTL_MODE_ATOMIC | DRM_IOCTL_SET_MASTER | DRM_IOCTL_DROP_MASTER
        | DRM_IOCTL_MODE_SETPLANE | DRM_IOCTL_MODE_DIRTYFB
        | DRM_IOCTL_MODE_OBJ_SETPROPERTY | DRM_IOCTL_MODE_SETPROPERTY
        | DRM_IOCTL_MODE_CURSOR | DRM_IOCTL_MODE_CURSOR2
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_res_layout() {
        // 4 ptrs + 8 u32 = 32 + 32 = 64 bytes
        assert_eq!(core::mem::size_of::<DrmModeCardRes>(), 64);
    }

    #[test]
    fn modeinfo_size() {
        // 4 + 6×u16 + 5×u16 + 4 + 4 + 4 + 32 = 4 + 12 + 10 + 4 + 4 + 4 + 32 = 70
        // Linux pads to align fields; verify what we have isn't surprising:
        let sz = core::mem::size_of::<DrmModeModeinfo>();
        assert!(sz >= 64 && sz <= 80);
    }

    #[test]
    fn vblank_event_layout() {
        // base 8 + user_data 8 + tv_sec 4 + tv_usec 4 + sequence 4 + crtc_id 4 = 32
        assert_eq!(core::mem::size_of::<DrmEventVblank>(), 32);
    }

    #[test]
    fn default_caps_all_one_or_set() {
        assert_eq!(default_cap(DRM_CAP_DUMB_BUFFER), 1);
        assert_eq!(default_cap(DRM_CAP_DUMB_PREFERRED_DEPTH), 32);
        assert_eq!(default_cap(DRM_CAP_CURSOR_WIDTH), 64);
        assert_eq!(default_cap(0xdead), 0);
    }

    #[test]
    fn master_only_classification() {
        assert!(is_master_only(DRM_IOCTL_MODE_SETCRTC));
        assert!(is_master_only(DRM_IOCTL_MODE_ATOMIC));
        assert!(!is_master_only(DRM_IOCTL_MODE_GETRESOURCES));
        assert!(!is_master_only(DRM_IOCTL_MODE_CREATE_DUMB));
        assert!(!is_master_only(DRM_IOCTL_PRIME_HANDLE_TO_FD));
    }

    #[test]
    fn crtc_layout() {
        // drm_mode_crtc: ptr 8 + 5×u32(connectors..fb_id..) ... + 68 mode
        // = 8 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 68 = 104.
        assert_eq!(core::mem::size_of::<DrmModeCrtc>(), 104);
    }

    #[test]
    fn get_encoder_layout() {
        assert_eq!(core::mem::size_of::<DrmModeGetEncoder>(), 20);
    }

    #[test]
    fn get_connector_layout() {
        // 4 ptrs (32) + 12 u32 (48) = 80.
        assert_eq!(core::mem::size_of::<DrmModeGetConnector>(), 80);
        // encoder_id sits right after count_encoders.
        assert_eq!(core::mem::offset_of!(DrmModeGetConnector, encoder_id), 44);
        assert_eq!(core::mem::offset_of!(DrmModeGetConnector, connector_id), 48);
        assert_eq!(core::mem::offset_of!(DrmModeGetConnector, connection), 60);
    }

    #[test]
    fn get_plane_res_layout() {
        assert_eq!(core::mem::size_of::<DrmModeGetPlaneRes>(), 16);
    }

    #[test]
    fn get_plane_layout() {
        // 6 u32 (24) + 1 ptr (8) = 32.
        assert_eq!(core::mem::size_of::<DrmModeGetPlane>(), 32);
        assert_eq!(core::mem::offset_of!(DrmModeGetPlane, format_type_ptr), 24);
    }

    #[test]
    fn id_model_1_1_1() {
        assert_eq!(crtc_id_for(0), 1);
        assert_eq!(crtc_id_for(1), 2);
        assert_eq!(connector_id_for(0), 0x100);
        assert_eq!(encoder_id_for(0), 0x200);
        assert_eq!(plane_id_for(0), 0x300);
    }

    #[test]
    fn id_model_round_trips() {
        let n = 3;
        for i in 0..n {
            assert_eq!(crtc_idx_of(crtc_id_for(i), n), Some(i));
            assert_eq!(connector_idx_of(connector_id_for(i), n), Some(i));
            assert_eq!(encoder_idx_of(encoder_id_for(i), n), Some(i));
            assert_eq!(plane_idx_of(plane_id_for(i), n), Some(i));
        }
        // Out-of-range / wrong-namespace ids are rejected.
        assert_eq!(crtc_idx_of(0, n), None);
        assert_eq!(crtc_idx_of(99, n), None);
        assert_eq!(connector_idx_of(0x99, n), None);
        assert_eq!(encoder_idx_of(0x300, n), None);
        assert_eq!(plane_idx_of(0x200, n), None);
    }

    #[test]
    fn mode_builder_dims_and_name() {
        let m = mode_from_rect(800, 600);
        assert_eq!(m.hdisplay, 800);
        assert_eq!(m.vdisplay, 600);
        assert_eq!(m.vrefresh, 60);
        assert!(m.htotal > 800);
        assert!(m.vtotal > 600);
        assert!(m.clock > 0);
        // name starts "800x600\0"
        assert_eq!(&m.name[..8], b"800x600\0");
        assert_ne!(m.ty & DRM_MODE_TYPE_PREFERRED, 0);
    }

    #[test]
    fn mode_builder_1920x1080() {
        let m = mode_from_rect(1920, 1080);
        assert_eq!(m.hdisplay, 1920);
        assert_eq!(m.vdisplay, 1080);
        assert_eq!(&m.name[..10], b"1920x1080\0");
    }

    #[test]
    fn handle_alloc_increments() {
        let a = alloc_handle();
        let b = alloc_handle();
        assert_ne!(a, b);
        assert_eq!(b, a + 1);
    }

    struct DummyDrv;
    impl DrmDriver for DummyDrv {
        fn name(&self) -> &'static str { "dummy" }
        fn version(&self) -> (u32, u32, u32) { (1, 0, 0) }
        fn date(&self) -> &'static str { "20260509" }
        fn desc(&self) -> &'static str { "test" }
        fn unique(&self) -> &str { "pci:0000:00:01.0" }
        fn resource_counts(&self) -> (u32, u32, u32, u32) { (0, 1, 1, 1) }
        fn dim_bounds(&self) -> (u32, u32, u32, u32) { (1, 8192, 1, 8192) }
        fn cap(&self, cap: u64) -> u64 { default_cap(cap) }
    }

    #[test]
    fn register_increments_card_count() {
        CARDS.lock().clear();
        node::unregister();
        let idx = register(Arc::new(DummyDrv));
        assert_eq!(idx, 0);
        assert_eq!(card_count(), 1);
        let idx2 = register(Arc::new(DummyDrv));
        assert_eq!(idx2, 1);
        assert!(unregister(idx2));
        assert!(unregister(idx));
        assert_eq!(card_count(), 0);
    }
}

pub mod crtc;
pub mod dumb;
pub mod modeset;
pub mod node;
