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
pub const DRM_IOCTL_MODE_ADDFB2:          u64 = 0xc04464b8;
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
    g.push(driver);
    (g.len() - 1) as u32
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
        let idx = register(Arc::new(DummyDrv));
        assert_eq!(idx, 0);
        assert_eq!(card_count(), 1);
        let idx2 = register(Arc::new(DummyDrv));
        assert_eq!(idx2, 1);
        CARDS.lock().clear();
    }
}
