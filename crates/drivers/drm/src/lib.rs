// DRM/KMS UAPI core per docs/47.
//
// Module manifest:
// - `uapi`: Linux DRM/KMS ioctl numbers, flags, constants, and wire structs.
// - `crtc`: card ownership, page-flip event queues, and CRTC state.
// - `dumb`: dumb-buffer allocation, framebuffer, and mmap bookkeeping.
// - `modeset`: GETRESOURCES/GETCRTC/connector/encoder/plane query handlers.
// - `node`: `/dev/dri/cardN` publication, file auth, scanout ops, and ioctl dispatch.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

#[cfg(test)]
pub(crate) static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());

pub mod uapi;
pub use uapi::*;

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
pub const DRM_CRTC_ID_BASE:      u32 = 1;
pub const DRM_CONNECTOR_ID_BASE: u32 = 0x100;
pub const DRM_ENCODER_ID_BASE:   u32 = 0x200;
pub const DRM_PLANE_ID_BASE:     u32 = 0x300;
pub const DRM_PLANE_ID_END:      u32 = 0x400;

/// CRTC object id for the `i`-th enabled scanout. # C: O(1)
pub const fn crtc_id_for(i: usize) -> u32 { DRM_CRTC_ID_BASE + i as u32 }
/// Connector object id for the `i`-th enabled scanout. # C: O(1)
pub const fn connector_id_for(i: usize) -> u32 { DRM_CONNECTOR_ID_BASE + i as u32 }
/// Encoder object id for the `i`-th enabled scanout. # C: O(1)
pub const fn encoder_id_for(i: usize) -> u32 { DRM_ENCODER_ID_BASE + i as u32 }
/// Primary-plane object id for the `i`-th CRTC. # C: O(1)
pub const fn plane_id_for(i: usize) -> u32 { DRM_PLANE_ID_BASE + i as u32 }

/// Invert `crtc_id_for`: id → scanout index, if valid for `count`.
/// # C: O(1)
pub fn crtc_idx_of(id: u32, count: usize) -> Option<usize> {
    if id == 0 { return None; }
    let i = (id - 1) as usize;
    if i < count { Some(i) } else { None }
}
/// Invert `connector_id_for`. # C: O(1)
pub fn connector_idx_of(id: u32, count: usize) -> Option<usize> {
    if id < DRM_CONNECTOR_ID_BASE { return None; }
    let i = (id - DRM_CONNECTOR_ID_BASE) as usize;
    if i < count { Some(i) } else { None }
}
/// Invert `encoder_id_for`. # C: O(1)
pub fn encoder_idx_of(id: u32, count: usize) -> Option<usize> {
    if id < DRM_ENCODER_ID_BASE || id >= DRM_PLANE_ID_BASE { return None; }
    let i = (id - DRM_ENCODER_ID_BASE) as usize;
    if i < count { Some(i) } else { None }
}
/// Invert `plane_id_for`. # C: O(1)
pub fn plane_idx_of(id: u32, count: usize) -> Option<usize> {
    if id < DRM_PLANE_ID_BASE || id >= DRM_PLANE_ID_END { return None; }
    let i = (id - DRM_PLANE_ID_BASE) as usize;
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

static CARDS: Spinlock<Vec<Option<Arc<dyn DrmDriver>>>, DriverLockClass>
    = Spinlock::new(Vec::new());
static NEXT_HANDLE: AtomicU32 = AtomicU32::new(1);

/// Register a per-device backend. Returns a stable card slot (0 ⇒ card0).
/// # C: O(N) to reuse a vacant slot, O(1) append when none exists.
pub fn register(driver: Arc<dyn DrmDriver>) -> u32 {
    register_with_parent(driver, None)
}

/// Register a per-device backend whose DRM class device is anchored under a
/// real model parent. This is the Linux class-device shape used by PCI/virtio
/// display drivers: `/sys/class/drm/cardN/device` points back to the owning
/// bus device instead of a virtual-only placeholder.
/// # C: O(N) to reuse a vacant slot, O(1) append when none exists.
pub fn register_with_parent(
    driver: Arc<dyn DrmDriver>,
    parent: Option<(&'static str, alloc::string::String)>,
) -> u32 {
    let mut driver = Some(driver);
    let card_id = {
        let mut g = CARDS.lock();
        if let Some(idx) = g.iter().position(|slot| slot.is_none()) {
            g[idx] = Some(driver.take().expect("DRM driver consumed once"));
            idx as u32
        } else {
            g.push(Some(driver.take().expect("DRM driver consumed once")));
            (g.len() - 1) as u32
        }
    };
    if !node::register(card_id, parent) {
        let mut g = CARDS.lock();
        if let Some(slot) = g.get_mut(card_id as usize) {
            *slot = None;
        }
        while matches!(g.last(), Some(None)) {
            g.pop();
        }
        return u32::MAX;
    }
    card_id
}

/// Snapshot one registered card by stable card id.
/// # C: O(1)
pub fn card(card_id: u32) -> Option<Arc<dyn DrmDriver>> {
    CARDS.lock()
        .get(card_id as usize)
        .and_then(|slot| slot.as_ref().cloned())
}

/// Snapshot the lowest-numbered registered card.
/// # C: O(N)
pub fn primary_card() -> Option<Arc<dyn DrmDriver>> {
    CARDS.lock().iter().find_map(|slot| slot.as_ref().cloned())
}

/// Snapshot of registered cards.
/// # C: O(N)
pub fn cards() -> Vec<Arc<dyn DrmDriver>> {
    CARDS.lock().iter().filter_map(|slot| slot.as_ref().cloned()).collect()
}

/// Unregister a per-device backend. Returns true if a live card was removed.
/// # C: O(N)
pub fn unregister(card_id: u32) -> bool {
    let mut g = CARDS.lock();
    let idx = card_id as usize;
    if idx >= g.len() {
        return false;
    }
    if g[idx].take().is_none() {
        return false;
    }
    while matches!(g.last(), Some(None)) {
        g.pop();
    }
    drop(g);
    crtc::clear_card_state(card_id);
    dumb::clear_card_state(card_id);
    node::unregister(card_id);
    true
}

/// Return the count of registered cards.
/// # C: O(N)
pub fn card_count() -> usize { CARDS.lock().iter().filter(|slot| slot.is_some()).count() }

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
        DRM_CAP_PRIME                   => 0,
        DRM_CAP_TIMESTAMP_MONOTONIC     => 1,
        DRM_CAP_ASYNC_PAGE_FLIP         => 0,
        DRM_CAP_CURSOR_WIDTH            => 0,
        DRM_CAP_CURSOR_HEIGHT           => 0,
        DRM_CAP_ADDFB2_MODIFIERS        => 0,
        DRM_CAP_PAGE_FLIP_TARGET        => 0,
        DRM_CAP_CRTC_IN_VBLANK_EVENT    => 1,
        DRM_CAP_SYNCOBJ                 => 0,
        DRM_CAP_SYNCOBJ_TIMELINE        => 0,
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
        assert_eq!(default_cap(DRM_CAP_CURSOR_WIDTH), 0);
        assert_eq!(default_cap(DRM_CAP_CURSOR_HEIGHT), 0);
        assert_eq!(default_cap(DRM_CAP_PRIME), 0);
        assert_eq!(default_cap(DRM_CAP_ADDFB2_MODIFIERS), 0);
        assert_eq!(default_cap(DRM_CAP_SYNCOBJ), 0);
        assert_eq!(default_cap(DRM_CAP_SYNCOBJ_TIMELINE), 0);
        assert_eq!(default_cap(DRM_CAP_ASYNC_PAGE_FLIP), 0);
        assert_eq!(default_cap(DRM_CAP_PAGE_FLIP_TARGET), 0);
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
        assert_eq!(connector_id_for(0), DRM_CONNECTOR_ID_BASE);
        assert_eq!(encoder_id_for(0), DRM_ENCODER_ID_BASE);
        assert_eq!(plane_id_for(0), DRM_PLANE_ID_BASE);
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
        assert_eq!(connector_idx_of(DRM_CONNECTOR_ID_BASE - 1, n), None);
        assert_eq!(encoder_idx_of(DRM_PLANE_ID_BASE, n), None);
        assert_eq!(plane_idx_of(DRM_ENCODER_ID_BASE, n), None);
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
    fn register_uses_stable_card_slots() {
        let _guard = crate::TEST_LOCK.lock();
        CARDS.lock().clear();
        node::unregister_all();
        let idx = register(Arc::new(DummyDrv));
        assert_eq!(idx, 0);
        assert_eq!(card_count(), 1);
        assert_eq!(node::registered_card_ids(), alloc::vec![0]);
        let idx2 = register(Arc::new(DummyDrv));
        assert_eq!(idx2, 1);
        assert_eq!(node::registered_card_ids(), alloc::vec![0, 1]);
        assert!(unregister(idx));
        assert_eq!(card_count(), 1);
        assert_eq!(node::registered_card_ids(), alloc::vec![1]);
        assert!(!unregister(idx));
        let idx3 = register(Arc::new(DummyDrv));
        assert_eq!(idx3, 0);
        assert_eq!(node::registered_card_ids(), alloc::vec![0, 1]);
        assert!(unregister(idx));
        assert!(unregister(idx2));
        assert_eq!(card_count(), 0);
        assert_eq!(node::registered_card_ids(), Vec::<u32>::new());
    }

    #[test]
    fn register_rolls_back_card_slot_when_node_publication_fails() {
        let _guard = crate::TEST_LOCK.lock();
        CARDS.lock().clear();
        node::unregister_all();
        let conflict = drv::try_device_add(Arc::new(
            drv::Device::new("drm", alloc::string::String::from("dri/card0"), 0, 0, 0)
                .with_devnode("drm", alloc::string::String::from("dri/card0"), Some((226, 0))),
        ))
        .expect("conflict device registration");

        assert_eq!(register(Arc::new(DummyDrv)), u32::MAX);
        assert_eq!(card_count(), 0);
        assert_eq!(node::registered_card_ids(), Vec::<u32>::new());

        drv::device_del(&conflict);
        let idx = register(Arc::new(DummyDrv));
        assert_eq!(idx, 0);
        assert!(unregister(idx));
    }
}

pub mod crtc;
pub mod dumb;
pub mod modeset;
pub mod node;
