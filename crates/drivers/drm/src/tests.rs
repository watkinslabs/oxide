use alloc::{sync::Arc, vec::Vec};

use crate::*;

#[test]
fn card_res_layout() {
    assert_eq!(core::mem::size_of::<DrmModeCardRes>(), 64);
}

#[test]
fn modeinfo_size() {
    let sz = core::mem::size_of::<DrmModeModeinfo>();
    assert!(sz >= 64 && sz <= 80);
}

#[test]
fn vblank_event_layout() {
    assert_eq!(core::mem::size_of::<DrmEventVblank>(), 32);
}

#[test]
fn default_caps_all_one_or_set() {
    assert_eq!(default_cap(DRM_CAP_DUMB_BUFFER), 1);
    assert_eq!(default_cap(DRM_CAP_DUMB_PREFERRED_DEPTH), 32);
    assert_eq!(default_cap(DRM_CAP_VBLANK_HIGH_CRTC), 0);
    assert_eq!(default_cap(DRM_CAP_CRTC_IN_VBLANK_EVENT), 0);
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
    assert_eq!(core::mem::size_of::<DrmModeCrtc>(), 104);
}

#[test]
fn get_encoder_layout() {
    assert_eq!(core::mem::size_of::<DrmModeGetEncoder>(), 20);
}

#[test]
fn get_connector_layout() {
    assert_eq!(core::mem::size_of::<DrmModeGetConnector>(), 80);
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
    crate::registry::clear_cards_for_tests();
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
    crate::registry::clear_cards_for_tests();
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

#[test]
fn unregister_drops_only_that_card_runtime_state() {
    let _guard = crate::TEST_LOCK.lock();
    crate::registry::clear_cards_for_tests();
    node::unregister_all();
    crate::dumb::TABLES.lock().fbs.clear();
    let card0 = register(Arc::new(DummyDrv));
    let card1 = register(Arc::new(DummyDrv));
    assert_eq!((card0, card1), (0, 1));

    crate::crtc::set_owner(card0, 0x1000);
    crate::crtc::set_owner(card1, 0x2000);
    crate::crtc::set_current_fb_for_tests(card0, 77);
    crate::crtc::set_current_fb_for_tests(card1, 88);
    crate::crtc::queue_flip_event(card0, 0x1000, crtc_id_for(0), 0xaaaa);
    crate::crtc::queue_flip_event(card1, 0x2000, crtc_id_for(0), 0xbbbb);
    crate::dumb::TABLES.lock().fbs.push(crate::dumb::FbObj {
        card_id: card0, fb_id: 77, w: 4, h: 4, pixel_format: DRM_FORMAT_XRGB8888,
        handles: [0; 4], pitches: [16, 0, 0, 0], offsets: [0; 4], scanout_res_id: 0,
    });
    crate::dumb::TABLES.lock().fbs.push(crate::dumb::FbObj {
        card_id: card1, fb_id: 88, w: 4, h: 4, pixel_format: DRM_FORMAT_XRGB8888,
        handles: [0; 4], pitches: [16, 0, 0, 0], offsets: [0; 4], scanout_res_id: 0,
    });

    assert!(unregister(card0));
    assert_eq!(crate::crtc::owner(card0), 0);
    assert_eq!(crate::crtc::current_fb(card0), 0);
    assert!(!crate::crtc::has_events(card0, 0x1000));
    assert!(crate::dumb::TABLES.lock().find_fb(card0, 77).is_none());
    assert_eq!(crate::crtc::owner(card1), 0x2000);
    assert_eq!(crate::crtc::current_fb(card1), 88);
    assert!(crate::crtc::has_events(card1, 0x2000));
    assert!(crate::dumb::TABLES.lock().find_fb(card1, 88).is_some());

    assert!(unregister(card1));
    crate::dumb::TABLES.lock().fbs.clear();
}

/// The size field embedded in a Linux `_IOC` ioctl number (bits 16..30).
fn ioc_size(ioctl: u64) -> u64 { (ioctl >> 16) & 0x3fff }

#[test]
fn ioctl_size_fields_match_structs() {
    // Every _IOWR ioctl encodes sizeof(struct) in bits 16..30. A mismatch means
    // the number was mis-transcribed (GETGAMMA/SETGAMMA had 0x18 vs 0x20,
    // SETPLANE had 0x30 vs 0x40) and libdrm's real call falls through to ENOTTY.
    use core::mem::size_of;
    assert_eq!(ioc_size(DRM_IOCTL_MODE_SETPLANE),        size_of::<DrmModeSetPlane>() as u64);
    assert_eq!(ioc_size(DRM_IOCTL_MODE_DIRTYFB),         size_of::<DrmModeFbDirtyCmd>() as u64);
    assert_eq!(ioc_size(DRM_IOCTL_MODE_OBJ_SETPROPERTY), size_of::<DrmModeObjSetProperty>() as u64);
    assert_eq!(ioc_size(DRM_IOCTL_MODE_SETPROPERTY),     size_of::<DrmModeConnectorSetProperty>() as u64);
    assert_eq!(ioc_size(DRM_IOCTL_MODE_GETGAMMA),        size_of::<DrmModeCrtcLut>() as u64);
    assert_eq!(ioc_size(DRM_IOCTL_MODE_SETGAMMA),        size_of::<DrmModeCrtcLut>() as u64);
    assert_eq!(ioc_size(DRM_IOCTL_MODE_GETFB),           size_of::<DrmModeFbCmd>() as u64);
    assert_eq!(ioc_size(DRM_IOCTL_MODE_SETCRTC),         size_of::<DrmModeCrtc>() as u64);
    assert_eq!(ioc_size(DRM_IOCTL_MODE_GETPLANE),        size_of::<DrmModeGetPlane>() as u64);
    // CURSOR/CURSOR2 nr byte + size must both be right.
    assert_eq!(ioc_size(DRM_IOCTL_MODE_CURSOR),          size_of::<DrmModeCursor>() as u64);
    assert_eq!(DRM_IOCTL_MODE_CURSOR  & 0xff, 0xa3);
    assert_eq!(ioc_size(DRM_IOCTL_MODE_CURSOR2),         size_of::<DrmModeCursor2>() as u64);
    assert_eq!(DRM_IOCTL_MODE_CURSOR2 & 0xff, 0xbb);
}

#[test]
fn new_kms_struct_sizes() {
    use core::mem::size_of;
    assert_eq!(size_of::<DrmModeSetPlane>(),             64);
    assert_eq!(size_of::<DrmModeFbDirtyCmd>(),           24);
    assert_eq!(size_of::<DrmModeObjSetProperty>(),       24);
    assert_eq!(size_of::<DrmModeConnectorSetProperty>(), 16);
    assert_eq!(size_of::<DrmModeCrtcLut>(),              32);
    assert_eq!(size_of::<DrmModeCursor>(),               28);
    assert_eq!(size_of::<DrmModeCursor2>(),              36);
    assert_eq!(size_of::<DrmModeFbCmd>(),                28);
}
