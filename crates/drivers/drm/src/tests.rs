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
    // A depth is the driver's to name; the core answers zero for a driver that
    // names none, and never a bit count.
    assert_eq!(default_cap(DRM_CAP_DUMB_PREFERRED_DEPTH), 0);
    assert_eq!(default_cap(DRM_CAP_VBLANK_HIGH_CRTC), 0);
    assert_eq!(default_cap(DRM_CAP_CRTC_IN_VBLANK_EVENT), 0);
    // Every device gets the core's 64x64 cursor size, including the ones with
    // no cursor plane at all: a display server sizes its cursor buffer object
    // from these before it can discover whether the cursor ioctls work.
    assert_eq!(default_cap(DRM_CAP_CURSOR_WIDTH), 64);
    assert_eq!(default_cap(DRM_CAP_CURSOR_HEIGHT), 64);
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

struct DummyDrv { render: bool }

impl DrmDriver for DummyDrv {
    fn name(&self) -> &'static str { "dummy" }
    fn version(&self) -> (u32, u32, u32) { (1, 0, 0) }
    fn date(&self) -> &'static str { "20260509" }
    fn desc(&self) -> &'static str { "test" }
    fn unique(&self) -> &str { "pci:0000:00:01.0" }
    fn resource_counts(&self) -> (u32, u32, u32, u32) { (0, 1, 1, 1) }
    fn dim_bounds(&self) -> (u32, u32, u32, u32) { (1, 8192, 1, 8192) }
    fn cap(&self, cap: u64) -> u64 { default_cap(cap) }
    fn supports_render_node(&self) -> bool { self.render }
}

#[test]
fn register_uses_stable_card_slots() {
    let _guard = crate::TEST_LOCK.lock();
    crate::registry::clear_cards_for_tests();
    node::unregister_all();
    let idx = register(Arc::new(DummyDrv { render: true }));
    assert_eq!(idx, 0);
    assert_eq!(card_count(), 1);
    assert_eq!(node::registered_card_ids(), alloc::vec![0]);
    let idx2 = register(Arc::new(DummyDrv { render: true }));
    assert_eq!(idx2, 1);
    assert_eq!(node::registered_card_ids(), alloc::vec![0, 1]);
    assert!(unregister(idx));
    assert_eq!(card_count(), 1);
    assert_eq!(node::registered_card_ids(), alloc::vec![1]);
    assert!(!unregister(idx));
    let idx3 = register(Arc::new(DummyDrv { render: true }));
    assert_eq!(idx3, 0);
    assert_eq!(node::registered_card_ids(), alloc::vec![0, 1]);
    assert!(unregister(idx));
    assert!(unregister(idx2));
    assert_eq!(card_count(), 0);
    assert_eq!(node::registered_card_ids(), Vec::<u32>::new());
}

#[test]
fn kms_only_card_does_not_consume_the_first_render_minor() {
    let _guard = crate::TEST_LOCK.lock();
    crate::registry::clear_cards_for_tests();
    node::unregister_all();

    let kms = register(Arc::new(DummyDrv { render: false }));
    assert_eq!(kms, 0);
    assert!(!drv::devices().iter().any(|d| d.bus == "drm" && d.addr == "renderD128"));

    let render = register(Arc::new(DummyDrv { render: true }));
    assert_eq!(render, 1);
    assert!(drv::devices().iter().any(|d| d.bus == "drm" && d.addr == "renderD128"));

    assert!(unregister(render));
    assert!(unregister(kms));
}

#[test]
fn register_rolls_back_card_slot_when_node_publication_fails() {
    let _guard = crate::TEST_LOCK.lock();
    crate::registry::clear_cards_for_tests();
    node::unregister_all();
    let conflict = drv::try_device_add(Arc::new(
        drv::Device::new("drm", alloc::string::String::from("card0"), 0, 0, 0)
            .with_devnode("drm", alloc::string::String::from("dri/card0"), Some((226, 0))),
    ))
    .expect("conflict device registration");

    assert_eq!(register(Arc::new(DummyDrv { render: true })), u32::MAX);
    assert_eq!(card_count(), 0);
    assert_eq!(node::registered_card_ids(), Vec::<u32>::new());

    drv::device_del(&conflict);
    let idx = register(Arc::new(DummyDrv { render: true }));
    assert_eq!(idx, 0);
    assert!(unregister(idx));
}

#[test]
fn unregister_drops_only_that_card_runtime_state() {
    let _guard = crate::TEST_LOCK.lock();
    crate::registry::clear_cards_for_tests();
    node::unregister_all();
    crate::dumb::TABLES.lock().fbs.clear();
    let card0 = register(Arc::new(DummyDrv { render: true }));
    let card1 = register(Arc::new(DummyDrv { render: true }));
    assert_eq!((card0, card1), (0, 1));

    crate::crtc::set_owner(card0, 0x1000);
    crate::crtc::set_owner(card1, 0x2000);
    crate::crtc::set_current_fb_for_tests(card0, 77);
    crate::crtc::set_current_fb_for_tests(card1, 88);
    crate::crtc::queue_flip_event(card0, 0x1000, crtc_id_for(0), 0xaaaa);
    crate::crtc::queue_flip_event(card1, 0x2000, crtc_id_for(0), 0xbbbb);
    crate::dumb::TABLES.lock().fbs.push(crate::dumb::FbObj {
        card_id: card0, fb_id: 77, owner_token: 0, bound: false, w: 4, h: 4, pixel_format: DRM_FORMAT_XRGB8888,
        handles: [0; 4], pitches: [16, 0, 0, 0], offsets: [0; 4], scanout_res_id: 0,
    });
    crate::dumb::TABLES.lock().fbs.push(crate::dumb::FbObj {
        card_id: card1, fb_id: 88, owner_token: 0, bound: false, w: 4, h: 4, pixel_format: DRM_FORMAT_XRGB8888,
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
    // the number was mis-transcribed (GETGAMMA/SETGAMMA had 0x18 vs 0x20) and
    // libdrm's real call falls through to ENOTTY. This check only proves the
    // number and the struct agree with EACH OTHER: SETPLANE passed it for months
    // with both wrong (48-byte struct widened to 64 to match a 0x40 number).
    // `ioctl_numbers_encode_their_linux_struct_size` is the one that anchors
    // them to Linux.
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
    assert_eq!(ioc_size(DRM_IOCTL_MODE_LIST_LESSEES),     size_of::<DrmModeListLessees>() as u64);
    assert_eq!(DRM_IOCTL_MODE_LIST_LESSEES & 0xff, 0xc7);
}

#[test]
fn new_kms_struct_sizes() {
    use core::mem::size_of;
    assert_eq!(size_of::<DrmModeSetPlane>(),             48);
    assert_eq!(size_of::<DrmModeFbDirtyCmd>(),           24);
    assert_eq!(size_of::<DrmModeObjSetProperty>(),       24);
    assert_eq!(size_of::<DrmModeConnectorSetProperty>(), 16);
    assert_eq!(size_of::<DrmModeCrtcLut>(),              32);
    assert_eq!(size_of::<DrmModeCursor>(),               28);
    assert_eq!(size_of::<DrmModeCursor2>(),              36);
    assert_eq!(size_of::<DrmModeFbCmd>(),                28);
    assert_eq!(size_of::<DrmModeListLessees>(),           16);
}

// ---------------------------------------------------------------------------
// ioctl request-number encoding.
//
// A DRM request number embeds sizeof(struct) in bits 16..30. Deriving one from
// the wrong struct size does not fail loudly: the dispatch `match` in `node.rs`
// compares the whole u64, so a wrong size means userspace's request number
// never matches and the ioctl falls through to ENOTTY. That is how both
// MODE_ATOMIC (56 mis-encoded as 64) and MODE_SETPLANE (48 mis-encoded as 64)
// became silently unreachable.
// ---------------------------------------------------------------------------

const IOC_WRITE: u64 = 1;
const IOC_READ: u64 = 2;
const IOC_RW: u64 = 3;
/// `_IOC(dir, 'd', nr, size)` — DRM's ioctl type byte is 'd' (0x64).
const fn ioc(dir: u64, nr: u64, size: u64) -> u64 { (dir << 30) | (size << 16) | (0x64 << 8) | nr }

/// Sizes match the Linux DRM/KMS UAPI's core and modesetting struct layouts.
#[test]
fn ioctl_numbers_encode_their_linux_struct_size() {
    assert_eq!(DRM_IOCTL_MODE_ATOMIC,            ioc(IOC_RW, 0xBC, 56), "drm_mode_atomic");
    assert_eq!(DRM_IOCTL_MODE_SETPLANE,          ioc(IOC_RW, 0xB7, 48), "drm_mode_set_plane");
    assert_eq!(DRM_IOCTL_MODE_OBJ_GETPROPERTIES, ioc(IOC_RW, 0xB9, 32), "drm_mode_obj_get_properties");
    assert_eq!(DRM_IOCTL_MODE_GETPROPERTY,       ioc(IOC_RW, 0xAA, 64), "drm_mode_get_property");
    assert_eq!(DRM_IOCTL_MODE_GETCONNECTOR,      ioc(IOC_RW, 0xA7, 80), "drm_mode_get_connector");
    assert_eq!(DRM_IOCTL_MODE_GETRESOURCES,      ioc(IOC_RW, 0xA0, 64), "drm_mode_card_res");
    assert_eq!(DRM_IOCTL_MODE_GETPLANE,          ioc(IOC_RW, 0xB6, 32), "drm_mode_get_plane");
    assert_eq!(DRM_IOCTL_MODE_GETPLANERESOURCES, ioc(IOC_RW, 0xB5, 16), "drm_mode_get_plane_res");
    assert_eq!(DRM_IOCTL_MODE_CREATEPROPBLOB,    ioc(IOC_RW, 0xBD, 16), "drm_mode_create_blob");
    assert_eq!(DRM_IOCTL_MODE_DESTROYPROPBLOB,   ioc(IOC_RW, 0xBE, 4),  "drm_mode_destroy_blob");
    assert_eq!(DRM_IOCTL_MODE_GETPROPBLOB,       ioc(IOC_RW, 0xAC, 16), "drm_mode_get_blob");
    assert_eq!(DRM_IOCTL_SET_CLIENT_CAP,         ioc(IOC_WRITE, 0x0d, 16), "drm_set_client_cap");
    assert_eq!(DRM_IOCTL_GET_CLIENT,             ioc(IOC_RW, 0x05, 40), "drm_client");
    assert_eq!(DRM_IOCTL_GET_STATS,              ioc(IOC_READ, 0x06, 248), "drm_stats");
    assert_eq!(DRM_IOCTL_MODE_ATTACHMODE,        ioc(IOC_RW, 0xA8, 72), "drm_mode_mode_cmd");
    assert_eq!(DRM_IOCTL_MODE_DETACHMODE,        ioc(IOC_RW, 0xA9, 72), "drm_mode_mode_cmd");
    assert_eq!(DRM_IOCTL_SYNCOBJ_WAIT,           ioc(IOC_RW, 0xC3, 40), "drm_syncobj_wait");
    assert_eq!(DRM_IOCTL_SYNCOBJ_RESET,          ioc(IOC_RW, 0xC4, 16), "drm_syncobj_array");
    assert_eq!(DRM_IOCTL_SYNCOBJ_SIGNAL,         ioc(IOC_RW, 0xC5, 16), "drm_syncobj_array");
    assert_eq!(DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT,  ioc(IOC_RW, 0xCA, 48), "drm_syncobj_timeline_wait");
    assert_eq!(DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD,   ioc(IOC_RW, 0xC1, 24), "drm_syncobj_handle");
    assert_eq!(DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE,   ioc(IOC_RW, 0xC2, 24), "drm_syncobj_handle");
    assert_eq!(DRM_IOCTL_MODE_LIST_LESSEES,       ioc(IOC_RW, 0xC7, 16), "drm_mode_list_lessees");
}

/// Each wire struct must be exactly the size its own request number claims.
/// This is the check that would have caught `DrmModeSetPlane` widening its
/// `src_*` fields to u64 while its request number stayed at the 48-byte value.
#[test]
fn wire_structs_are_the_size_their_ioctl_number_claims() {
    use core::mem::size_of;
    assert_eq!(size_of::<DrmModeSetPlane>(),     ioc_size(DRM_IOCTL_MODE_SETPLANE) as usize);
    assert_eq!(size_of::<DrmModeCardRes>(),      ioc_size(DRM_IOCTL_MODE_GETRESOURCES) as usize);
    assert_eq!(size_of::<DrmModeGetConnector>(), ioc_size(DRM_IOCTL_MODE_GETCONNECTOR) as usize);
    assert_eq!(size_of::<DrmModeGetPlane>(),     ioc_size(DRM_IOCTL_MODE_GETPLANE) as usize);
    assert_eq!(size_of::<DrmModeGetPlaneRes>(),  ioc_size(DRM_IOCTL_MODE_GETPLANERESOURCES) as usize);
    assert_eq!(size_of::<DrmModeGetEncoder>(),   ioc_size(DRM_IOCTL_MODE_GETENCODER) as usize);
    assert_eq!(size_of::<DrmModeCrtc>(),         ioc_size(DRM_IOCTL_MODE_GETCRTC) as usize);
    assert_eq!(size_of::<DrmModeCreateBlob>(),   ioc_size(DRM_IOCTL_MODE_CREATEPROPBLOB) as usize);
    assert_eq!(size_of::<DrmModeDestroyBlob>(),  ioc_size(DRM_IOCTL_MODE_DESTROYPROPBLOB) as usize);
}

/// Field OFFSETS, not just sizes. Transposing fields inside a struct leaves
/// `size_of` unchanged, so both the ioctl-number check and the struct-size
/// check keep passing while every field is read from the wrong place —
/// `drm_mode_create_blob` shipped as (length, blob_id, data) instead of
/// (data, length, blob_id), which made `length` the low half of the caller's
/// data pointer and failed every CREATEPROPBLOB with EINVAL.
/// Offsets match the Linux DRM/KMS UAPI's modesetting struct layout.
#[test]
fn wire_struct_field_offsets_match_linux() {
    use core::mem::offset_of;
    assert_eq!(offset_of!(DrmModeCreateBlob, data),    0);
    assert_eq!(offset_of!(DrmModeCreateBlob, length),  8);
    assert_eq!(offset_of!(DrmModeCreateBlob, blob_id), 12);

    // drm_mode_set_plane declares the source rect x, y, **h, w**.
    assert_eq!(offset_of!(DrmModeSetPlane, crtc_x), 16);
    assert_eq!(offset_of!(DrmModeSetPlane, crtc_w), 24);
    assert_eq!(offset_of!(DrmModeSetPlane, src_x),  32);
    assert_eq!(offset_of!(DrmModeSetPlane, src_y),  36);
    assert_eq!(offset_of!(DrmModeSetPlane, src_h),  40);
    assert_eq!(offset_of!(DrmModeSetPlane, src_w),  44);

    // The property tail of drm_mode_get_connector; get_connector writes these.
    assert_eq!(offset_of!(DrmModeGetConnector, props_ptr),       16);
    assert_eq!(offset_of!(DrmModeGetConnector, prop_values_ptr), 24);
    assert_eq!(offset_of!(DrmModeGetConnector, count_modes),     32);
    assert_eq!(offset_of!(DrmModeGetConnector, count_props),     36);
    assert_eq!(offset_of!(DrmModeGetConnector, count_encoders),  40);
}

/// A DIRTYFB probe carrying an id that resolves to no framebuffer is answered
/// ENOENT, never EINVAL. Xorg's modesetting driver issues exactly this probe
/// before it owns a framebuffer, and reads EINVAL as "this driver does not
/// refresh on demand": it then stops calling DIRTYFB for the life of the
/// session, its shadow buffer is never pushed, and the desktop runs on a black
/// screen with every other part of the stack reporting success.
#[test]
fn a_dirtyfb_probe_for_an_unknown_framebuffer_is_enoent() {
    let probe = DrmModeFbDirtyCmd { fb_id: 0, ..Default::default() };
    assert_eq!(crate::kms_ext::dirty_verdict(&probe, false, 0),
               crate::kms_ext::DirtyVerdict::NoFramebuffer);
    // Still ENOENT when a framebuffer is on screen — the id, not the scanout,
    // decides this leg.
    assert_eq!(crate::kms_ext::dirty_verdict(&probe, false, 2),
               crate::kms_ext::DirtyVerdict::NoFramebuffer);
}

/// The lookup outranks the request's own validity: an unknown id reports the
/// missing framebuffer even when the clip fields contradict each other.
#[test]
fn the_framebuffer_lookup_is_decided_before_the_clip_fields() {
    let contradictory = DrmModeFbDirtyCmd { fb_id: 7, num_clips: 4, clips_ptr: 0, ..Default::default() };
    assert_eq!(crate::kms_ext::dirty_verdict(&contradictory, false, 7),
               crate::kms_ext::DirtyVerdict::NoFramebuffer);
    assert_eq!(crate::kms_ext::dirty_verdict(&contradictory, true, 7),
               crate::kms_ext::DirtyVerdict::Malformed);
}

/// Clip count and clip pointer are supplied together or not at all; a copy
/// annotation names source/destination pairs, so its clips come in twos; and
/// the clip walk has a ceiling.
#[test]
fn a_contradictory_dirtyfb_request_is_einval() {
    let base = DrmModeFbDirtyCmd { fb_id: 2, ..Default::default() };
    let cases = [
        DrmModeFbDirtyCmd { num_clips: 1, clips_ptr: 0, ..base },
        DrmModeFbDirtyCmd { num_clips: 0, clips_ptr: 0x4000, ..base },
        DrmModeFbDirtyCmd { flags: DRM_MODE_FB_DIRTY_ANNOTATE_COPY, num_clips: 3, clips_ptr: 0x4000, ..base },
        DrmModeFbDirtyCmd { num_clips: crate::damage::MAX_DAMAGE_CLIPS + 1, clips_ptr: 0x4000, ..base },
    ];
    for c in cases {
        assert_eq!(crate::kms_ext::dirty_verdict(&c, true, 2),
                   crate::kms_ext::DirtyVerdict::Malformed, "{c:?}");
    }
    // A whole-surface refresh carries no clips at all, and is not malformed.
    assert_eq!(crate::kms_ext::dirty_verdict(&base, true, 2), crate::kms_ext::DirtyVerdict::Refresh);
    // An even pair count under a copy annotation is accepted.
    let pairs = DrmModeFbDirtyCmd { flags: DRM_MODE_FB_DIRTY_ANNOTATE_COPY, num_clips: 4, clips_ptr: 0x4000, ..base };
    assert_eq!(crate::kms_ext::dirty_verdict(&pairs, true, 2), crate::kms_ext::DirtyVerdict::Refresh);
}

/// A framebuffer that exists but is not the one on screen has nothing to
/// refresh: that is a success, not an error, and it is not a scanout push.
#[test]
fn dirtyfb_on_a_framebuffer_that_is_not_on_screen_succeeds_without_a_push() {
    let d = DrmModeFbDirtyCmd { fb_id: 3, ..Default::default() };
    assert_eq!(crate::kms_ext::dirty_verdict(&d, true, 2), crate::kms_ext::DirtyVerdict::NotOnScreen);
    assert_eq!(crate::kms_ext::dirty_verdict(&d, true, 3), crate::kms_ext::DirtyVerdict::Refresh);
}

/// The cursor size is a CORE answer, not a per-driver one. Every device reports
/// 64x64 unless it names a size of its own — devices with no cursor plane
/// included, because a display server sizes its cursor buffer object from these
/// two numbers before it can discover whether the cursor ioctls work. This
/// lived in two drivers and was missing from the third, so the one firmware
/// framebuffer answered zero and a client asking it for a cursor was told to
/// allocate a 0x0 buffer.
#[test]
fn every_device_reports_a_usable_cursor_size() {
    for cap in [DRM_CAP_CURSOR_WIDTH, DRM_CAP_CURSOR_HEIGHT] {
        assert_eq!(default_cap(cap), 64);
        // The advertising filter must not zero it back out on the way to the
        // caller: this cap is reported, not suppressed.
        assert_eq!(advertised_cap(cap, default_cap(cap)), 64);
    }
}

/// A preferred depth counts colour bits, not the pixel's size. XRGB8888 is 32
/// bits per pixel carrying a depth of 24 — its fourth byte is padding.
#[test]
fn a_preferred_depth_is_colour_bits_not_pixel_bits() {
    assert_eq!(format_depth(DRM_FORMAT_XRGB8888), 24);
    assert_eq!(format_depth(DRM_FORMAT_ARGB8888), 32);
    // A format nothing scans out has no depth to prefer.
    assert_eq!(format_depth(0), 0);
    assert_eq!(format_depth(0x3631_5044), 0); // 'DP16', a format this stack does not scan out
}

#[test]
fn display_density_uses_physical_geometry_and_default_for_missing_size() {
    assert_eq!(dpi_from_geometry(1920, 1080, 508, 285), 96);
    assert_eq!(dpi_from_geometry(0, 1080, 508, 286), DEFAULT_SCREEN_DPI);
    assert_eq!(dpi_from_geometry(1920, 1080, 0, 286), DEFAULT_SCREEN_DPI);
}
