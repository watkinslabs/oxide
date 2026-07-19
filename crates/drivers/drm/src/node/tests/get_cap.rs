use super::*;

struct OverreportDrv;

impl crate::DrmDriver for OverreportDrv {
    fn name(&self) -> &'static str { "overreport" }
    fn version(&self) -> (u32, u32, u32) { (1, 0, 0) }
    fn date(&self) -> &'static str { "20260509" }
    fn desc(&self) -> &'static str { "overreport caps" }
    fn unique(&self) -> &str { "pci:0000:00:02.0" }
    fn resource_counts(&self) -> (u32, u32, u32, u32) { (0, 1, 1, 1) }
    fn dim_bounds(&self) -> (u32, u32, u32, u32) { (1, 8192, 1, 8192) }
    fn cap(&self, cap: u64) -> u64 {
        match cap {
            crate::DRM_CAP_DUMB_BUFFER => crate::default_cap(cap),
            _ => u64::MAX,
        }
    }
}

#[test]
fn drm_get_cap_clamps_unsupported_driver_advertisements() {
    let _guard = crate::TEST_LOCK.lock();
    crate::registry::clear_cards_for_tests();
    unregister_all();
    let card_id = crate::register(Arc::new(OverreportDrv));
    let card = open_file(make_card_inode(card_id));
    let unsupported = [
        crate::DRM_CAP_PRIME,
        crate::DRM_CAP_ASYNC_PAGE_FLIP,
        crate::DRM_CAP_ADDFB2_MODIFIERS,
        crate::DRM_CAP_PAGE_FLIP_TARGET,
        crate::DRM_CAP_VBLANK_HIGH_CRTC,
        crate::DRM_CAP_CRTC_IN_VBLANK_EVENT,
        crate::DRM_CAP_SYNCOBJ,
        crate::DRM_CAP_SYNCOBJ_TIMELINE,
    ];

    for capability in unsupported {
        let mut req = [capability, u64::MAX];
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_GET_CAP, req.as_mut_ptr() as u64), Some(0));
        assert_eq!(req[1], 0);
    }

    let mut supported = [crate::DRM_CAP_DUMB_BUFFER, 0];
    assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_GET_CAP, supported.as_mut_ptr() as u64), Some(0));
    assert_eq!(supported[1], 1);
    assert!(crate::unregister(card_id));
    unregister_all();
}
