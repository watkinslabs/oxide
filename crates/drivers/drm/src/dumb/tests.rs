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
    let sz = core::mem::size_of::<DrmModeFbCmd2>();
    assert_eq!(sz, 104);
    assert_eq!(core::mem::offset_of!(DrmModeFbCmd2, handles), 20);
    assert_eq!(core::mem::offset_of!(DrmModeFbCmd2, modifier), 72);
}

#[test]
fn fb_cmd_layout() { assert_eq!(core::mem::size_of::<DrmModeFbCmd>(), 28); }

#[test]
fn pitch_align_64() {
    assert_eq!(dumb_pitch(640, 32), Some(2560));
    assert_eq!(dumb_pitch(100, 32), Some(448));
    assert_eq!(dumb_pitch(640, 16), Some(1280));
    assert_eq!(dumb_pitch(640, 0), None);
    assert_eq!(dumb_pitch(640, 12), None);
    assert_eq!(dumb_pitch(640, 33), None);
}

#[test]
fn size_align_4096() {
    assert_eq!(dumb_size(2560, 480), Some(1228800));
    assert_eq!(dumb_size(448, 100), Some(45056));
}

#[test]
fn order_math() {
    assert_eq!(order_for_bytes(0), 0);
    assert_eq!(order_for_bytes(4096), 0);
    assert_eq!(order_for_bytes(4097), 1);
    assert_eq!(order_for_bytes(8192), 1);
    assert_eq!(order_for_bytes(8193), 2);
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
    let buf = DumbBuf {
        card_id: 0,
        handle: 1,
        pa: 0x10_0000,
        size: 4096,
        order: 0,
        w: 16,
        h: 16,
        pitch: 64,
        bpp: 32,
        refcnt: 1,
        mmap_refs: 0,
        deleted: false,
    };

    assert!(fb_plane_fits_buf(16, 16, DRM_FORMAT_XRGB8888, 64, 0, &buf));
    assert!(fb_plane_fits_buf(8, 8, DRM_FORMAT_XRGB8888, 64, 128, &buf));
    assert!(!fb_plane_fits_buf(16, 16, DRM_FORMAT_XRGB8888, 63, 0, &buf));
    assert!(!fb_plane_fits_buf(16, 16, DRM_FORMAT_XRGB8888, 64, 4090, &buf));
    assert!(!fb_plane_fits_buf(u32::MAX, 2, DRM_FORMAT_XRGB8888, u32::MAX, 0, &buf));
}

#[test]
fn cookie_round_trip() {
    let c = cookie_for(1);
    assert_eq!(c, DRM_MMAP_COOKIE_BASE | (1 << super::math::DRM_MMAP_COOKIE_HANDLE_SHIFT));
    assert_eq!(handle_of_cookie(c), Some(1));
    let c7 = cookie_for(7);
    assert_eq!(handle_of_cookie(c7), Some(7));
    let high = 1 << 20;
    assert_eq!(handle_of_cookie(cookie_for(high)), Some(high));
    assert_eq!(handle_of_cookie(cookie_for(u32::MAX)), Some(u32::MAX));
    assert_eq!(handle_of_cookie(0), None);
    assert_eq!(handle_of_cookie(DRM_MMAP_COOKIE_BASE), None);
    assert_eq!(handle_of_cookie(cookie_for(1) | 1), None);
    assert_eq!(handle_of_cookie(cookie_for(1) | (1u64 << 47)), None);
}

#[test]
fn table_insert_lookup_ref_unref() {
    let mut t = DumbTables::new();
    t.insert_buf(DumbBuf {
        card_id: 0,
        handle: 1,
        pa: 0x10_0000,
        size: 4096,
        order: 0,
        w: 4,
        h: 4,
        pitch: 16,
        bpp: 32,
        refcnt: 1,
        mmap_refs: 0,
        deleted: false,
    });
    assert!(t.find_buf(0, 1).is_some());
    assert!(t.find_buf(1, 1).is_none());
    assert!(t.find_buf(0, 2).is_none());
    assert!(t.ref_handle(0, 1));
    assert_eq!(t.find_buf(0, 1).unwrap().refcnt, 2);
    assert!(!t.ref_handle(0, 99));
    assert_eq!(t.unref_handle(0, 1), None);
    assert_eq!(t.find_buf(0, 1).unwrap().refcnt, 1);
    assert_eq!(t.unref_handle(0, 1), Some((0x10_0000, 0)));
    assert!(t.find_buf(0, 1).is_none());
    assert_eq!(t.unref_handle(0, 1), None);
}

#[test]
fn fb_table_insert_lookup() {
    let mut t = DumbTables::new();
    t.fbs.push(FbObj {
        card_id: 0,
        fb_id: 1,
        w: 640,
        h: 480,
        pixel_format: DRM_FORMAT_XRGB8888,
        handles: [3, 0, 0, 0],
        pitches: [2560, 0, 0, 0],
        offsets: [0; 4],
        scanout_res_id: 0,
    });
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
    t.insert_buf(DumbBuf {
        card_id: 0,
        handle: 1,
        pa: 0x10_0000,
        size: 4096,
        order: 0,
        w: 4,
        h: 4,
        pitch: 16,
        bpp: 32,
        refcnt: 1,
        mmap_refs: 0,
        deleted: false,
    });
    t.insert_buf(DumbBuf {
        card_id: 1,
        handle: 1,
        pa: 0x20_0000,
        size: 4096,
        order: 0,
        w: 4,
        h: 4,
        pitch: 16,
        bpp: 32,
        refcnt: 1,
        mmap_refs: 0,
        deleted: false,
    });
    t.fbs.push(FbObj {
        card_id: 0,
        fb_id: 7,
        w: 4,
        h: 4,
        pixel_format: DRM_FORMAT_XRGB8888,
        handles: [1, 0, 0, 0],
        pitches: [16, 0, 0, 0],
        offsets: [0; 4],
        scanout_res_id: 0,
    });
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
    t.insert_buf(DumbBuf {
        card_id: 0,
        handle: 1,
        pa: 0x10_0000,
        size: 4096,
        order: 0,
        w: 4,
        h: 4,
        pitch: 16,
        bpp: 32,
        refcnt: 2,
        mmap_refs: 0,
        deleted: false,
    });
    t.fbs.push(FbObj {
        card_id: 0,
        fb_id: 7,
        w: 4,
        h: 4,
        pixel_format: DRM_FORMAT_XRGB8888,
        handles: [1, 0, 0, 0],
        pitches: [16, 0, 0, 0],
        offsets: [0; 4],
        scanout_res_id: 42,
    });

    assert_eq!(t.remove_card(0), (alloc::vec![(0x10_0000, 0)], alloc::vec![42]));
    assert!(t.find_fb(0, 7).is_none());
    assert!(t.find_buf(0, 1).is_none());
}

#[test]
fn mmap_pin_survives_card_remove_until_unpin() {
    let mut t = DumbTables::new();
    t.insert_buf(DumbBuf {
        card_id: 0,
        handle: 1,
        pa: 0x10_0000,
        size: 4096,
        order: 0,
        w: 4,
        h: 4,
        pitch: 16,
        bpp: 32,
        refcnt: 1,
        mmap_refs: 0,
        deleted: false,
    });
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
