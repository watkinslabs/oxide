use super::*;

#[test]
fn clear_card_state_releases_bound_scanout_resource() {
    let _guard = crate::TEST_LOCK.lock();
    reset_global_tables();
    crate::node::clear_scanout_ops(3);
    DESTROYED_DRIVER_KEY.store(0, Ordering::Release);
    DESTROYED_RES_ID.store(0, Ordering::Release);
    crate::node::set_scanout_ops(3, crate::node::ScanoutOps {
        driver_key: scanout_key(0x3003), create_from_pa: test_create, destroy_resource: record_destroy,
        present: test_present, set_cursor: test_set_cursor, move_cursor: test_move_cursor,
        restore_console: test_restore, boot_res_id: test_boot,
    });
    TABLES.lock().fbs.push(FbObj {
        card_id: 3, fb_id: 9, owner_token: 0, bound: false, w: 4, h: 4, pixel_format: DRM_FORMAT_XRGB8888,
        handles: [0; 4], pitches: [16, 0, 0, 0], offsets: [0; 4], scanout_res_id: 77,
    });
    clear_card_state(3);
    assert_eq!(DESTROYED_DRIVER_KEY.load(Ordering::Acquire), 0x3003);
    assert_eq!(DESTROYED_RES_ID.load(Ordering::Acquire), 77);
    assert!(TABLES.lock().find_fb(3, 9).is_none());
    crate::node::clear_scanout_ops(3);
    reset_global_tables();
}

#[test]
fn mmap_pin_survives_card_remove_until_unpin() {
    let mut t = DumbTables::new();
    t.insert_buf(DumbBuf { card_id: 0, handle: 1, owner_token: 0, pa: 0x10_0000, size: 4096,
        order: 0, w: 4, h: 4, pitch: 16, bpp: 32, refcnt: 1, mmap_refs: 0, deleted: false });
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

#[test]
fn closefb_defers_retirement_until_scanout_replaces_it() {
    let mut t = DumbTables::new();
    t.insert_buf(DumbBuf { card_id: 0, handle: 7, owner_token: 11, pa: 0x10_0000, size: 4096,
        order: 0, w: 4, h: 4, pitch: 16, bpp: 32, refcnt: 2, mmap_refs: 0, deleted: false });
    t.fbs.push(FbObj { card_id: 0, fb_id: 9, owner_token: 11, bound: true, w: 4, h: 4,
        pixel_format: DRM_FORMAT_XRGB8888, handles: [7, 0, 0, 0], pitches: [16, 0, 0, 0],
        offsets: [0; 4], scanout_res_id: 42 });
    assert_eq!(t.close_fb(0, 11, 9), Ok(None));
    assert!(t.find_fb(0, 9).is_some());
    assert_eq!(t.replace_bound_fb(0, 9, 0), Some(([None, None, None, None], 42)));
    assert!(t.find_fb(0, 9).is_none());
}
