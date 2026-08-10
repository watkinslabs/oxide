use super::*;

fn einval() -> i64 {
    use syscall::errno::Errno;
    -(Errno::Einval.as_i32() as i64)
}

#[test]
fn addfb2_rejects_unused_plane_offset_for_packed_rgb() {
    let _tables = super::global_tables_claim();
    reset_global_tables();
    insert_global_buf(4096);

    let mut req = DrmModeFbCmd2 {
        width: 16,
        height: 16,
        pixel_format: DRM_FORMAT_XRGB8888,
        handles: [1, 0, 0, 0],
        pitches: [64, 0, 0, 0],
        offsets: [0, 4, 0, 0],
        ..Default::default()
    };

    assert_eq!(addfb2(0, (&mut req as *mut DrmModeFbCmd2) as u64), einval());
    assert!(TABLES.lock().fbs.is_empty());
    reset_global_tables();
}

#[test]
fn legacy_addfb_rejects_framebuffer_larger_than_backing_buffer() {
    let _tables = super::global_tables_claim();
    reset_global_tables();
    insert_global_buf(4096);

    let mut req = DrmModeFbCmd {
        width: 16,
        height: 65,
        pitch: 64,
        bpp: 32,
        depth: 24,
        handle: 1,
        ..Default::default()
    };

    assert_eq!(addfb(0, (&mut req as *mut DrmModeFbCmd) as u64), einval());
    {
        let t = TABLES.lock();
        assert!(t.fbs.is_empty());
        assert_eq!(t.find_buf(0, 1).unwrap().refcnt, 1);
    }
    reset_global_tables();
}
