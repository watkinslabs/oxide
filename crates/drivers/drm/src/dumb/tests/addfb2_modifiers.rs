use super::*;

#[test]
fn addfb2_rejects_nonzero_modifier_even_without_modifier_flag() {
    use syscall::errno::Errno;

    let mut req = DrmModeFbCmd2 {
        width: 4,
        height: 4,
        pixel_format: DRM_FORMAT_XRGB8888,
        flags: 0,
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
    assert_eq!(req.fb_id, 0);
}
