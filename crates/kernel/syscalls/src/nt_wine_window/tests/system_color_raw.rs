use super::*;
use ipc::win32_gdi::GdiManager;

#[test]
fn status_face_color_converts_once_and_never_allocates_a_brush() {
    assert_eq!(route::<()>(0x133d, &[15, 6], |_| panic!("color allocated brush")), Some(0x00c8d0d4));
    assert_eq!(route::<()>(0x133d, &[0xdeadbeef0000000f, 0x1234567800000006], |_| panic!("color allocated brush")), Some(0x00c8d0d4));
    assert_eq!(route::<()>(0x133d, &[8, 6], |_| panic!("color allocated brush")), Some(0));
}

#[test]
fn status_background_uses_protected_canonical_brush_and_real_pixels() {
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(20, 10).unwrap();
    let brush = route(0x133d, &[15, 7], |role| owner.system_brush(role)).unwrap() as u32;
    assert!(owner.contains_object(brush));
    owner.select_brush(dc, brush).unwrap();
    owner.pat_blt(dc, 0, 0, 20, 10, 0x00f00021).unwrap();
    assert!(owner.surface(dc).unwrap().2.iter().all(|p| *p == SystemColor::Face.color()));
    owner.delete_object(brush).unwrap();
    assert!(owner.contains_object(brush));
    assert_eq!(route(0x133d, &[15, 7], |role| owner.system_brush(role)), Some(brush as u64));
    let position = owner.text_state(dc).unwrap().attributes.current_position;
    assert_eq!(position, (0, 0));
}

#[test]
fn invalid_index_and_failed_publication_return_null_not_ntstatus() {
    assert_eq!(route::<()>(0x133d, &[u64::MAX, 7], |_| panic!("invalid role")), Some(0));
    assert_eq!(route(0x133d, &[15, 7], |_| Err(0xc000000du64)), Some(0));
    for (ordinal, selector) in [(0x133c, 7), (0x133d, 8), (0x133d, 9), (0x4e5400000000133d, 7)] {
        assert_eq!(route::<()>(ordinal, &[15, selector], |_| panic!("unclaimed brush")), None);
    }
    assert_eq!(route::<()>(0x133d, &[], |_| panic!("short brush")), None);
}
