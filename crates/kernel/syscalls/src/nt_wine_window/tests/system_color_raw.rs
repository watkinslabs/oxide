use super::*;
use ipc::win32_gdi::GdiManager;

/// The session colour table's answer for one role, defaulted.
fn value(role: SystemColor) -> u32 { role.color() }

#[test]
fn status_face_color_converts_once_and_never_allocates_an_object() {
    assert_eq!(route::<()>(0x133d, &[15, 6], value, |_| panic!("color allocated brush"), |_| panic!("color allocated pen")), Some(0x00c8d0d4));
    assert_eq!(route::<()>(0x133d, &[0xdeadbeef0000000f, 0x1234567800000006], value, |_| panic!("color allocated brush"), |_| panic!("color allocated pen")), Some(0x00c8d0d4));
    assert_eq!(route::<()>(0x133d, &[8, 6], value, |_| panic!("color allocated brush"), |_| panic!("color allocated pen")), Some(0));
}

#[test]
fn the_colour_query_reads_the_session_table_not_the_role_default() {
    // A role whose session value was replaced answers the replacement, so a
    // colour query and a brush query of the same role cannot disagree.
    assert_eq!(route::<()>(0x133d, &[15, 6], |_| 0x0011_2233, |_| panic!("brush"), |_| panic!("pen")), Some(0x0033_2211));
}

#[test]
fn status_background_uses_protected_canonical_brush_and_real_pixels() {
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(20, 10).unwrap();
    let brush = route(0x133d, &[15, 7], value, |role| owner.system_brush(role), |_| panic!("pen")).unwrap() as u32;
    assert!(owner.contains_object(brush));
    owner.select_brush(dc, brush).unwrap();
    owner.pat_blt(dc, 0, 0, 20, 10, 0x00f00021).unwrap();
    assert!(owner.surface(dc).unwrap().2.iter().all(|p| *p == SystemColor::Face.color()));
    owner.delete_object(brush).unwrap();
    assert!(owner.contains_object(brush));
    assert_eq!(route(0x133d, &[15, 7], value, |role| owner.system_brush(role), |_| panic!("pen")), Some(brush as u64));
    let position = owner.text_state(dc).unwrap().attributes.current_position;
    assert_eq!(position, (0, 0));
}

#[test]
fn the_pen_query_answers_a_protected_width_one_solid_pen_of_the_role() {
    let mut owner = GdiManager::new();
    let pen = route(0x133d, &[6, 8], value, |_| panic!("pen query allocated brush"), |role| owner.system_pen(role)).unwrap() as u32;
    assert_ne!(pen, 0);
    assert!(owner.is_system_pen(pen));
    let description = owner.pen_description(pen, 0).unwrap();
    assert_eq!((description.color, description.width), (SystemColor::WindowFrame.color(), 1));
    // The identity is cached and survives an application deletion.
    owner.delete_object(pen).unwrap();
    assert_eq!(route(0x133d, &[6, 8], value, |_| panic!("brush"), |role| owner.system_pen(role)), Some(pen as u64));
    // A pen and a brush of the same role are different objects.
    let brush = route(0x133d, &[6, 7], value, |role| owner.system_brush(role), |_| panic!("pen")).unwrap() as u32;
    assert_ne!(brush, pen);
}

#[test]
fn invalid_index_and_failed_publication_return_null_not_ntstatus() {
    assert_eq!(route::<()>(0x133d, &[u64::MAX, 7], value, |_| panic!("invalid role"), |_| panic!("pen")), Some(0));
    assert_eq!(route::<()>(0x133d, &[u64::MAX, 8], value, |_| panic!("brush"), |_| panic!("invalid role")), Some(0));
    assert_eq!(route(0x133d, &[15, 7], value, |_| Err(0xc000000du64), |_| panic!("pen")), Some(0));
    assert_eq!(route(0x133d, &[15, 8], value, |_| panic!("brush"), |_| Err(0xc000000du64)), Some(0));
    // Codes this family does not own, and any other ordinal, are declined so
    // the chain keeps walking rather than answering zero here.
    for (ordinal, selector) in [(0x133c, 7), (0x133d, 5), (0x133d, 9), (0x4e5400000000133d, 7)] {
        assert_eq!(route::<()>(ordinal, &[15, selector], value, |_| panic!("unclaimed brush"), |_| panic!("unclaimed pen")), None);
    }
    assert_eq!(route::<()>(0x133d, &[], value, |_| panic!("short brush"), |_| panic!("short pen")), None);
}
