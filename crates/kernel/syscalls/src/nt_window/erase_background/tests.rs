use super::*;

#[test]
fn only_the_two_erase_messages_are_intercepted() {
    assert!(is_erase_message(WM_ERASEBKGND));
    assert!(is_erase_message(WM_ICONERASEBKGND));
    assert!(!is_erase_message(0x000f));
    assert!(!is_erase_message(0x0133));
}

#[test]
fn a_zero_background_does_not_erase() {
    assert_eq!(brush_for(0, |_| panic!("no system lookup for a null brush")), None);
}

#[test]
fn small_values_name_a_system_colour_plus_one() {
    // COLOR_WINDOW + 1, the value Notepad registers.
    assert_eq!(brush_for(6, |index| { assert_eq!(index, 5); Some(0x77) }), Some(0x77));
    assert_eq!(brush_for(COLOR_MENUBAR + 1, |index| { assert_eq!(index, COLOR_MENUBAR as u32); Some(9) }), Some(9));
    assert_eq!(brush_for(3, |_| None), None);
}

#[test]
fn larger_values_are_the_brush_handle() {
    assert_eq!(brush_for(COLOR_MENUBAR + 2, |_| panic!("a handle is not a colour index")), Some(32));
    assert_eq!(brush_for(0x0501_0042, |_| panic!()), Some(0x0501_0042));
    assert_eq!(brush_for(1 << 40, |_| panic!()), None);
}

#[test]
fn parent_dc_classes_fill_their_client_rectangle() {
    assert!(fills_client_rect(CS_PARENTDC));
    assert!(fills_client_rect(CS_PARENTDC | 0x3));
    assert!(!fills_client_rect(0x3));
}
