//! Caption colour selection per drawing flag.
use super::*;

#[test]
fn a_caption_inside_a_button_takes_the_dialog_face_and_button_text() {
    assert_eq!(background_color(DC_INBUTTON), SystemColor::Face);
    assert_eq!(background_color(DC_INBUTTON | DC_ACTIVE), SystemColor::Face);
    assert_eq!(text_color(DC_INBUTTON), SystemColor::ButtonText);
    assert_eq!(text_color(DC_INBUTTON | DC_ACTIVE), SystemColor::ButtonText);
}

#[test]
fn an_ordinary_caption_follows_its_active_state() {
    assert_eq!(background_color(DC_ACTIVE), SystemColor::ActiveCaption);
    assert_eq!(background_color(0), SystemColor::InactiveCaption);
    assert_eq!(text_color(DC_ACTIVE), SystemColor::CaptionText);
    assert_eq!(text_color(0), SystemColor::InactiveCaptionText);
}

#[test]
fn unrelated_flags_do_not_change_the_colours() {
    for extra in [DC_SMALLCAP, DC_ICON, DC_GRADIENT, DC_BUTTONS, DC_TEXT] {
        assert_eq!(background_color(DC_ACTIVE | extra), SystemColor::ActiveCaption);
        assert_eq!(text_color(DC_ACTIVE | extra), SystemColor::CaptionText);
    }
}

#[test]
fn only_a_text_request_draws_text() {
    assert!(draws_text(DC_TEXT));
    assert!(draws_text(DC_TEXT | DC_ACTIVE));
    assert!(!draws_text(DC_ACTIVE | DC_ICON));
}
