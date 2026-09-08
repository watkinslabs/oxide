use super::*;
use table::slot;

/// A slot constant that names a different entry than its comment claims writes
/// every struct-shaped action into the wrong setting, and nothing else here
/// would notice.
#[test]
fn named_slots_are_the_entries_their_actions_name() {
    assert_eq!(slot_of_get(action::GET_BORDER), Some(slot::BORDER));
    assert_eq!(slot_of_get(action::GET_ICON_TITLE_WRAP), Some(slot::ICON_TITLE_WRAP));
    assert_eq!(slot_of_get(action::GET_WHEEL_SCROLL_LINES), slot_of_set(action::SET_WHEEL_SCROLL_LINES));
    assert_eq!(ENTRIES[slot::MENU_HEIGHT].kind, Kind::Twips);
    assert_eq!(ENTRIES[slot::MIN_ARRANGE].kind, Kind::Word);
}

/// Two entries sharing one action number make the second unreachable.
#[test]
fn no_action_number_names_two_entries() {
    for (index, entry) in ENTRIES.iter().enumerate() {
        for (other, candidate) in ENTRIES.iter().enumerate() {
            if index == other { continue; }
            assert!(entry.get == NO_ACTION || entry.get != candidate.get, "duplicate getter {}", entry.get);
            assert!(entry.set == NO_ACTION || entry.set != candidate.set, "duplicate setter {}", entry.set);
        }
    }
}

/// The twips quoting is what turns the stored profile numbers into the pixel
/// dimensions every nonclient measurement uses.
#[test]
fn twips_entries_resolve_to_the_profile_pixel_dimensions() {
    let store = SystemParameters::new();
    assert_eq!(store.pixels(slot::BORDER, 96), 1);
    assert_eq!(store.pixels(slot::SCROLL_WIDTH, 96), 16);
    assert_eq!(store.pixels(slot::CAPTION_HEIGHT, 96), 18);
    assert_eq!(store.pixels(slot::SM_CAPTION_HEIGHT, 96), 15);
    assert_eq!(store.pixels(slot::MENU_HEIGHT, 96), 18);
    // Twice the resolution is twice the dimension.
    assert_eq!(store.pixels(slot::CAPTION_HEIGHT, 192), 36);
}

/// The graphics owner's profile constants and this table are one value, so a
/// change to either cannot leave a caller reading a dimension the profile does
/// not draw.
#[test]
fn the_profile_dimensions_are_this_table() {
    assert_eq!(default_pixels(slot::MENU_HEIGHT), crate::win32_gdi::MENU_HEIGHT);
}

/// The actions the shipped window and dialog modules call must each name an
/// entry: an action with no entry is refused, and a refused action is what the
/// unadmitted-ordinal report was made of.
#[test]
fn every_action_the_shipped_modules_call_is_answered() {
    let store = SystemParameters::new();
    for action in [action::GET_ICON_TITLE_LOGFONT, action::GET_ICON_TITLE_WRAP,
        action::GET_WHEEL_SCROLL_LINES, action::GET_DESK_WALLPAPER, action::GET_FLAT_MENU,
        action::GET_GRADIENT_CAPTIONS, action::GET_NONCLIENT_METRICS, action::GET_KEYBOARD_CUES,
        action::GET_ICON_METRICS, action::GET_MINIMIZED_METRICS] {
        assert_ne!(store.read(action, 96, true), Request::Refused, "action {action:#x} refused");
    }
    for action in [action::SET_ICON_TITLE_LOGFONT, action::SET_GRADIENT_CAPTIONS,
        action::SET_FLAT_MENU, action::SET_DESK_WALLPAPER] {
        let mut store = SystemParameters::new();
        let font = [0; LOGFONTW_BYTES];
        let carried = StructWrite { words: &[], font: Some(&font) };
        assert_ne!(store.write(action, 1, Some(carried)), Request::Refused, "action {action:#x} refused");
    }
}

/// The values the shipped modules read out of the store before anything writes
/// one. A wrong default here is a wrong scroll step or a menu drawn flat.
#[test]
fn the_defaults_are_the_ones_the_reference_quotes() {
    let store = SystemParameters::new();
    assert_eq!(store.read(action::GET_WHEEL_SCROLL_LINES, 96, true), Request::Word(3));
    assert_eq!(store.read(action::GET_ICON_TITLE_WRAP, 96, true), Request::Word(1));
    assert_eq!(store.read(action::GET_GRADIENT_CAPTIONS, 96, true), Request::Word(1));
    assert_eq!(store.read(action::GET_KEYBOARD_CUES, 96, true), Request::Word(0));
    assert_eq!(store.read(action::GET_FLAT_MENU, 96, true), Request::Word(0));
    assert_eq!(store.read(action::GET_MENU_SHOW_DELAY, 96, true), Request::Word(400));
    assert_eq!(store.read(action::GET_CARET_WIDTH, 96, true), Request::Word(1));
    assert_eq!(store.read(action::GET_FAST_TASK_SWITCH, 96, true), Request::Word(1));
    assert_eq!(store.read(action::GET_BORDER, 96, true), Request::Word(1));
}

/// An unknown action is answered, not refused as an unadmitted call: the
/// reference answers FALSE and the ordinal stays claimed.
#[test]
fn an_unknown_action_is_refused_rather_than_answered_with_a_value() {
    let mut store = SystemParameters::new();
    assert_eq!(store.read(0xdead, 96, true), Request::Refused);
    assert_eq!(store.write(0xdead, 1, None), Request::Refused);
    assert_eq!(store.write(action::SET_FAST_TASK_SWITCH, 1, None), Request::Refused);
}

/// A write is what the next read answers; a store that drops the write leaves
/// every client on the default forever.
#[test]
fn a_write_is_what_the_next_read_answers() {
    let mut store = SystemParameters::new();
    assert_eq!(store.write(action::SET_WHEEL_SCROLL_LINES, 7, None), Request::Applied);
    assert_eq!(store.read(action::GET_WHEEL_SCROLL_LINES, 96, true), Request::Word(7));
    assert_eq!(store.write(action::SET_FLAT_MENU, 1, None), Request::Applied);
    assert_eq!(store.read(action::GET_FLAT_MENU, 96, true), Request::Word(1));
}

/// The spacing actions read when the call carries an output pointer and write
/// when it does not, and a write below the floor is raised to it.
#[test]
fn the_spacing_actions_read_with_a_pointer_and_write_without_one() {
    let mut store = SystemParameters::new();
    assert_eq!(store.read(action::ICON_HORIZONTAL_SPACING, 96, true), Request::Word(75));
    assert_eq!(store.read(action::ICON_HORIZONTAL_SPACING, 96, false), Request::Refused);
    assert_eq!(store.write(action::ICON_VERTICAL_SPACING, 8, None), Request::Applied);
    assert_eq!(store.read(action::ICON_VERTICAL_SPACING, 96, true), Request::Word(32));
}

/// The struct-shaped reads carry the words their records hold, in record order.
#[test]
fn the_struct_reads_carry_their_records_words() {
    let store = SystemParameters::new();
    assert_eq!(store.read(action::GET_MOUSE, 96, true), Request::Words(alloc::vec![6, 10, 1]));
    assert_eq!(store.read(action::GET_MINIMIZED_METRICS, 96, true), Request::Words(alloc::vec![154, 0, 0, 8]));
    assert_eq!(store.read(action::GET_ICON_METRICS, 96, true), Request::IconMetrics(alloc::vec![75, 75, 1]));
}

/// A nonclient write reaches the same record the next nonclient read builds:
/// the two must not be separate copies of the same dimensions.
#[test]
fn a_nonclient_write_is_in_the_profile_the_next_read_builds() {
    let mut store = SystemParameters::new();
    let words = [3, 20, 21, 30, 31, 12, 13, 40, 41];
    assert_eq!(store.write(action::SET_NONCLIENT_METRICS, 0, Some(StructWrite { words: &words, font: None })), Request::Applied);
    let profile = store.nonclient_profile(crate::win32_gdi::NONCLIENT_BYTES as u32, 96).unwrap();
    let word = |offset: usize| i32::from_le_bytes(profile[offset..offset + 4].try_into().unwrap());
    for (index, offset) in NONCLIENT_DIMENSION_OFFSETS.into_iter().enumerate() {
        assert_eq!(word(offset), words[index], "profile word {index}");
    }
    assert_eq!(store.read(action::GET_BORDER, 96, true), Request::Word(3));
}

/// A face a client writes is the face the profile carries afterwards.
#[test]
fn a_written_face_is_the_face_the_profile_carries() {
    let mut store = SystemParameters::new();
    let mut face = [0u8; LOGFONTW_BYTES];
    face[0] = 0x2a;
    store.set_nonclient_fonts(&[face]);
    let profile = store.nonclient_profile(crate::win32_gdi::NONCLIENT_BYTES as u32, 96).unwrap();
    assert_eq!(profile[NONCLIENT_FACE_OFFSETS[0]], 0x2a);
    assert_eq!(store.nonclient_font(0), Some(&face));
    assert_eq!(store.nonclient_font(1), None);
}

/// The wallpaper path a client writes is the path the next read answers.
#[test]
fn the_wallpaper_path_round_trips() {
    let mut store = SystemParameters::new();
    assert!(store.wallpaper().is_empty());
    assert!(store.set_wallpaper(&[b'a' as u16, b'b' as u16]));
    assert_eq!(store.wallpaper(), &[b'a' as u16, b'b' as u16]);
    assert_eq!(store.read(action::GET_DESK_WALLPAPER, 96, true), Request::Path);
    assert_eq!(store.write(action::SET_DESK_WALLPAPER, 0, None), Request::Path);
}
