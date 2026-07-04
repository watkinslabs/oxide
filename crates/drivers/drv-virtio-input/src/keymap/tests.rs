use crate::keymap::{
    load_text,
    output::Out,
    parse::parse_value_for_tests,
    state::{set_loaded, set_mods_raw, test_serial_lock, Mods},
    translate,
    translate_app,
};

const SAMPLE: &[u8] = br#"
# Tiny US-shaped keymap for unit tests.
keymap "Test US"
keycode 2  plain=1 shift=!
keycode 30 plain=a shift=A
keycode 46 plain=c shift=C
keycode 26 plain=[ shift={
keycode 57 plain=\sp
keycode 28 plain=\n
"#;

fn install() {
    load_text(SAMPLE).expect("parse");
}

#[test]
fn plain_letter() {
    let _g = test_serial_lock();
    install();
    set_mods_raw(0);
    assert_eq!(translate(30).as_bytes(), b"a");
}

#[test]
fn special_keys_emit_escape_sequences() {
    let _g = test_serial_lock();
    install();
    set_mods_raw(0);
    assert_eq!(translate(103).as_bytes(), b"\x1b[A", "Up");
    assert_eq!(translate(108).as_bytes(), b"\x1b[B", "Down");
    assert_eq!(translate(106).as_bytes(), b"\x1b[C", "Right");
    assert_eq!(translate(105).as_bytes(), b"\x1b[D", "Left");
    assert_eq!(translate(104).as_bytes(), b"\x1b[5~", "PageUp");
    assert_eq!(translate(109).as_bytes(), b"\x1b[6~", "PageDown");
    assert_eq!(translate(59).as_bytes(), b"\x1bOP", "F1");
}

#[test]
fn special_keys_independent_of_layout() {
    let _g = test_serial_lock();
    set_loaded(false);
    assert_eq!(translate(103).as_bytes(), b"\x1b[A");
    assert_eq!(translate(30).as_bytes(), b"");
}

#[test]
fn shift_letter() {
    let _g = test_serial_lock();
    install();
    set_mods_raw(Mods::SHIFT.bits());
    assert_eq!(translate(30).as_bytes(), b"A");
}

#[test]
fn caps_folds_on_letter_only() {
    let _g = test_serial_lock();
    install();
    set_mods_raw(Mods::CAPS.bits());
    assert_eq!(translate(30).as_bytes(), b"A");
    assert_eq!(translate(2).as_bytes(), b"1");
}

#[test]
fn ctrl_letter_is_control_code() {
    let _g = test_serial_lock();
    install();
    set_mods_raw(Mods::CTRL.bits());
    assert_eq!(translate(30).as_bytes(), &[0x01]);
    assert_eq!(translate(46).as_bytes(), &[0x03]);
}

#[test]
fn alt_prefixes_with_esc() {
    let _g = test_serial_lock();
    install();
    set_mods_raw(Mods::ALT.bits());
    assert_eq!(translate(30).as_bytes(), &[0x1b, b'a']);
}

#[test]
fn rejects_unloaded() {
    let _g = test_serial_lock();
    set_loaded(false);
    assert_eq!(translate(30), Out::NONE);
}

#[test]
fn parses_escapes_and_hex() {
    let _g = test_serial_lock();
    assert_eq!(parse_value_for_tests(b"\\n"), Some(b'\n' as u32));
    assert_eq!(parse_value_for_tests(b"\\sp"), Some(b' ' as u32));
    assert_eq!(parse_value_for_tests(b"0x1b"), Some(0x1b));
    assert_eq!(parse_value_for_tests(b"A"), Some(b'A' as u32));
    assert_eq!(parse_value_for_tests(b"''"), Some(0));
    assert_eq!(parse_value_for_tests(b"??"), None);
}

#[test]
fn parses_unicode_codepoint() {
    let _g = test_serial_lock();
    assert_eq!(parse_value_for_tests(b"U+00E4"), Some(0x00E4));
    assert_eq!(parse_value_for_tests(b"U+1F600"), Some(0x1F600));
    assert_eq!(parse_value_for_tests(b"U+110000"), None);
}

#[test]
fn parses_multibyte_utf8_direct() {
    assert_eq!(parse_value_for_tests(&[0xC3, 0xA4]), Some(0x00E4));
    assert_eq!(parse_value_for_tests(&[0xC3, 0xB1]), Some(0x00F1));
}

#[test]
fn out_encodes_utf8_for_unicode() {
    let o = Out::from_codepoint(0x00E4);
    assert_eq!(o.as_bytes(), &[0xC3, 0xA4]);
    let o = Out::from_codepoint(0x20AC);
    assert_eq!(o.as_bytes(), &[0xE2, 0x82, 0xAC]);
}

#[test]
fn locale_de_umlaut_via_keymap() {
    let _g = test_serial_lock();
    let blob: &[u8] = br#"
keymap "Test DE"
keycode 39 plain=U+00F6 shift=U+00D6
"#;
    load_text(blob).unwrap();
    set_mods_raw(0);
    assert_eq!(translate(39).as_bytes(), "ö".as_bytes());
    set_mods_raw(Mods::SHIFT.bits());
    assert_eq!(translate(39).as_bytes(), "Ö".as_bytes());
}

#[test]
fn arrows_use_csi_in_normal_mode_ss3_in_app_mode() {
    assert_eq!(translate_app(103, false).as_bytes(), b"\x1b[A", "Up normal = CSI");
    assert_eq!(translate_app(103, true).as_bytes(), b"\x1bOA", "Up app = SS3");
    assert_eq!(translate_app(105, true).as_bytes(), b"\x1bOD", "Left app = SS3");
    assert_eq!(translate_app(102, true).as_bytes(), b"\x1bOH", "Home app = SS3");
    assert_eq!(translate_app(104, true).as_bytes(), b"\x1b[5~", "PgUp app unchanged");
}
