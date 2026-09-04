use alloc::{vec, vec::Vec};
use super::{decode_utf16, parse_environment};

fn units(text: &str) -> Vec<u16> { text.encode_utf16().collect() }

#[test]
fn utf16_command_line_round_trips() {
    assert_eq!(decode_utf16(&units("notepad.exe \"file one.txt\"")),
        Some("notepad.exe \"file one.txt\"".into()));
}

#[test]
fn environment_requires_double_nul_terminator() {
    assert_eq!(parse_environment(&units("PATH=C:\\Windows\0TEMP=C:\\Temp\0\0")),
        Some(vec![("PATH".into(), "C:\\Windows".into()),
                 ("TEMP".into(), "C:\\Temp".into())]));
    assert_eq!(parse_environment(&units("PATH=C:\\Windows\0")), None);
}

#[test]
fn environment_rejects_missing_name() {
    assert_eq!(parse_environment(&units("=bad\0\0")), None);
    assert_eq!(parse_environment(&units("BROKEN\0\0")), None);
}

#[test]
fn environment_accepts_empty_block() {
    assert_eq!(parse_environment(&[0, 0]), Some(Vec::new()));
}

#[test]
fn denormalization_preserves_nulls_and_returns_record_offsets() {
    let base = 0x1000_0000;
    assert_eq!(super::denormalize_pointer_offsets(base,
        [base + 0x410, 0, base + 0x428, base + 0x440, 0, 0, base + 0x458, 0]),
        Some([0x410, 0, 0x428, 0x440, 0, 0, 0x458, 0]));
    assert_eq!(super::denormalize_pointer_offsets(base, [base - 1, 0, 0, 0, 0, 0, 0, 0]), None);
}
