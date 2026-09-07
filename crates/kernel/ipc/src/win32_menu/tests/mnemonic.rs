//! The prefix rules, against the labels a real text editor's menu bar carries
//! and against every shape of prefix a label can hold.
use super::*;
use alloc::vec;
use alloc::vec::Vec;

/// The five labels of the reference text editor's own menu bar.
const NOTEPAD_BAR: [&[u8]; 5] = [b"&File", b"&Edit", b"F&ormat", b"&View", b"&Help"];

fn wide(label: &[u8]) -> Vec<u16> { label.iter().map(|unit| *unit as u16).chain(core::iter::once(0)).collect() }

fn drawn(label: &[u8]) -> (Vec<u8>, Option<usize>) {
    let text = display_text(&wide(label));
    (text.units.iter().map(|unit| *unit as u8).collect(), text.mnemonic)
}

#[test]
fn a_prefix_is_consumed_and_marks_the_character_behind_it() {
    let expected: [(&[u8], usize); 5] = [(b"File", 0), (b"Edit", 0), (b"Format", 1), (b"View", 0), (b"Help", 0)];
    for (label, (text, mnemonic)) in NOTEPAD_BAR.iter().zip(expected) {
        assert_eq!(drawn(label), (text.to_vec(), Some(mnemonic)), "label {label:?}");
        // The drawn label is one character shorter than the stored one, so
        // what is measured matches what is drawn.
        assert_eq!(display_len(&wide(label)), label.len() - 1);
    }
}

#[test]
fn a_label_with_no_prefix_is_drawn_as_it_is_stored() {
    assert_eq!(drawn(b"Format"), (b"Format".to_vec(), None));
    assert_eq!(display_len(&wide(b"Format")), 6);
    assert_eq!(mnemonic_char(&wide(b"Format")), None);
}

#[test]
fn a_doubled_prefix_draws_one_literal_prefix_and_marks_nothing() {
    assert_eq!(drawn(b"AT&&T"), (b"AT&T".to_vec(), None));
    assert_eq!(display_len(&wide(b"AT&&T")), 4);
    // A doubled prefix ahead of a real one leaves the real one marking.
    assert_eq!(drawn(b"AT&&T &Wireless"), (b"AT&T Wireless".to_vec(), Some(5)));
}

#[test]
fn a_prefix_at_the_end_of_a_label_stands_for_itself() {
    assert_eq!(drawn(b"Save&"), (b"Save&".to_vec(), None));
    assert_eq!(display_len(&wide(b"Save&")), 5);
}

#[test]
fn only_the_first_prefix_of_a_label_marks_a_character() {
    assert_eq!(drawn(b"&Save &As"), (b"Save As".to_vec(), Some(0)));
    assert_eq!(mnemonic_char(&wide(b"&Save &As")), Some(b'S' as u16));
}

#[test]
fn the_legacy_prefixes_mark_and_drop_the_way_the_ampersand_does() {
    let alphabet = vec![ALPHA_PREFIX, b'O' as u16, b'k' as u16, 0];
    assert_eq!(display_text(&alphabet), DisplayText { units: vec![b'O' as u16, b'k' as u16], mnemonic: Some(0) });
    let katakana = vec![b'O' as u16, KANA_PREFIX, b'k' as u16, 0];
    assert_eq!(display_text(&katakana), DisplayText { units: vec![b'O' as u16], mnemonic: None });
}

#[test]
fn a_label_stops_at_its_terminator() {
    assert_eq!(stored_len(&[65, 66, 0, 67]), 2);
    assert_eq!(stored_len(&[65, 66]), 2);
    assert_eq!(stored_len(&[]), 0);
    assert_eq!(drawn(b""), (Vec::new(), None));
}

#[test]
fn a_label_splits_at_its_first_tab_and_each_half_keeps_its_own_prefix_rules() {
    let halves = label_halves(&wide(b"&Save\tCtrl+S"));
    assert_eq!(halves.name, DisplayText { units: wide(b"Save")[..4].to_vec(), mnemonic: Some(0) });
    let (align, accel) = halves.accel.unwrap();
    assert_eq!(align, AccelAlign::Tab);
    assert_eq!(accel.units, wide(b"Ctrl+S")[..6].to_vec());
}

#[test]
fn a_flush_right_unit_splits_the_label_the_same_way_a_tab_does() {
    let halves = label_halves(&wide(b"Help\x08F1"));
    assert_eq!(halves.accel.unwrap().0, AccelAlign::FlushRight);
    assert_eq!(halves.name.units, wide(b"Help")[..4].to_vec());
}

#[test]
fn a_label_with_no_split_unit_is_all_name() {
    let halves = label_halves(&wide(b"&Undo"));
    assert_eq!(halves.name, display_text(&wide(b"&Undo")));
    assert_eq!(halves.accel, None);
}

#[test]
fn the_mnemonic_of_a_split_label_is_looked_for_in_its_name_half_only() {
    // The prefix in the accelerator half marks nothing: the key that selects
    // the item is the one its name advertises.
    assert_eq!(mnemonic_char(&wide(b"Save\tCtrl+&S")), None);
    assert_eq!(mnemonic_char(&wide(b"&Save\tCtrl+S")), Some(b'S' as u16));
}
