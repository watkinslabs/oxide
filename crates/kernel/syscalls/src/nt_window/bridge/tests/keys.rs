//! The keyboard half of the compositor event surface: which message one key
//! transition becomes, the lParam it carries, and the character message the
//! text that follows it becomes.
use super::*;
use super::tests::{deliver, deliver_keys, event, next, state, words};
use super::super::key_message::{KEY_ALT, WM_CHAR, WM_SYSCHAR, WM_SYSKEYDOWN, WM_SYSKEYUP};

#[test]
fn key_scan_extended_repeat_and_release_bits_are_preserved() {
    let (mut state, id) = state();
    assert!(deliver(&mut state, &event(Opcode::Key, id, words(&[0x41, 0x1e, 1, KEY_EXTENDED | KEY_PREVIOUS]))));
    let key = next(&mut state).unwrap();
    assert_eq!(key.message, gui::WM_KEYDOWN);
    assert_eq!(key.wparam, 0x41);
    assert_eq!(key.lparam as u32, 1 | (0x1e << 16) | KEY_EXTENDED | KEY_PREVIOUS);
    assert!(deliver(&mut state, &event(Opcode::Key, id, words(&[0x41, 0x1e, 0, 0]))));
    let key = next(&mut state).unwrap();
    assert_eq!(key.message, gui::WM_KEYUP);
    assert_eq!(key.lparam as u32, 1 | (0x1e << 16) | KEY_PREVIOUS | KEY_RELEASE);
}

/// The Alt key's own press is a system key and already carries the context
/// bit, which is what puts a bare Alt into menu mode.
#[test]
fn alt_press_and_release_are_system_keys_carrying_the_context_bit() {
    let (mut state, id) = state();
    let mut keys = SysKeyLatch::default();
    assert!(deliver_keys(&mut state, &mut keys, &event(Opcode::Key, id, words(&[0xa4, 0x38, 1, 0]))));
    let key = next(&mut state).unwrap();
    assert_eq!(key.message, WM_SYSKEYDOWN);
    assert_eq!(key.wparam, 0x12);
    assert_eq!(key.lparam as u32 & KEY_ALT, KEY_ALT);
    assert!(deliver_keys(&mut state, &mut keys, &event(Opcode::Key, id, words(&[0xa4, 0x38, 0, 0]))));
    let key = next(&mut state).unwrap();
    assert_eq!(key.message, WM_SYSKEYUP);
    assert_eq!(key.lparam as u32 & KEY_ALT, 0);
}

/// Alt held with a letter is the system key the menu bar's mnemonic rides on,
/// and the text the source reports for it is a system character carrying that
/// key's own lParam.
#[test]
fn alt_letter_is_a_system_key_and_its_text_is_a_system_character() {
    let (mut state, id) = state();
    let mut keys = SysKeyLatch::default();
    assert!(deliver_keys(&mut state, &mut keys, &event(Opcode::Key, id, words(&[0xa4, 0x38, 1, 0]))));
    assert!(deliver_keys(&mut state, &mut keys, &event(Opcode::Key, id, words(&[0x46, 0x21, 1, 0]))));
    assert!(deliver_keys(&mut state, &mut keys, &event(Opcode::Text, id, b"f".to_vec())));
    assert_eq!(next(&mut state).unwrap().message, WM_SYSKEYDOWN);
    let letter = next(&mut state).unwrap();
    assert_eq!((letter.message, letter.wparam), (WM_SYSKEYDOWN, 0x46));
    let character = next(&mut state).unwrap();
    assert_eq!((character.message, character.wparam), (WM_SYSCHAR, b'f' as u64));
    assert_eq!(character.lparam, letter.lparam);
    assert_eq!(character.lparam as u32 & KEY_ALT, KEY_ALT);
}

/// Text with no Alt held is an ordinary character carrying its key's lParam.
#[test]
fn text_after_an_ordinary_key_is_an_ordinary_character() {
    let (mut state, id) = state();
    let mut keys = SysKeyLatch::default();
    assert!(deliver_keys(&mut state, &mut keys, &event(Opcode::Key, id, words(&[0x41, 0x1e, 1, 0]))));
    assert!(deliver_keys(&mut state, &mut keys, &event(Opcode::Text, id, b"a".to_vec())));
    let key = next(&mut state).unwrap();
    assert_eq!(key.message, gui::WM_KEYDOWN);
    let character = next(&mut state).unwrap();
    assert_eq!((character.message, character.wparam, character.lparam), (WM_CHAR, b'a' as u64, key.lparam));
}

