//! XKB symbols/text and evdev-X11 keycodes to native keyboard fields.
//! No keyboard registry: caller supplies XKB modifiers and prior key state.

pub const KEY_EXTENDED: u32 = 1 << 24;
pub const KEY_ALT: u32 = 1 << 29;
pub const KEY_PREVIOUS: u32 = 1 << 30;
pub const KEY_RELEASE: u32 = 1 << 31;
const X11_EVDEV_OFFSET: u32 = 8;
const SCAN_EXTENDED: u16 = 0x100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scan { pub code: u8, pub extended: bool }

/// Requires the evdev XKB keycode mapping, not arbitrary X server keycodes.
/// Unknown physical keys have no fabricated scan code.
pub fn evdev_x11_scan(keycode: u32) -> Option<Scan> {
    let key = keycode.checked_sub(X11_EVDEV_OFFSET)?;
    let scan: u16 = match key {
        69 => 0x145, // NumLock; Pause uses the same low scan without extended.
        1..=83 | 86..=88 => key as u16,
        89 => 0x73, 90 | 91 | 93 => 0x70, 92 => 0x79, 94 => 0x7b,
        96 => 0x11c, 97 => 0x11d, 98 => 0x135, 99 => 0x137, 100 => 0x138,
        102 => 0x147, 103 => 0x148, 104 => 0x149, 105 => 0x14b, 106 => 0x14d,
        107 => 0x14f, 108 => 0x150, 109 => 0x151, 110 => 0x152, 111 => 0x153,
        113 => 0x120, 114 => 0x12e, 115 => 0x130, 116 => 0x15e,
        119 => 0x45, 121 => 0x7e, 124 => 0x7d,
        125 => 0x15b, 126 => 0x15c, 127 => 0x15d,
        _ => return None,
    };
    Some(Scan { code: scan as u8, extended: scan & SCAN_EXTENDED != 0 })
}

/// Use the layout's base-level symbol for printable key identity. Shifted
/// text is a separate XKB result; punctuation cannot identify a layout alone.
/// Unsupported symbols return None, never a wire VK of zero.
pub fn keysym_to_vk(sym: u32) -> Option<u32> {
    Some(match sym {
        0x61..=0x7a => sym - 0x20,
        0x41..=0x5a | 0x30..=0x39 => sym,
        0x20 | 0xff80 => 0x20,
        0x3b => 0xba, 0x3d => 0xbb, 0x2c => 0xbc, 0x2d => 0xbd,
        0x2e => 0xbe, 0x2f => 0xbf, 0x60 => 0xc0, 0x5b => 0xdb,
        0x5c => 0xdc, 0x5d => 0xdd, 0x27 => 0xde,
        0xff08 => 0x08, 0xff09 | 0xfe20 | 0xff89 => 0x09,
        0xff0b | 0xff9d => 0x0c, 0xff0d | 0xff8d => 0x0d,
        0xff13 => 0x13, 0xff14 => 0x91, 0xff1b => 0x1b,
        0xff21 | 0xff34 => 0x19, 0xff22 => 0x1d, 0xff23 => 0x1c,
        0xff31 => 0x15,
        0xff50 | 0xff95 => 0x24, 0xff51 | 0xff96 => 0x25,
        0xff52 | 0xff97 => 0x26, 0xff53 | 0xff98 => 0x27,
        0xff54 | 0xff99 => 0x28, 0xff55 | 0xff9a => 0x21,
        0xff56 | 0xff9b => 0x22, 0xff57 | 0xff9c => 0x23,
        0xff60 => 0x29, 0xff61 => 0x2c, 0xff62 => 0x2b,
        0xff63 | 0xff9e => 0x2d, 0xffff | 0xff9f => 0x2e,
        0xff67 => 0x5d, 0xff69 | 0xff6b => 0x03, 0xff6a => 0x2f,
        0xff7f => 0x90, 0xffaa => 0x6a, 0xffab => 0x6b,
        0xffac | 0xffae => 0x6e, 0xffad => 0x6d, 0xffaf => 0x6f,
        0xffb0..=0xffb9 => 0x60 + sym - 0xffb0, 0xffbd => 0x92,
        0xffbe..=0xffd5 => 0x70 + sym - 0xffbe,
        0xffe1 => 0xa0, 0xffe2 => 0xa1, 0xffe3 => 0xa2, 0xffe4 => 0xa3,
        0xffe5 => 0x14, 0xffe7 | 0xffe9 => 0xa4,
        0xffe8 | 0xffea | 0xfe03 => 0xa5, 0xffeb => 0x5b, 0xffec => 0x5c,
        0x1008ff11 => 0xae, 0x1008ff12 => 0xad, 0x1008ff13 => 0xaf,
        0x1008ff14 => 0xb3, 0x1008ff15 => 0xb2, 0x1008ff16 => 0xb1,
        0x1008ff17 => 0xb0, 0x1008ff18 => 0xb4, 0x1008ff1b => 0xaa,
        0x1008ff26 => 0xa6, 0x1008ff27 => 0xa7, 0x1008ff28 => 0xa9,
        0x1008ff29 => 0xa8,
        _ => return None,
    })
}

/// XKB modifier indices/masks belong to the live keymap. In particular Alt
/// and level-three must not be guessed from fixed Mod1/Mod5 assignments.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModifierMasks { pub shift: u32, pub control: u32, pub alt: u32, pub level_three: u32 }

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Modifiers { pub shift: bool, pub control: bool, pub alt: bool, pub level_three: bool }

impl ModifierMasks {
    pub fn decode(self, active: u32) -> Modifiers {
        Modifiers { shift: active & self.shift != 0, control: active & self.control != 0,
            alt: active & self.alt != 0, level_three: active & self.level_three != 0 }
    }
}

/// Wire modifier word: only bits 24/29/30. Caller supplies Alt context and
/// previous physical state, not the pre-event X11 state mask.
pub fn key_flags(scan: Scan, pressed: bool, was_down: bool, alt_context: bool) -> u32 {
    (if scan.extended { KEY_EXTENDED } else { 0 }) |
    (if alt_context { KEY_ALT } else { 0 }) |
    (if was_down || !pressed { KEY_PREVIOUS } else { 0 })
}

pub fn key_lparam(scan: Scan, pressed: bool, was_down: bool, alt_context: bool) -> u32 {
    1 | ((scan.code as u32) << 16) | key_flags(scan, pressed, was_down, alt_context) |
        if pressed { 0 } else { KEY_RELEASE }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextError { Conversion, Truncated, InvalidUtf8, EmbeddedNul }

/// xkb_keysym_to_utf8 counts its terminating NUL. No text on key release.
pub fn keysym_utf8(buffer: &[u8], count: i32, pressed: bool) -> Result<Option<&str>, TextError> {
    if !pressed || count == 0 { return Ok(None); }
    let count = usize::try_from(count).map_err(|_| TextError::Conversion)?;
    terminated_utf8(buffer, count - 1)
}

/// xkb_state_key_get_utf8 excludes its NUL and performs Control/case transforms.
/// Prefer this over keysym-only conversion for application text.
pub fn state_utf8(buffer: &[u8], count: i32, pressed: bool) -> Result<Option<&str>, TextError> {
    if !pressed || count == 0 { return Ok(None); }
    let count = usize::try_from(count).map_err(|_| TextError::Conversion)?;
    terminated_utf8(buffer, count)
}

fn terminated_utf8(buffer: &[u8], length: usize) -> Result<Option<&str>, TextError> {
    if buffer.get(length) != Some(&0) { return Err(TextError::Truncated); }
    let bytes = &buffer[..length];
    if bytes.contains(&0) { return Err(TextError::EmbeddedNul); }
    let text = std::str::from_utf8(bytes).map_err(|_| TextError::InvalidUtf8)?;
    Ok(if text.is_empty() { None } else { Some(text) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_char;
    use crate::ffi::{XkbContext, XkbKeymap, XkbState, xkb_context_new, xkb_context_unref,
        xkb_keymap_unref, xkb_state_unref, xkb_state_update_key, xkb_state_key_get_one_sym, xkb_keysym_to_utf8};

    #[repr(C)]
    struct Names { rules: *const c_char, model: *const c_char, layout: *const c_char, variant: *const c_char, options: *const c_char }
    #[link(name = "xkbcommon")]
    extern "C" {
        fn xkb_keymap_new_from_names(context: *mut XkbContext, names: *const Names, flags: u32) -> *mut XkbKeymap;
        fn xkb_state_new(keymap: *mut XkbKeymap) -> *mut XkbState;
        fn xkb_state_key_get_utf8(state: *mut XkbState, key: u32, buffer: *mut c_char, size: usize) -> i32;
    }

    #[test]
    fn actual_xkb_keysym_results_exclude_nul_on_wire() {
        for (sym, expected) in [(0x61,"a"), (0xff0d,"\r"), (0x0101f642,"🙂")] {
            let mut buffer = [0u8; 16];
            // SAFETY: xkb_keysym_to_utf8 receives the complete writable buffer.
            let count = unsafe { xkb_keysym_to_utf8(sym, buffer.as_mut_ptr().cast(), buffer.len()) };
            assert_eq!(count as usize, expected.len() + 1);
            assert_eq!(keysym_utf8(&buffer, count, true), Ok(Some(expected)));
            assert_eq!(keysym_utf8(&buffer, count, false), Ok(None));
        }
    }

    #[test]
    fn actual_xkb_state_applies_shift_control_and_release() {
        // SAFETY: xkb_context_new takes flags only and returns an owned context.
        let context = unsafe { xkb_context_new(0) };
        assert!(!context.is_null());
        let names = Names { rules: c"evdev".as_ptr(), model: c"pc105".as_ptr(), layout: c"us".as_ptr(),
            variant: c"".as_ptr(), options: c"".as_ptr() };
        // SAFETY: xkb_keymap_new_from_names reads live NUL-terminated names.
        let keymap = unsafe { xkb_keymap_new_from_names(context, &names, 0) };
        assert!(!keymap.is_null());
        // SAFETY: xkb_state_new borrows the live keymap and retains its own ref.
        let state = unsafe { xkb_state_new(keymap) };
        assert!(!state.is_null());
        let read_a = || {
            let mut buffer = [0u8; 16];
            // SAFETY: xkb_state_key_get_utf8 receives live state and buffer.
            let count = unsafe { xkb_state_key_get_utf8(state, 38, buffer.as_mut_ptr().cast(), buffer.len()) };
            state_utf8(&buffer, count, true).unwrap().unwrap().to_owned()
        };
        assert_eq!(read_a(), "a");
        // SAFETY: xkb_state_update_key uses a valid evdev key on live state.
        unsafe { xkb_state_update_key(state, 50, 1); }
        assert_eq!(read_a(), "A");
        let mut digit = [0u8; 8];
        // SAFETY: live XKB state and complete writable digit buffer are passed.
        let count = unsafe { xkb_state_key_get_utf8(state, 10, digit.as_mut_ptr().cast(), digit.len()) };
        assert_eq!(state_utf8(&digit, count, true), Ok(Some("!")));
        // SAFETY: xkb_state_key_get_one_sym reads a valid key in the live state.
        let shifted = unsafe { xkb_state_key_get_one_sym(state, 10) };
        assert_eq!(shifted, b'!' as u32);
        assert_eq!(keysym_to_vk(shifted), None); // Text is not base key identity.
        assert_eq!(keysym_to_vk(b'1' as u32), Some(0x31));
        let mut truncated = [0u8; 1];
        // SAFETY: XKB receives a one-byte buffer and must report required length.
        let required = unsafe { xkb_state_key_get_utf8(state, 10, truncated.as_mut_ptr().cast(), truncated.len()) };
        assert_eq!(required, 1);
        assert_eq!(state_utf8(&truncated, required, true), Err(TextError::Truncated));
        // SAFETY: xkb_state_update_key releases Shift then depresses Control.
        unsafe { xkb_state_update_key(state, 50, 0); xkb_state_update_key(state, 37, 1); }
        assert_eq!(read_a(), "\u{1}");
        // SAFETY: xkb_state_update_key releases the previously pressed Control.
        unsafe { xkb_state_update_key(state, 37, 0); }
        assert_eq!(read_a(), "a");
        // SAFETY: owned xkb state/keymap/context are released once in ref order.
        unsafe { xkb_state_unref(state); xkb_keymap_unref(keymap); xkb_context_unref(context); }
    }

    #[test]
    fn alphabet_and_digits_are_virtual_keys_not_keycodes() {
        for c in b'a'..=b'z' {
            assert_eq!(keysym_to_vk(c as u32), Some(c.to_ascii_uppercase() as u32));
            assert_eq!(keysym_to_vk(c.to_ascii_uppercase() as u32), Some(c.to_ascii_uppercase() as u32));
        }
        for c in b'0'..=b'9' { assert_eq!(keysym_to_vk(c as u32), Some(c as u32)); }
        assert_eq!(evdev_x11_scan(38), Some(Scan { code: 0x1e, extended: false }));
        assert_eq!(evdev_x11_scan(10), Some(Scan { code: 0x02, extended: false }));
        assert_eq!(keysym_to_vk(0x0101f642), None);
        assert_eq!(keysym_to_vk(0), None);
        assert_eq!(evdev_x11_scan(7), None);
        assert_eq!(evdev_x11_scan(u32::MAX), None);
    }

    #[test]
    fn navigation_and_keypad_have_distinct_extended_scans() {
        for (sym, vk, xkey, scan) in [(0xff50,0x24,110,0x47), (0xff51,0x25,113,0x4b),
            (0xff52,0x26,111,0x48), (0xff53,0x27,114,0x4d), (0xff54,0x28,116,0x50),
            (0xff55,0x21,112,0x49), (0xff56,0x22,117,0x51), (0xff57,0x23,115,0x4f),
            (0xff63,0x2d,118,0x52), (0xffff,0x2e,119,0x53)] {
            assert_eq!(keysym_to_vk(sym), Some(vk));
            assert_eq!(evdev_x11_scan(xkey), Some(Scan { code: scan, extended: true }));
        }
        assert_eq!(keysym_to_vk(0xff95), Some(0x24));
        assert_eq!(evdev_x11_scan(79), Some(Scan { code: 0x47, extended: false }));
        assert_eq!(evdev_x11_scan(104), Some(Scan { code: 0x1c, extended: true }));
        assert_eq!(keysym_to_vk(0xffac), Some(0x6e));
    }

    #[test]
    fn controls_modifiers_and_function_keys() {
        for (sym, vk) in [(0xff08,8),(0xff09,9),(0xfe20,9),(0xff0d,13),(0xff1b,27),
            (0xffe1,0xa0),(0xffe2,0xa1),(0xffe3,0xa2),(0xffe4,0xa3),
            (0xffe9,0xa4),(0xffea,0xa5),(0xfe03,0xa5)] { assert_eq!(keysym_to_vk(sym), Some(vk)); }
        for n in 0..24 { assert_eq!(keysym_to_vk(0xffbe + n), Some(0x70 + n)); }
        assert_eq!(evdev_x11_scan(62), Some(Scan { code: 0x36, extended: false }));
        assert_eq!(evdev_x11_scan(105), Some(Scan { code: 0x1d, extended: true }));
        assert_eq!(evdev_x11_scan(108), Some(Scan { code: 0x38, extended: true }));
        assert_eq!(evdev_x11_scan(127), Some(Scan { code: 0x45, extended: false }));
    }

    #[test]
    fn lparam_initial_repeat_release_and_alt_flags() {
        let scan = evdev_x11_scan(113).unwrap();
        assert_eq!(key_lparam(scan, true, false, false), 0x014b0001);
        assert_eq!(key_lparam(scan, true, true, true), 0x614b0001);
        assert_eq!(key_lparam(scan, false, false, true), 0xe14b0001);
        assert_eq!(key_flags(scan, false, false, true), 0x61000000);
        assert_eq!(key_lparam(evdev_x11_scan(38).unwrap(), true, false, false), 0x001e0001);
    }

    #[test]
    fn modifier_masks_follow_keymap_not_fixed_x11_mod_slots() {
        let masks = ModifierMasks { shift: 1, control: 4, alt: 64, level_three: 8 };
        assert_eq!(masks.decode(8), Modifiers { level_three: true, ..Modifiers::default() });
        assert_eq!(masks.decode(69), Modifiers { shift: true, control: true, alt: true, level_three: false });
        assert_eq!(masks.decode(0), Modifiers::default());
    }

    #[test]
    fn flags_truth_table_has_no_x11_masks_or_release_bit_on_wire() {
        for extended in [false, true] { for pressed in [false, true] {
            for previous in [false, true] { for alt in [false, true] {
                let scan = Scan { code: 0x38, extended };
                let flags = key_flags(scan, pressed, previous, alt);
                assert_eq!((flags >> 24) & 1, extended as u32);
                assert_eq!((flags >> 29) & 1, alt as u32);
                assert_eq!((flags >> 30) & 1, (previous || !pressed) as u32);
                assert_eq!(flags & !0x61000000, 0);
                let lparam = key_lparam(scan, pressed, previous, alt);
                assert_eq!(lparam & 0xffff, 1);
                assert_eq!((lparam >> 16) & 0xff, 0x38);
                assert_eq!((lparam >> 31) & 1, (!pressed) as u32);
            }}
        }}
    }

    #[test]
    fn base_punctuation_keypad_digits_and_scan_domain() {
        for (sym, vk) in [(b';',0xba),(b'=',0xbb),(b',',0xbc),(b'-',0xbd),
            (b'.',0xbe),(b'/',0xbf),(b'`',0xc0),(b'[',0xdb),(b'\\',0xdc),(b']',0xdd),(b'\'',0xde)] {
            assert_eq!(keysym_to_vk(sym as u32), Some(vk));
        }
        for n in 0..10 { assert_eq!(keysym_to_vk(0xffb0 + n), Some(0x60 + n)); }
        for keycode in 0..=255 {
            if let Some(scan) = evdev_x11_scan(keycode) {
                assert_ne!(scan.code, 0);
                assert_eq!(key_flags(scan, true, false, false) & !0x01000000, 0);
            }
        }
        assert_eq!(evdev_x11_scan(8), None);
        assert_eq!(evdev_x11_scan(256), None);
    }

    #[test]
    fn text_counts_are_bounded_even_with_oversized_signed_results() {
        for count in [i32::MIN, -2, -1] {
            assert_eq!(state_utf8(b"a\0", count, true), Err(TextError::Conversion));
        }
        for count in [3, 32, i32::MAX] {
            assert_eq!(state_utf8(b"a\0", count, true), Err(TextError::Truncated));
            assert_eq!(keysym_utf8(b"a\0", count, true), Err(TextError::Truncated));
        }
        assert_eq!(state_utf8(b"a\0ignored", 1, true), Ok(Some("a")));
        assert_eq!(keysym_utf8(b"a\0ignored", 2, true), Ok(Some("a")));
        assert_eq!(state_utf8(b"a\0", i32::MAX, false), Ok(None));
    }

    #[test]
    fn text_removes_only_terminator_preserves_control_and_supplementary() {
        for text in ["a", "A", "9", "\t", "\r", "\u{8}", "\u{1}", "é", "🙂"] {
            let mut buf = text.as_bytes().to_vec(); buf.push(0);
            assert_eq!(keysym_utf8(&buf, buf.len() as i32, true), Ok(Some(text)));
            assert_eq!(state_utf8(&buf, text.len() as i32, true), Ok(Some(text)));
            assert_eq!(state_utf8(&buf, text.len() as i32, false), Ok(None));
        }
        assert_eq!(state_utf8("🙂\0".as_bytes(), 4, true).unwrap().unwrap().encode_utf16().collect::<Vec<_>>(), [0xd83d,0xde42]);
    }

    #[test]
    fn text_rejects_failed_truncated_invalid_and_embedded_nul() {
        assert_eq!(keysym_utf8(b"a\0", -1, true), Err(TextError::Conversion));
        assert_eq!(keysym_utf8(b"a\0", 3, true), Err(TextError::Truncated));
        assert_eq!(keysym_utf8(b"ab", 2, true), Err(TextError::Truncated));
        assert_eq!(state_utf8(b"a\0", 2, true), Err(TextError::Truncated));
        assert_eq!(keysym_utf8(b"\xff\0", 2, true), Err(TextError::InvalidUtf8));
        assert_eq!(keysym_utf8(b"a\0b\0", 4, true), Err(TextError::EmbeddedNul));
        assert_eq!(keysym_utf8(b"\0", 1, true), Ok(None));
        assert_eq!(state_utf8(&[], 0, true), Ok(None));
        assert_eq!(keysym_utf8(&[], -1, false), Ok(None));
    }
}
