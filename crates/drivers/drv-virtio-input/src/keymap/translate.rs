use crate::keymap::{
    output::Out,
    state::{active_keymap, is_loaded, mods, Keymap, Mods},
};

/// Navigation / function keys → ANSI/xterm escape sequences.
/// # C: O(1)
fn special_key_seq(kc: u16, app_cursor: bool) -> Option<Out> {
    let cur = |c: u8| {
        if app_cursor {
            Out::seq(&[0x1b, b'O', c])
        } else {
            Out::seq(&[0x1b, b'[', c])
        }
    };
    Some(match kc {
        103 => cur(b'A'),
        108 => cur(b'B'),
        106 => cur(b'C'),
        105 => cur(b'D'),
        102 => cur(b'H'),
        107 => cur(b'F'),
        104 => Out::seq(b"\x1b[5~"),
        109 => Out::seq(b"\x1b[6~"),
        110 => Out::seq(b"\x1b[2~"),
        111 => Out::seq(b"\x1b[3~"),
        59 => Out::seq(b"\x1bOP"),
        60 => Out::seq(b"\x1bOQ"),
        61 => Out::seq(b"\x1bOR"),
        62 => Out::seq(b"\x1bOS"),
        63 => Out::seq(b"\x1b[15~"),
        64 => Out::seq(b"\x1b[17~"),
        65 => Out::seq(b"\x1b[18~"),
        66 => Out::seq(b"\x1b[19~"),
        67 => Out::seq(b"\x1b[20~"),
        68 => Out::seq(b"\x1b[21~"),
        87 => Out::seq(b"\x1b[23~"),
        88 => Out::seq(b"\x1b[24~"),
        _ => return None,
    })
}

/// Translate `keycode` under the active layout and modifier state, in
/// normal (non-application) cursor-key mode. # C: O(1).
pub fn translate(keycode: u16) -> Out {
    translate_app(keycode, false)
}

/// Translate `keycode` under the active layout + modifier state, honoring
/// the foreground VT's DECCKM (`app_cursor`) for the cursor keys.
/// # C: O(1)
pub fn translate_app(keycode: u16, app_cursor: bool) -> Out {
    if let Some(seq) = special_key_seq(keycode, app_cursor) {
        return seq;
    }
    if !is_loaded() {
        return Out::NONE;
    }
    let g = active_keymap();
    let km = match g.as_ref() {
        Some(k) => k,
        None => return Out::NONE,
    };
    let m = mods();
    let kc = keycode as usize;
    if kc >= 256 {
        return Out::NONE;
    }

    if m.contains(Mods::CTRL) {
        let plain = km.plain[kc];
        if let Ok(p) = u8::try_from(plain) {
            if p.is_ascii_lowercase() {
                return wrap_meta(m, Out::one(p - b'a' + 1));
            }
            if p.is_ascii_uppercase() {
                return wrap_meta(m, Out::one(p - b'A' + 1));
            }
            match p {
                b'[' | b'{' => return wrap_meta(m, Out::one(0x1b)),
                b'\\' | b'|' => return wrap_meta(m, Out::one(0x1c)),
                b']' | b'}' => return wrap_meta(m, Out::one(0x1d)),
                b' ' => return wrap_meta(m, Out::one(0x00)),
                _ => {}
            }
        }
    }

    if m.contains(Mods::ALTGR) {
        let tbl = if m.contains(Mods::SHIFT) {
            &km.shift_altgr
        } else {
            &km.altgr
        };
        let cp = tbl[kc];
        if cp != 0 {
            return wrap_meta(m, Out::from_codepoint(cp));
        }
    }

    let shifted = if is_letter_kc(km, kc) {
        m.shifted_letter()
    } else {
        m.contains(Mods::SHIFT)
    };
    let cp = if shifted { km.shift[kc] } else { km.plain[kc] };
    if cp == 0 {
        return Out::NONE;
    }
    wrap_meta(m, Out::from_codepoint(cp))
}

#[inline]
fn wrap_meta(m: Mods, o: Out) -> Out {
    if m.contains(Mods::ALT) {
        o.with_meta()
    } else {
        o
    }
}

fn is_letter_kc(km: &Keymap, kc: usize) -> bool {
    let cp = km.plain[kc];
    if cp > 0x7F {
        return false;
    }
    let b = cp as u8;
    b.is_ascii_lowercase() || b.is_ascii_uppercase()
}
