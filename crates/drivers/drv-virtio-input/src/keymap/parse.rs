extern crate alloc;

use alloc::string::String;

use crate::keymap::state::{install_keymap, Keymap};

/// Errors from the text parser. Held verbatim so userspace can
/// turn them back into `loadkeys`-style diagnostics.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LoadError {
    BadLine(u32),
    BadKeycode(u32),
    BadValue(u32),
    Truncated,
}

/// Parse a text keymap blob and install it as the active map.
/// Replaces any previously loaded map. Returns the layout name on
/// success, or `LoadError` pointing at the offending line.
/// # C: O(len(blob))
pub fn load_text(blob: &[u8]) -> Result<String, LoadError> {
    let mut km = Keymap::empty();
    let mut line_no = 0u32;
    for raw_line in blob.split(|&b| b == b'\n') {
        line_no += 1;
        let line = trim(raw_line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }

        if line.starts_with(b"keymap") {
            let rest = trim(&line[b"keymap".len()..]);
            km.name = parse_name(rest).unwrap_or_default();
            continue;
        }

        if !line.starts_with(b"keycode") {
            return Err(LoadError::BadLine(line_no));
        }
        let rest = trim(&line[b"keycode".len()..]);
        let (n_str, rest) = split_ws(rest);
        let kc: usize = parse_dec(n_str).ok_or(LoadError::BadKeycode(line_no))?;
        if kc >= 256 {
            return Err(LoadError::BadKeycode(line_no));
        }

        let mut cursor = rest;
        while !cursor.is_empty() {
            let (tok, next) = split_ws(cursor);
            cursor = next;
            if tok.is_empty() {
                continue;
            }
            let eq = match tok.iter().position(|&b| b == b'=') {
                Some(index) => index,
                None => return Err(LoadError::BadLine(line_no)),
            };
            let (key, valpart) = (&tok[..eq], &tok[eq + 1..]);
            let val = parse_value(valpart).ok_or(LoadError::BadValue(line_no))?;
            let tbl = match key {
                b"plain" => &mut km.plain,
                b"shift" => &mut km.shift,
                b"altgr" => &mut km.altgr,
                b"shift_altgr" => &mut km.shift_altgr,
                _ => return Err(LoadError::BadLine(line_no)),
            };
            tbl[kc] = val;
        }
    }

    let name = km.name.clone();
    install_keymap(km);
    Ok(name)
}

fn trim(s: &[u8]) -> &[u8] {
    let mut a = 0;
    let mut b = s.len();
    while a < b && (s[a] == b' ' || s[a] == b'\t' || s[a] == b'\r') {
        a += 1;
    }
    while b > a && (s[b - 1] == b' ' || s[b - 1] == b'\t' || s[b - 1] == b'\r') {
        b -= 1;
    }
    &s[a..b]
}

fn split_ws(s: &[u8]) -> (&[u8], &[u8]) {
    let s = trim(s);
    let mut i = 0;
    while i < s.len() && s[i] != b' ' && s[i] != b'\t' {
        i += 1;
    }
    let tok = &s[..i];
    let rest = if i < s.len() { trim(&s[i + 1..]) } else { &[][..] };
    (tok, rest)
}

fn parse_dec(s: &[u8]) -> Option<usize> {
    let s = trim(s);
    if s.is_empty() {
        return None;
    }
    let mut n: usize = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((c - b'0') as usize)?;
    }
    Some(n)
}

fn parse_name(s: &[u8]) -> Option<String> {
    let s = trim(s);
    if s.len() < 2 || s[0] != b'"' || s[s.len() - 1] != b'"' {
        return None;
    }
    let body = &s[1..s.len() - 1];
    Some(String::from_utf8_lossy(body).into_owned())
}

/// Parse a keymap value into a Unicode codepoint. Returns 0 for
/// `''` (explicit no-mapping), `Some(cp)` for a codepoint, or
/// `None` for unparseable input.
#[cfg(test)]
pub(crate) fn parse_value_for_tests(v: &[u8]) -> Option<u32> {
    parse_value(v)
}

fn parse_value(v: &[u8]) -> Option<u32> {
    let v = trim(v);
    if v == b"''" {
        return Some(0);
    }
    if v.starts_with(b"U+") || v.starts_with(b"u+") {
        let mut n: u32 = 0;
        if v.len() <= 2 || v.len() > 8 {
            return None;
        }
        for &c in &v[2..] {
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => 10 + (c - b'a'),
                b'A'..=b'F' => 10 + (c - b'A'),
                _ => return None,
            };
            n = n.checked_shl(4)?.checked_add(d as u32)?;
            if n > 0x10_FFFF {
                return None;
            }
        }
        return Some(n);
    }
    if v.starts_with(b"0x") || v.starts_with(b"0X") {
        let mut n: u32 = 0;
        for &c in &v[2..] {
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => 10 + (c - b'a'),
                b'A'..=b'F' => 10 + (c - b'A'),
                _ => return None,
            };
            n = n.checked_shl(4)?.checked_add(d as u32)?;
            if n > 0xFF {
                return None;
            }
        }
        return Some(n);
    }
    if v.starts_with(b"\\") && v.len() == 2 {
        return Some(match v[1] {
            b'n' => b'\n' as u32,
            b't' => b'\t' as u32,
            b'b' => 0x08,
            b'r' => b'\r' as u32,
            b'e' => 0x1b,
            b'\\' => b'\\' as u32,
            b'0' => 0x00,
            _ => return None,
        });
    }
    if v == b"\\sp" {
        return Some(b' ' as u32);
    }
    if v.len() == 1 && v[0].is_ascii() {
        return Some(v[0] as u32);
    }
    decode_utf8(v)
}

fn decode_utf8(v: &[u8]) -> Option<u32> {
    if v.is_empty() {
        return None;
    }
    let b0 = v[0];
    let (n, cp): (usize, u32) = if b0 < 0x80 {
        (1, b0 as u32)
    } else if b0 & 0xE0 == 0xC0 {
        if v.len() < 2 || v[1] & 0xC0 != 0x80 {
            return None;
        }
        (2, (((b0 & 0x1F) as u32) << 6) | ((v[1] & 0x3F) as u32))
    } else if b0 & 0xF0 == 0xE0 {
        if v.len() < 3 || v[1] & 0xC0 != 0x80 || v[2] & 0xC0 != 0x80 {
            return None;
        }
        (
            3,
            (((b0 & 0x0F) as u32) << 12)
                | (((v[1] & 0x3F) as u32) << 6)
                | ((v[2] & 0x3F) as u32),
        )
    } else if b0 & 0xF8 == 0xF0 {
        if v.len() < 4 || v[1] & 0xC0 != 0x80 || v[2] & 0xC0 != 0x80 || v[3] & 0xC0 != 0x80 {
            return None;
        }
        (
            4,
            (((b0 & 0x07) as u32) << 18)
                | (((v[1] & 0x3F) as u32) << 12)
                | (((v[2] & 0x3F) as u32) << 6)
                | ((v[3] & 0x3F) as u32),
        )
    } else {
        return None;
    };
    if v.len() != n {
        return None;
    }
    if cp > 0x10_FFFF || (0xD800..=0xDFFF).contains(&cp) {
        return None;
    }
    Some(cp)
}
