// Keymap layer per docs/46 + Linux's `loadkeys(1)` model. The
// translation tables are *not* compiled into the kernel — they
// load at runtime from `/etc/keymap` (rootfs-owned text file) so
// any region / language / custom layout can swap in without a
// rebuild, identical to how Linux ships `/usr/share/keymaps/*.map`
// and `loadkeys` installs them via the `KDSKBENT` ioctl.
//
// Text format (one keycode per non-comment, non-blank line):
//
//   # comments start with `#`
//   keymap "US QWERTY"
//   keycode <NN> [plain=<c>] [shift=<c>] [altgr=<c>] [shift_altgr=<c>]
//
// `<c>` is one of:
//   - a single printable ASCII character (case-sensitive)
//   - `\n` `\t` `\b` `\e` `\\` `\sp`  (escape forms)
//   - `0xHH`            (hex literal, 8-bit)
//   - `''`              (explicit "no mapping")
//
// Unspecified columns inherit `0` (no mapping). Modifier keycodes
// (Shift / Ctrl / Alt) are not listed here — the drain hard-wires
// them to mod-state bits so a misconfigured keymap can never lock
// the user out of changing layouts.
//
// Modifier state tracking
//   - SHIFT / CTRL / ALT / ALTGR / META are level-triggered.
//   - CAPS / NUM / SCROLL are edge-triggered (toggle on press).
//   - The driver keeps per-side flags (left vs. right) so apps that
//     distinguish can read them via a future ioctl.
//
// Translate(keycode):
//   1. Ctrl + ['a'..='z']  →  control code (^A..^Z)
//   2. AltGr + key         →  shift_altgr / altgr layer
//   3. Shift / Caps        →  shift layer (caps folds only on letters)
//   4. Plain               →  plain layer
//   5. Alt held            →  prepend ESC (xterm Meta convention)

#![cfg_attr(not(test), no_std)]
#![allow(unused_macros, unused_imports)]

extern crate alloc;
use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

// Inline bitflags so we don't pull in the `bitflags` crate.
macro_rules! bitflags_lite {
    ($v:vis struct $T:ident : $repr:ty { $(const $name:ident = $val:expr;)+ }) => {
        #[derive(Copy, Clone, Eq, PartialEq, Debug)]
        $v struct $T($repr);
        impl $T {
            $(pub const $name: Self = Self($val);)+
            /// # C: O(1)
            pub const fn empty() -> Self { Self(0) }
            /// # C: O(1)
            pub const fn bits(self) -> $repr { self.0 }
            /// # C: O(1)
            pub const fn from_bits_truncate(b: $repr) -> Self { Self(b) }
            /// # C: O(1)
            pub const fn contains(self, o: Self) -> bool { (self.0 & o.0) == o.0 }
        }
        impl core::ops::BitOr  for $T { type Output = Self; fn bitor (self, o: Self) -> Self { Self(self.0 | o.0) } }
        impl core::ops::BitAnd for $T { type Output = Self; fn bitand(self, o: Self) -> Self { Self(self.0 & o.0) } }
        impl core::ops::Not    for $T { type Output = Self; fn not   (self)         -> Self { Self(!self.0)    } }
    };
}

bitflags_lite! {
    pub struct Mods: u8 {
        const SHIFT  = 1 << 0;
        const CTRL   = 1 << 1;
        const ALT    = 1 << 2;
        const ALTGR  = 1 << 3;
        const META   = 1 << 4;
        const CAPS   = 1 << 5;
        const NUM    = 1 << 6;
        const SCROLL = 1 << 7;
    }
}

impl Mods {
    /// Effective shift state for letter keys: `Shift XOR CapsLock`.
    /// # C: O(1)
    pub fn shifted_letter(self) -> bool {
        self.contains(Self::SHIFT) ^ self.contains(Self::CAPS)
    }
}

const TABLE_SIZE: usize = 256;

/// Runtime keymap. Loaded from `/etc/keymap` via [`load_text`];
/// callers must own it for as long as it is the active map.
pub struct Keymap {
    pub name:        String,
    pub plain:       [u8; TABLE_SIZE],
    pub shift:       [u8; TABLE_SIZE],
    pub altgr:       [u8; TABLE_SIZE],
    pub shift_altgr: [u8; TABLE_SIZE],
}

impl Keymap {
    /// Construct an all-zero map. Used as a placeholder before the
    /// first `load_text` lands; every entry returns `Out::None`.
    /// # C: O(TABLE_SIZE × 4)
    pub fn empty() -> Self {
        Self {
            name: String::new(),
            plain: [0; TABLE_SIZE],
            shift: [0; TABLE_SIZE],
            altgr: [0; TABLE_SIZE],
            shift_altgr: [0; TABLE_SIZE],
        }
    }
}

// We pick a non-allocating storage so the kernel can install /
// query keymaps from any context without contending on KAlloc.
// The Spinlock guards the boxed Keymap behind a class-ranked spin.
use sync::{Spinlock, Tty as KbdLockClass};

extern crate alloc as _alloc;
static ACTIVE: Spinlock<Option<_alloc::boxed::Box<Keymap>>, KbdLockClass> = Spinlock::new(None);
static LOADED: AtomicBool = AtomicBool::new(false);

/// Live modifier mask. Updated by the drain.
static MODS_RAW: AtomicU8 = AtomicU8::new(0);

// Per-side flags.
static SHIFT_L: AtomicBool = AtomicBool::new(false);
static SHIFT_R: AtomicBool = AtomicBool::new(false);
static CTRL_L:  AtomicBool = AtomicBool::new(false);
static CTRL_R:  AtomicBool = AtomicBool::new(false);
static ALT_L:   AtomicBool = AtomicBool::new(false);
static ALT_R:   AtomicBool = AtomicBool::new(false);

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
        if line.is_empty() || line.starts_with(b"#") { continue; }

        // `keymap "<name>"` directive.
        if line.starts_with(b"keymap") {
            let rest = trim(&line[b"keymap".len()..]);
            km.name = parse_name(rest).unwrap_or_default();
            continue;
        }
        // `keycode <NN> ...`
        if !line.starts_with(b"keycode") { return Err(LoadError::BadLine(line_no)); }
        let rest = trim(&line[b"keycode".len()..]);
        let (n_str, rest) = split_ws(rest);
        let kc: usize = parse_dec(n_str).ok_or(LoadError::BadKeycode(line_no))?;
        if kc >= TABLE_SIZE { return Err(LoadError::BadKeycode(line_no)); }

        // Iterate `key=val` pairs.
        let mut cursor = rest;
        while !cursor.is_empty() {
            let (tok, next) = split_ws(cursor);
            cursor = next;
            if tok.is_empty() { continue; }
            let eq = match tok.iter().position(|&b| b == b'=') {
                Some(i) => i, None => return Err(LoadError::BadLine(line_no)),
            };
            let (key, valpart) = (&tok[..eq], &tok[eq + 1..]);
            let val = parse_value(valpart).ok_or(LoadError::BadValue(line_no))?;
            let tbl = match key {
                b"plain"       => &mut km.plain,
                b"shift"       => &mut km.shift,
                b"altgr"       => &mut km.altgr,
                b"shift_altgr" => &mut km.shift_altgr,
                _ => return Err(LoadError::BadLine(line_no)),
            };
            tbl[kc] = val;
        }
    }

    let name = km.name.clone();
    *ACTIVE.lock() = Some(_alloc::boxed::Box::new(km));
    LOADED.store(true, Ordering::Release);
    Ok(name)
}

/// True iff at least one keymap has been loaded. Drain checks this
/// before translating; if false, EV_KEY events are dropped on the
/// floor (userspace must `loadkeys` before keystrokes flow).
/// # C: O(1)
pub fn is_loaded() -> bool { LOADED.load(Ordering::Acquire) }

/// Read the live modifier mask. Lock-free.
/// # C: O(1)
pub fn mods() -> Mods { Mods::from_bits_truncate(MODS_RAW.load(Ordering::Acquire)) }

/// Update a level-triggered modifier bit.
/// # C: O(1)
pub fn set_mod(bit: Mods, pressed: bool) {
    if pressed { MODS_RAW.fetch_or(bit.bits(), Ordering::Release); }
    else       { MODS_RAW.fetch_and(!bit.bits(), Ordering::Release); }
}

/// Toggle a Caps / Num / Scroll lock bit (call only on key press,
/// ignore the release).
/// # C: O(1)
pub fn toggle_lock(bit: Mods) {
    MODS_RAW.fetch_xor(bit.bits(), Ordering::Release);
}

/// Per-side modifier identity.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Side {
    ShiftLeft, ShiftRight,
    CtrlLeft,  CtrlRight,
    AltLeft,   AltRight,
}

/// Set the per-side flag and update the global merged bit so the
/// mask reflects "either side held".
/// # C: O(1)
pub fn set_side(side: Side, pressed: bool) {
    let (flag, group, peer) = match side {
        Side::ShiftLeft  => (&SHIFT_L, Mods::SHIFT, &SHIFT_R),
        Side::ShiftRight => (&SHIFT_R, Mods::SHIFT, &SHIFT_L),
        Side::CtrlLeft   => (&CTRL_L,  Mods::CTRL,  &CTRL_R),
        Side::CtrlRight  => (&CTRL_R,  Mods::CTRL,  &CTRL_L),
        Side::AltLeft    => (&ALT_L,   Mods::ALT,   &ALT_R),
        Side::AltRight   => (&ALT_R,   Mods::ALTGR, &ALT_L),
    };
    flag.store(pressed, Ordering::Release);
    let any = pressed || peer.load(Ordering::Acquire);
    set_mod(group, any);
}

/// Translation output. `One` = the single byte we map to; `Two` =
/// ESC-prefixed Meta sequence (Alt held); `None` = no mapping.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Out {
    None,
    One(u8),
    Two(u8, u8),
}

impl Out {
    /// Iterate produced bytes. Empty for `None`.
    /// # C: O(1) — bounded by 2 bytes.
    pub fn for_each<F: FnMut(u8)>(self, mut f: F) {
        match self {
            Out::None        => {},
            Out::One(a)      => f(a),
            Out::Two(a, b)   => { f(a); f(b); }
        }
    }
}

/// Translate `keycode` under the active layout and modifier state.
/// Returns `Out::None` if no map is loaded or the key has no entry
/// for the current modifier combination.
/// # C: O(1) — table lookups + a handful of conditionals.
pub fn translate(keycode: u16) -> Out {
    if !is_loaded() { return Out::None; }
    let g = ACTIVE.lock();
    let km = match g.as_ref() { Some(k) => k, None => return Out::None };
    let m = mods();
    let kc = keycode as usize;
    if kc >= TABLE_SIZE { return Out::None; }

    if m.contains(Mods::CTRL) {
        let plain = km.plain[kc];
        if (b'a'..=b'z').contains(&plain) { return wrap_meta(m, plain - b'a' + 1); }
        if (b'A'..=b'Z').contains(&plain) { return wrap_meta(m, plain - b'A' + 1); }
        match plain {
            b'[' | b'{' => return wrap_meta(m, 0x1b),
            b'\\'| b'|' => return wrap_meta(m, 0x1c),
            b']' | b'}' => return wrap_meta(m, 0x1d),
            b' '        => return wrap_meta(m, 0x00),
            _ => {}
        }
    }

    if m.contains(Mods::ALTGR) {
        let tbl = if m.contains(Mods::SHIFT) { &km.shift_altgr } else { &km.altgr };
        let b = tbl[kc];
        if b != 0 { return wrap_meta(m, b); }
    }

    let shifted = if is_letter_kc(km, kc) {
        m.shifted_letter()
    } else {
        m.contains(Mods::SHIFT)
    };
    let b = if shifted { km.shift[kc] } else { km.plain[kc] };
    if b == 0 { return Out::None; }
    wrap_meta(m, b)
}

#[inline]
fn wrap_meta(m: Mods, b: u8) -> Out {
    if m.contains(Mods::ALT) { Out::Two(0x1b, b) } else { Out::One(b) }
}

fn is_letter_kc(km: &Keymap, kc: usize) -> bool {
    let b = km.plain[kc];
    (b'a'..=b'z').contains(&b) || (b'A'..=b'Z').contains(&b)
}

// ----------------------------------------------------------------
// Text-format parser helpers.
// ----------------------------------------------------------------

fn trim(s: &[u8]) -> &[u8] {
    let mut a = 0; let mut b = s.len();
    while a < b && (s[a] == b' ' || s[a] == b'\t' || s[a] == b'\r') { a += 1; }
    while b > a && (s[b-1] == b' ' || s[b-1] == b'\t' || s[b-1] == b'\r') { b -= 1; }
    &s[a..b]
}

fn split_ws(s: &[u8]) -> (&[u8], &[u8]) {
    let s = trim(s);
    let mut i = 0;
    while i < s.len() && s[i] != b' ' && s[i] != b'\t' { i += 1; }
    let tok = &s[..i];
    let rest = if i < s.len() { trim(&s[i+1..]) } else { &[][..] };
    (tok, rest)
}

fn parse_dec(s: &[u8]) -> Option<usize> {
    let s = trim(s);
    if s.is_empty() { return None; }
    let mut n: usize = 0;
    for &c in s {
        if !c.is_ascii_digit() { return None; }
        n = n.checked_mul(10)?.checked_add((c - b'0') as usize)?;
    }
    Some(n)
}

fn parse_name(s: &[u8]) -> Option<String> {
    let s = trim(s);
    if s.len() < 2 || s[0] != b'"' || s[s.len()-1] != b'"' { return None; }
    let body = &s[1..s.len()-1];
    Some(String::from_utf8_lossy(body).into_owned())
}

fn parse_value(v: &[u8]) -> Option<u8> {
    let v = trim(v);
    if v == b"''" { return Some(0); }
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
            if n > 0xFF { return None; }
        }
        return Some(n as u8);
    }
    if v.starts_with(b"\\") && v.len() == 2 {
        return Some(match v[1] {
            b'n' => b'\n', b't' => b'\t', b'b' => 0x08,
            b'r' => b'\r', b'e' => 0x1b,  b'\\' => b'\\',
            b'0' => 0x00,
            _ => return None,
        });
    }
    if v == b"\\sp" { return Some(b' '); }
    if v.len() == 1 && v[0].is_ascii() { return Some(v[0]); }
    None
}

// ----------------------------------------------------------------
// Tests
// ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        install();
        MODS_RAW.store(0, Ordering::Relaxed);
        assert_eq!(translate(30), Out::One(b'a'));
    }

    #[test]
    fn shift_letter() {
        install();
        MODS_RAW.store(Mods::SHIFT.bits(), Ordering::Relaxed);
        assert_eq!(translate(30), Out::One(b'A'));
    }

    #[test]
    fn caps_folds_on_letter_only() {
        install();
        MODS_RAW.store(Mods::CAPS.bits(), Ordering::Relaxed);
        assert_eq!(translate(30), Out::One(b'A'));
        assert_eq!(translate(2),  Out::One(b'1'));
    }

    #[test]
    fn ctrl_letter_is_control_code() {
        install();
        MODS_RAW.store(Mods::CTRL.bits(), Ordering::Relaxed);
        assert_eq!(translate(30), Out::One(0x01));
        assert_eq!(translate(46), Out::One(0x03));
    }

    #[test]
    fn alt_prefixes_with_esc() {
        install();
        MODS_RAW.store(Mods::ALT.bits(), Ordering::Relaxed);
        assert_eq!(translate(30), Out::Two(0x1b, b'a'));
    }

    #[test]
    fn rejects_unloaded() {
        // Force unload — write directly.
        LOADED.store(false, Ordering::Relaxed);
        assert_eq!(translate(30), Out::None);
    }

    #[test]
    fn parses_escapes_and_hex() {
        assert_eq!(parse_value(b"\\n"), Some(b'\n'));
        assert_eq!(parse_value(b"\\sp"), Some(b' '));
        assert_eq!(parse_value(b"0x1b"), Some(0x1b));
        assert_eq!(parse_value(b"A"), Some(b'A'));
        assert_eq!(parse_value(b"''"), Some(0));
        assert_eq!(parse_value(b"??"), None);
    }
}
