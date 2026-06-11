// TIOCLINUX subfunction state + pure helpers (Linux
// drivers/tty/vt/{selection.c,vt_ioctl.c} + tty_io.c TIOCLINUX path).
//
// The ioctl marshalling lives in the kernel syscall glue (kernel-only); this
// module owns the kernel-global state those subfunctions mutate (selection
// buffer, word-select LUT, screen-blank flag, kmsg-redirect target VT) plus the
// PURE region-resolution + shift-state-mapping logic that is host-testable
// without a boot.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use sync::{Spinlock, TaskList as VtLockClass};

extern crate alloc;
use alloc::vec::Vec;

// ============================================================
// TIOCLINUX subfunction selectors (linux/include/uapi/linux/tiocl.h)
// ============================================================
pub const TIOCL_SETSEL:         u8 = 2;
pub const TIOCL_PASTESEL:       u8 = 3;
pub const TIOCL_UNBLANKSCREEN:  u8 = 4;
pub const TIOCL_SELLOADLUT:     u8 = 5;
pub const TIOCL_GETSHIFTSTATE:  u8 = 6;
pub const TIOCL_GETMOUSEREPORTING: u8 = 7;
pub const TIOCL_SETVESABLANK:   u8 = 10;
pub const TIOCL_SELMOUSEREPORT: u8 = 11; // (mouse report mode; unused here)
pub const TIOCL_GETFGCONSOLE:   u8 = 12;
pub const TIOCL_SCROLLCONSOLE:  u8 = 13;
pub const TIOCL_BLANKSCREEN:    u8 = 14;
pub const TIOCL_BLANKEDSCREEN:  u8 = 15;
pub const TIOCL_GETKMSGREDIRECT: u8 = 17;
pub const TIOCL_SETKMSGREDIRECT: u8 = 16;

// sel_mode values (TIOCL_SETSEL): char / word / line / clear / pointer.
pub const TIOCL_SELCHAR:    u16 = 0;
pub const TIOCL_SELWORD:    u16 = 1;
pub const TIOCL_SELLINE:    u16 = 2;

// ============================================================
// Kernel-global state
// ============================================================

/// Resolved selection text (Linux `vc_sel.buffer`). Set by TIOCL_SETSEL,
/// consumed by TIOCL_PASTESEL. Owned bytes (Latin-1 glyphs), no attrs.
static SELECTION: Spinlock<Vec<u8>, VtLockClass> = Spinlock::new(Vec::new());

/// Word-selection char-class LUT (Linux `inwordLut`): 256 bits / 32 bytes,
/// bit set = the char is a "word" char for double-click word selection.
/// Set by TIOCL_SELLOADLUT. Default matches Linux: alnum + 0xA0-0xFF + '_'.
static SEL_LUT: Spinlock<[u8; 32], VtLockClass> = Spinlock::new(default_lut());

/// Screen-blank flag (Linux `console_blanked`). TIOCL_BLANKSCREEN sets it,
/// TIOCL_UNBLANKSCREEN clears it. Observable via TIOCL_BLANKEDSCREEN.
/// NOTE: we have no DPMS / pixel-blank hardware path, so this is the stored
/// state only; UNBLANK forces a console repaint, BLANK records intent.
static BLANKED: AtomicBool = AtomicBool::new(false);

/// VESA blank interval in minutes (Linux `blankinterval`, TIOCL_SETVESABLANK).
/// Stored state — no hw blank timer drives it.
static BLANK_INTERVAL: AtomicU32 = AtomicU32::new(0);

/// kmsg-redirect target VT (Linux `kmsg_redirect`): 0 = current fg console.
/// Set by TIOCL_SETKMSGREDIRECT, read by TIOCL_GETKMSGREDIRECT.
static KMSG_REDIRECT: AtomicU8 = AtomicU8::new(0);

const fn default_lut() -> [u8; 32] {
    // bit i set ⇒ char i is a word char. Linux default: '0'..'9','A'..'Z',
    // 'a'..'z','_' and 0xA0..=0xFF. Build it const at compile time.
    let mut lut = [0u8; 32];
    let mut c = 0usize;
    while c < 256 {
        let w = (c >= b'0' as usize && c <= b'9' as usize)
            || (c >= b'A' as usize && c <= b'Z' as usize)
            || (c >= b'a' as usize && c <= b'z' as usize)
            || c == b'_' as usize
            || c >= 0xA0;
        if w { lut[c >> 3] |= 1 << (c & 7); }
        c += 1;
    }
    lut
}

// ---- accessors used by the kernel ioctl glue ----

/// Replace the stored selection buffer (TIOCL_SETSEL result). # C: O(n)
pub fn set_selection(bytes: Vec<u8>) { *SELECTION.lock() = bytes; }

/// Clone the stored selection buffer for paste (TIOCL_PASTESEL). # C: O(n)
pub fn selection() -> Vec<u8> { SELECTION.lock().clone() }

/// Load the word-select char-class LUT (TIOCL_SELLOADLUT). # C: O(1)
pub fn set_sel_lut(lut: [u8; 32]) { *SEL_LUT.lock() = lut; }

/// Snapshot the word-select LUT. # C: O(1)
pub fn sel_lut() -> [u8; 32] { *SEL_LUT.lock() }

/// Set the screen-blank flag (TIOCL_BLANKSCREEN / UNBLANK). # C: O(1)
pub fn set_blanked(v: bool) { BLANKED.store(v, Ordering::Release); }

/// Read the screen-blank flag (TIOCL_BLANKEDSCREEN). # C: O(1)
pub fn blanked() -> bool { BLANKED.load(Ordering::Acquire) }

/// Store the VESA blank interval in minutes (TIOCL_SETVESABLANK). # C: O(1)
pub fn set_blank_interval(mins: u32) { BLANK_INTERVAL.store(mins, Ordering::Release); }

/// Read the stored VESA blank interval. # C: O(1)
pub fn blank_interval() -> u32 { BLANK_INTERVAL.load(Ordering::Acquire) }

/// Set the kmsg-redirect target VT (TIOCL_SETKMSGREDIRECT). # C: O(1)
pub fn set_kmsg_redirect(vt: u8) { KMSG_REDIRECT.store(vt, Ordering::Release); }

/// Read the kmsg-redirect target VT (TIOCL_GETKMSGREDIRECT). # C: O(1)
pub fn kmsg_redirect() -> u8 { KMSG_REDIRECT.load(Ordering::Acquire) }

// ============================================================
// PURE helpers (host-testable)
// ============================================================

/// Map the keyboard-driver modifier bits to the Linux TIOCL_GETSHIFTSTATE
/// byte (Linux `getshiftstate`: bit0 SHIFT, bit1 ALTGR, bit2 CTRL, bit3 ALT).
/// `mods` is the `drv_virtio_input::keymap::Mods` raw bitmask
/// (SHIFT=1<<0, CTRL=1<<1, ALT=1<<2, ALTGR=1<<3, …). Pure so the bit mapping
/// can be unit-tested without a boot. # C: O(1)
pub fn linux_shift_state(mods: u8) -> u8 {
    const M_SHIFT: u8 = 1 << 0;
    const M_CTRL:  u8 = 1 << 1;
    const M_ALT:   u8 = 1 << 2;
    const M_ALTGR: u8 = 1 << 3;
    const L_SHIFT: u8 = 1; // (1<<KG_SHIFT)
    const L_ALTGR: u8 = 2; // (1<<KG_ALTGR)
    const L_CTRL:  u8 = 4; // (1<<KG_CTRL)
    const L_ALT:   u8 = 8; // (1<<KG_ALT)
    let mut out = 0u8;
    if mods & M_SHIFT != 0 { out |= L_SHIFT; }
    if mods & M_ALTGR != 0 { out |= L_ALTGR; }
    if mods & M_CTRL  != 0 { out |= L_CTRL; }
    if mods & M_ALT   != 0 { out |= L_ALT; }
    out
}

/// Linear cell index for `(x, y)` on a `cols`-wide grid. # C: O(1)
#[inline]
fn cell_index(x: u16, y: u16, cols: u16) -> usize { y as usize * cols as usize + x as usize }

/// Resolve a TIOCL_SETSEL rectangular region into the inclusive linear cell
/// range `[start, end]` over a `rows`×`cols` grid, mirroring Linux
/// `set_selection_kernel` / `highlight`:
/// - coords are CLAMPED to the grid (xs/xe to cols-1, ys/ye to rows-1);
/// - the region runs from the (ys,xs) cell to the (ye,xe) cell in reading
///   order; if the end precedes the start they are swapped;
/// - `TIOCL_SELLINE` (2) extends to whole lines: start→column 0 of its row,
///   end→last column of its row;
/// - char (0) / word (1) select the exact cell span (word refinement is the
///   caller's; this returns the raw clamped span which word then widens via the
///   LUT — char and line are exact here).
///
/// Returns `None` for an empty grid. Pure → host-testable. # C: O(1)
pub fn resolve_selection(
    xs: u16, ys: u16, xe: u16, ye: u16, sel_mode: u16,
    rows: u16, cols: u16,
) -> Option<(usize, usize)> {
    if rows == 0 || cols == 0 { return None; }
    let cx = |x: u16| x.min(cols - 1);
    let cy = |y: u16| y.min(rows - 1);
    let (mut sx, mut sy) = (cx(xs), cy(ys));
    let (mut ex, mut ey) = (cx(xe), cy(ye));
    let mut start = cell_index(sx, sy, cols);
    let mut end = cell_index(ex, ey, cols);
    if end < start {
        core::mem::swap(&mut start, &mut end);
        core::mem::swap(&mut sx, &mut ex);
        core::mem::swap(&mut sy, &mut ey);
    }
    if sel_mode == TIOCL_SELLINE {
        // whole-line: start to col 0 of its row, end to last col of its row.
        start = cell_index(0, sy, cols);
        end = cell_index(cols - 1, ey, cols);
    }
    Some((start, end))
}

/// True if glyph byte `g` is a word char per the loaded LUT (used by
/// word-mode selection widening). # C: O(1)
pub fn is_word_char(lut: &[u8; 32], g: u8) -> bool {
    (lut[(g as usize) >> 3] >> (g as usize & 7)) & 1 != 0
}

/// Widen `[start, end]` to whole words for TIOCL_SELWORD (Linux double-click):
/// move `start` left while the preceding cell on its row is a word char, and
/// `end` right while the following cell on its row is a word char. `screen` is
/// the rows*cols glyph dump (Latin-1). Pure → host-testable. # C: O(span)
pub fn widen_to_words(
    screen: &[u8], lut: &[u8; 32], cols: u16, start: usize, end: usize,
) -> (usize, usize) {
    let cols = cols as usize;
    if cols == 0 || screen.is_empty() { return (start, end); }
    let row_of = |i: usize| i / cols;
    let mut s = start.min(screen.len().saturating_sub(1));
    let mut e = end.min(screen.len().saturating_sub(1));
    // Only widen if the selection itself starts on a word char (Linux refuses
    // to grow a selection anchored on whitespace).
    if !is_word_char(lut, screen[s]) { return (s, e); }
    while s > 0 && row_of(s - 1) == row_of(s) && is_word_char(lut, screen[s - 1]) { s -= 1; }
    while e + 1 < screen.len() && row_of(e + 1) == row_of(e) && is_word_char(lut, screen[e + 1]) { e += 1; }
    (s, e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shift_state_maps_each_modifier() {
        // Mods: SHIFT=1, CTRL=2, ALT=4, ALTGR=8.
        assert_eq!(linux_shift_state(0), 0);
        assert_eq!(linux_shift_state(1), 1, "SHIFT → bit0");
        assert_eq!(linux_shift_state(8), 2, "ALTGR → bit1");
        assert_eq!(linux_shift_state(2), 4, "CTRL → bit2");
        assert_eq!(linux_shift_state(4), 8, "ALT → bit3");
        // Combined SHIFT|CTRL → 1|4 = 5.
        assert_eq!(linux_shift_state(1 | 2), 5);
        // SHIFT|CTRL|ALT|ALTGR → 1|4|8|2 = 15.
        assert_eq!(linux_shift_state(1 | 2 | 4 | 8), 15);
        // Unrelated bits (CAPS=1<<5, NUM=1<<6) are ignored.
        assert_eq!(linux_shift_state(1 << 5 | 1 << 6), 0);
    }

    #[test]
    fn selection_char_span_same_row() {
        // 25x80 grid, select cols 5..10 on row 3.
        let r = resolve_selection(5, 3, 10, 3, TIOCL_SELCHAR, 25, 80).unwrap();
        assert_eq!(r, (3 * 80 + 5, 3 * 80 + 10));
    }

    #[test]
    fn selection_spans_multiple_rows() {
        let r = resolve_selection(2, 1, 4, 2, TIOCL_SELCHAR, 25, 80).unwrap();
        assert_eq!(r, (1 * 80 + 2, 2 * 80 + 4));
    }

    #[test]
    fn selection_swaps_reversed_endpoints() {
        // end precedes start → swap so start <= end.
        let r = resolve_selection(10, 3, 5, 3, TIOCL_SELCHAR, 25, 80).unwrap();
        assert_eq!(r, (3 * 80 + 5, 3 * 80 + 10));
    }

    #[test]
    fn selection_clamps_out_of_range_coords() {
        // xs/xe beyond cols, ys/ye beyond rows → clamp to last col/row.
        let r = resolve_selection(200, 99, 250, 99, TIOCL_SELCHAR, 25, 80).unwrap();
        assert_eq!(r, (24 * 80 + 79, 24 * 80 + 79));
    }

    #[test]
    fn selection_line_mode_extends_full_rows() {
        // line mode: start col 0 of its row, end last col of its row.
        let r = resolve_selection(5, 1, 7, 2, TIOCL_SELLINE, 25, 80).unwrap();
        assert_eq!(r, (1 * 80, 2 * 80 + 79));
    }

    #[test]
    fn selection_empty_grid() {
        assert!(resolve_selection(0, 0, 0, 0, TIOCL_SELCHAR, 0, 80).is_none());
        assert!(resolve_selection(0, 0, 0, 0, TIOCL_SELCHAR, 25, 0).is_none());
    }

    #[test]
    fn word_lut_default_classifies() {
        let lut = default_lut();
        assert!(is_word_char(&lut, b'a'));
        assert!(is_word_char(&lut, b'Z'));
        assert!(is_word_char(&lut, b'0'));
        assert!(is_word_char(&lut, b'_'));
        assert!(!is_word_char(&lut, b' '));
        assert!(!is_word_char(&lut, b'.'));
    }

    #[test]
    fn word_widen_grows_to_word_boundaries() {
        // one row of 16 cols: "  hello world   " — select inside "hello".
        let cols: u16 = 16;
        let screen = b"  hello world   ";
        let lut = default_lut();
        // anchor on 'l' at index 4 (cell 4 = 'l'), end at index 4.
        let (s, e) = widen_to_words(screen, &lut, cols, 4, 4);
        // "hello" spans indices 2..=6.
        assert_eq!((s, e), (2, 6));
    }

    #[test]
    fn word_widen_does_not_cross_row() {
        // 4-col rows: "ab  " / "cdef" — selecting last col of row0 ('b'@1)
        // must not pull cells from row1.
        let cols: u16 = 4;
        let screen = b"ab  cdef";
        let lut = default_lut();
        let (s, e) = widen_to_words(screen, &lut, cols, 1, 1);
        assert_eq!((s, e), (0, 1), "stays within row 0");
    }

    #[test]
    fn word_widen_refuses_whitespace_anchor() {
        let cols: u16 = 16;
        let screen = b"  hello world   ";
        let lut = default_lut();
        // index 0 is a space → no widening.
        assert_eq!(widen_to_words(screen, &lut, cols, 0, 0), (0, 0));
    }
}
