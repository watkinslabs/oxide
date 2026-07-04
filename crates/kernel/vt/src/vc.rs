// `Vc` — per-VT screen buffer (Linux `struct vc_data`). Cell grid +
// cursor + current SGR attr + saved cursor + modes (DECAWM…) + G0/G1
// charset. The emulator (emulator.rs) is the only mutator of the grid
// beyond the structural helpers here. No rendering: a `Cell` carries a
// glyph codepoint + packed attr; consw/fbcon (T2) blits them later.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use crate::palette::VGA_PALETTE;

mod core;
mod ops;
mod scroll;
mod view;

/// Number of virtual terminals (Linux `MAX_NR_CONSOLES` default).
/// # C: const.
pub const N_VT: usize = 63;

/// Default tab stop width (DEC/VT100 hardware tabs every 8 columns).
pub const TAB_WIDTH: u16 = 8;

/// Selected character set for a G0/G1 slot. VT100/VT102 support ASCII
/// (DEC `B`) and the DEC Special Graphics line-drawing set (DEC `0`).
/// # C: const enum.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Charset {
    /// US ASCII (`ESC ( B`). Codepoints pass through unchanged.
    Ascii,
    /// DEC Special Graphics + line drawing (`ESC ( 0`). Codepoints
    /// 0x60..0x7e map to Unicode box-drawing/symbol glyphs.
    DecSpecial,
}

impl Default for Charset {
    fn default() -> Self {
        Charset::Ascii
    }
}

/// DEC Special Graphics map: input byte `0x60 + i` → Unicode codepoint.
/// Indexed `[byte - 0x60]` for bytes in `0x60..=0x7e`. Matches the VT100
/// special-graphics ROM (DEC STD 070) as adopted by xterm/Linux `vt.c`.
/// `0x00` entries fall through to the literal byte (no special glyph).
/// # C: const table.
pub const DEC_SPECIAL_GRAPHICS: [u32; 0x1f] = [
    0x0020, // 0x60 ` blank (DEC: no glyph; xterm: space)
    0x25c6, // 0x61 a ◆ diamond
    0x2592, // 0x62 b ▒ checkerboard (medium shade)
    0x2409, // 0x63 c ␉ HT symbol
    0x240c, // 0x64 d ␌ FF symbol
    0x240d, // 0x65 e ␍ CR symbol
    0x240a, // 0x66 f ␊ LF symbol
    0x00b0, // 0x67 g ° degree
    0x00b1, // 0x68 h ± plus/minus
    0x2424, // 0x69 i ␤ NL symbol
    0x2518, // 0x6a j ┘ lower-right corner
    0x2510, // 0x6b k ┐ upper-right corner
    0x250c, // 0x6c l ┌ upper-left corner
    0x2514, // 0x6d m └ lower-left corner
    0x253c, // 0x6e n ┼ crossing
    0x23ba, // 0x6f o ⎺ scan line 1 (top)
    0x23bb, // 0x70 p ⎻ scan line 3
    0x2500, // 0x71 q ─ horizontal line (scan line 5, middle)
    0x23bc, // 0x72 r ⎼ scan line 7
    0x23bd, // 0x73 s ⎽ scan line 9 (bottom)
    0x251c, // 0x74 t ├ left tee
    0x2524, // 0x75 u ┤ right tee
    0x2534, // 0x76 v ┴ bottom tee
    0x252c, // 0x77 w ┬ top tee
    0x2502, // 0x78 x │ vertical line
    0x2264, // 0x79 y ≤ less-than-or-equal
    0x2265, // 0x7a z ≥ greater-than-or-equal
    0x03c0, // 0x7b { π pi
    0x2260, // 0x7c | ≠ not-equal
    0x00a3, // 0x7d } £ sterling
    0x00b7, // 0x7e ~ · middle dot
];

/// Map one codepoint through the active GL charset. ASCII passes through;
/// DEC Special Graphics translates 0x60..0x7e per `DEC_SPECIAL_GRAPHICS`.
/// # C: O(1).
#[inline]
pub fn map_charset(cp: u32, set: Charset) -> u32 {
    match set {
        Charset::Ascii => cp,
        Charset::DecSpecial => {
            if (0x60..=0x7e).contains(&cp) {
                DEC_SPECIAL_GRAPHICS[(cp - 0x60) as usize]
            } else {
                cp
            }
        }
    }
}

/// Default foreground SGR color index (light grey, VGA 7).
pub const DEFAULT_FG: u8 = 7;
/// Default background SGR color index (black, VGA 0).
pub const DEFAULT_BG: u8 = 0;

/// Default foreground as resolved 0x00RRGGBB (light grey, VGA 7).
/// # C: const.
pub const DEFAULT_FG_RGB: u32 =
    ((VGA_PALETTE[DEFAULT_FG as usize][0] as u32) << 16)
        | ((VGA_PALETTE[DEFAULT_FG as usize][1] as u32) << 8)
        | (VGA_PALETTE[DEFAULT_FG as usize][2] as u32);
/// Default background as resolved 0x00RRGGBB (black, VGA 0).
/// # C: const.
pub const DEFAULT_BG_RGB: u32 =
    ((VGA_PALETTE[DEFAULT_BG as usize][0] as u32) << 16)
        | ((VGA_PALETTE[DEFAULT_BG as usize][1] as u32) << 8)
        | (VGA_PALETTE[DEFAULT_BG as usize][2] as u32);

/// Bound on scrolled-off history rows kept per `Vc`. At up-to-`cols`
/// cells/row this is the dominant `Vc` allocation; fine for one active
/// VT (per-VT lazy alloc is a later task).
pub const SCROLLBACK_LINES: usize = 1000;

// `Attr` + `Cell` live in `cell.rs`; re-export so `vc::Attr` and external
// `vtdata::Attr` paths keep resolving (57§9).
pub use crate::cell::{
    Attr, Cell, ATTR_BLINK, ATTR_BOLD, ATTR_CONCEAL, ATTR_FAINT, ATTR_ITALIC,
    ATTR_REVERSE, ATTR_STRIKE, ATTR_UNDERLINE, ATTR_WIDE, ATTR_WIDE_SPACER,
};


/// Per-VT screen buffer + emulator-visible state.
#[derive(Clone, Debug)]
pub struct Vc {
    pub cols: u16,
    pub rows: u16,
    cells: Vec<Cell>,
    /// Cursor column [0,cols).
    pub x: u16,
    /// Cursor row [0,rows).
    pub y: u16,
    /// Current SGR attribute applied to printed glyphs.
    pub attr: Attr,
    /// Saved cursor state (DECSC / ESC 7): position + SGR attr + both
    /// charset slots + GL selector + origin mode + pending-wrap. A VT100
    /// DECSC saves the FULL graphic rendition + character-set state, not
    /// just the position (DEC STD 070 / VT100 user guide).
    pub saved_x: u16,
    pub saved_y: u16,
    pub saved_attr: Attr,
    saved_g0: Charset,
    saved_g1: Charset,
    saved_gl: u8,
    saved_origin: bool,
    saved_wrap_pending: bool,
    /// G0 charset slot (`ESC ( B` / `ESC ( 0`). Default ASCII.
    pub g0: Charset,
    /// G1 charset slot (`ESC ) B` / `ESC ) 0`). Default ASCII.
    pub g1: Charset,
    /// GL selector: 0 = G0 (after SI `\x0f`), 1 = G1 (after SO `\x0e`).
    pub gl: u8,
    /// DECOM origin mode (`?6h/l`): cursor addressing relative to the
    /// scroll region and confined to it when set. Default off (absolute).
    pub origin_mode: bool,
    /// DECTCEM cursor-visible flag (`?25h/l`). Renderer-only; default on.
    pub cursor_visible: bool,
    /// Tab-stop bitmap, one bool per column (true = stop set). HTS/TBC
    /// edit it; HT advances to the next set stop. Default every 8 cols.
    tab_stops: Vec<bool>,
    /// DECAWM autowrap mode (default on, Linux/xterm default).
    pub autowrap: bool,
    /// Deferred-wrap latch: set after printing into the last column with
    /// autowrap on; the NEXT printable wraps first (Linux/xterm
    /// pending-wrap semantics so the rightmost column is usable).
    pub wrap_pending: bool,
    /// Top of the scroll region (inclusive), 0-based. Default 0.
    pub scroll_top: u16,
    /// Bottom of the scroll region (inclusive), 0-based. Default rows-1.
    pub scroll_bot: u16,
    /// Per-row dirty flags (len == rows). A row is marked when any cell
    /// in it changes; the renderer (`consw::render`) blits dirty rows
    /// then clears the marks. Bridges the emulator (data) to consw
    /// (pixels) without the emulator depending on a concrete renderer.
    dirty: Vec<bool>,
    /// Set when the cursor moves or its row changes; the renderer
    /// repaints the cursor cell and clears it.
    cursor_dirty: bool,
    /// Position of the cursor block last drawn by the renderer. When the
    /// cursor moves, the renderer must first repaint THIS cell with its
    /// normal (non-reverse) attributes so the reverse-video block leaves
    /// no artifact behind (Linux fbcon erases the prior cursor cell before
    /// drawing the new one). `None` = no cursor block currently on screen.
    last_cursor: Option<(u16, u16)>,
    /// Scrolled-off rows, oldest at the front. Each entry is a full row
    /// of `cols` cells. Bounded by `SCROLLBACK_LINES` (evict oldest).
    history: VecDeque<Vec<Cell>>,
    /// Lines scrolled back: 0 = live bottom, N = N lines into history.
    /// Clamped to `[0, history.len()]`. Output/echo snaps it to 0.
    view_offset: usize,
    /// Alternate screen buffer (`CSI ?47/?1047/?1049h`). `Some` while on the
    /// alt screen, holding the saved MAIN-screen cells + cursor/attr to
    /// restore on `…l`. Full-screen apps (htop/top/vim/less) draw their UI on
    /// the alt screen, then restore the shell on exit. Linux
    /// `drivers/tty/vt/vt.c` `set_mode`/`save_screen`.
    alt_screen: Option<AltScreen>,
    /// Active 256-color palette (index → 0x00RRGGBB). SGR index colors and
    /// `38;5`/`48;5` resolve through THIS table at apply time, so `OSC 4`
    /// palette redefinition affects glyphs printed afterward (`57§14`).
    /// Initialized to the xterm/VGA defaults (`palette::xterm_256_rgb`).
    palette: [u32; 256],
    /// Default fg/bg (`OSC 10`/`11`, SGR 39/49 target). Distinct from the
    /// const `DEFAULT_*_RGB` so `OSC 10/11` can redefine them per VT.
    default_fg: u32,
    default_bg: u32,
}

/// The xterm/VGA-default 256-entry palette. # C: O(256).
fn default_palette() -> [u32; 256] {
    let mut p = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        p[i] = crate::palette::xterm_256_rgb(i as u32);
        i += 1;
    }
    p
}

/// Saved MAIN-screen state captured on alt-screen entry. # C: O(cols*rows).
#[derive(Clone, Debug)]
struct AltScreen {
    cells: Vec<Cell>,
    x: u16,
    y: u16,
    attr: Attr,
}

/// Default tab-stop bitmap: a stop every `TAB_WIDTH` columns (col 0 has
/// no stop; HT always moves at least one column). # C: O(cols).
fn default_tab_stops(cols: u16) -> Vec<bool> {
    let mut v = vec![false; cols as usize];
    let mut c = TAB_WIDTH;
    while (c as usize) < v.len() {
        v[c as usize] = true;
        c += TAB_WIDTH;
    }
    v
}
