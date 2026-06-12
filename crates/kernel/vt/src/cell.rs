// Cell + Attr: one screen cell and the SGR rendition applied to it. Cells
// carry FULLY-RESOLVED 24-bit RGB (Linux per-cell attributes, truecolor-
// faithful): SGR 16/256-color indices resolve to RGB at set-time via the
// canonical `palette`; SGR 38;2/48;2 truecolor stores RGB verbatim. The
// renderer reads `cell.fg`/`cell.bg` directly — no palette lookup. `flags`
// packs the rendition bits + the wide-character occupancy bits (`57§9`).

use crate::palette::xterm_256_rgb;
use crate::vc::{DEFAULT_BG_RGB, DEFAULT_FG_RGB};

/// Flag bit: bold/bright intensity (SGR 1).
pub const ATTR_BOLD: u16 = 1;
/// Flag bit: underline (SGR 4).
pub const ATTR_UNDERLINE: u16 = 2;
/// Flag bit: reverse video (SGR 7).
pub const ATTR_REVERSE: u16 = 4;
/// Flag bit: faint/dim (SGR 2).
pub const ATTR_FAINT: u16 = 8;
/// Flag bit: italic (SGR 3).
pub const ATTR_ITALIC: u16 = 16;
/// Flag bit: blink (SGR 5).
pub const ATTR_BLINK: u16 = 32;
/// Flag bit: conceal/hidden (SGR 8).
pub const ATTR_CONCEAL: u16 = 64;
/// Flag bit: crossed-out/strike (SGR 9).
pub const ATTR_STRIKE: u16 = 128;
/// Flag bit: wide-char primary cell (East-Asian width 2; `57§9.2`).
pub const ATTR_WIDE: u16 = 256;
/// Flag bit: wide-char spacer (the second cell of a width-2 glyph).
pub const ATTR_WIDE_SPACER: u16 = 512;

/// Cell/cursor attribute: fg/bg as resolved 0x00RRGGBB RGB + rendition
/// flags. SGR index colors resolve to RGB at set-time (`set_fg_index`/
/// `set_bg_index`); truecolor SGR stores RGB directly. `bold` brightens a
/// basic 0..7 index to 8..15 at resolve time (VGA bright convention).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Attr {
    pub fg: u32,
    pub bg: u32,
    pub bold: bool,
    pub underline: bool,
    pub reverse: bool,
    pub faint: bool,
    pub italic: bool,
    pub blink: bool,
    pub conceal: bool,
    pub strike: bool,
}

impl Default for Attr {
    fn default() -> Self {
        Attr {
            fg: DEFAULT_FG_RGB,
            bg: DEFAULT_BG_RGB,
            bold: false,
            underline: false,
            reverse: false,
            faint: false,
            italic: false,
            blink: false,
            conceal: false,
            strike: false,
        }
    }
}

impl Attr {
    /// Pack the rendition flags into a u16 (`ATTR_*`). Wide-char bits are
    /// per-cell occupancy, not rendition, so they are NOT set here.
    /// # C: O(1).
    pub fn flags(self) -> u16 {
        let mut f = 0u16;
        if self.bold { f |= ATTR_BOLD; }
        if self.underline { f |= ATTR_UNDERLINE; }
        if self.reverse { f |= ATTR_REVERSE; }
        if self.faint { f |= ATTR_FAINT; }
        if self.italic { f |= ATTR_ITALIC; }
        if self.blink { f |= ATTR_BLINK; }
        if self.conceal { f |= ATTR_CONCEAL; }
        if self.strike { f |= ATTR_STRIKE; }
        f
    }

    /// Build an `Attr` from a `Cell`'s fg/bg RGB + packed flags. Wide-char
    /// occupancy bits do not map back to rendition.
    /// # C: O(1).
    pub fn from_cell(c: Cell) -> Self {
        Attr {
            fg: c.fg,
            bg: c.bg,
            bold: c.flags & ATTR_BOLD != 0,
            underline: c.flags & ATTR_UNDERLINE != 0,
            reverse: c.flags & ATTR_REVERSE != 0,
            faint: c.flags & ATTR_FAINT != 0,
            italic: c.flags & ATTR_ITALIC != 0,
            blink: c.flags & ATTR_BLINK != 0,
            conceal: c.flags & ATTR_CONCEAL != 0,
            strike: c.flags & ATTR_STRIKE != 0,
        }
    }

    /// Reset to SGR defaults (SGR 0).
    /// # C: O(1).
    pub fn reset(&mut self) {
        *self = Attr::default();
    }
}

/// One screen cell: a glyph codepoint, fully-resolved fg/bg 0x00RRGGBB, and
/// packed `ATTR_*` flags. A blank cell is `glyph == ' '` with the prevailing
/// attr. A width-2 glyph occupies a primary cell (`ATTR_WIDE`) plus a spacer
/// cell (`ATTR_WIDE_SPACER`) in the next column (`57§9.2`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Cell {
    pub glyph: u32,
    pub fg: u32,
    pub bg: u32,
    pub flags: u16,
}

impl Default for Cell {
    fn default() -> Self {
        Cell::blank(Attr::default())
    }
}

impl Cell {
    /// Blank cell carrying `attr` (used for erase/scroll fill).
    /// # C: O(1).
    pub fn blank(attr: Attr) -> Self {
        Cell { glyph: ' ' as u32, fg: attr.fg, bg: attr.bg, flags: attr.flags() }
    }

    /// Cell with `glyph` and `attr` applied.
    /// # C: O(1).
    pub fn glyph(glyph: u32, attr: Attr) -> Self {
        Cell { glyph, fg: attr.fg, bg: attr.bg, flags: attr.flags() }
    }

    /// Cell with `glyph`, `attr`, and extra occupancy `flags` OR'd in (e.g.
    /// `ATTR_WIDE` on a wide-char primary).
    /// # C: O(1).
    pub fn glyph_flags(glyph: u32, attr: Attr, extra: u16) -> Self {
        Cell { glyph, fg: attr.fg, bg: attr.bg, flags: attr.flags() | extra }
    }

    /// Spacer cell occupying the second column of a width-2 glyph. Renders
    /// as a blank carrying the primary's colors; flagged `ATTR_WIDE_SPACER`
    /// so erase/overwrite logic can find and clear its primary.
    /// # C: O(1).
    pub fn wide_spacer(attr: Attr) -> Self {
        Cell { glyph: ' ' as u32, fg: attr.fg, bg: attr.bg, flags: attr.flags() | ATTR_WIDE_SPACER }
    }

    /// Is this the primary cell of a width-2 glyph? # C: O(1).
    pub fn is_wide(self) -> bool { self.flags & ATTR_WIDE != 0 }

    /// Is this the spacer cell of a width-2 glyph? # C: O(1).
    pub fn is_wide_spacer(self) -> bool { self.flags & ATTR_WIDE_SPACER != 0 }
}
