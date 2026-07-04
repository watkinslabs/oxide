// ECMA-48 / vt102 emulator (Linux `vt.c` `do_con_trol`). Relocated and
// adapted from `fbcon::Console`'s parser: same CSI/SGR/ESC/OSC/UTF-8
// state machine, but it mutates a `Vc` cell grid instead of blitting
// pixels. One `feed(&mut Vc, byte)` advances the machine.
//
// Parity scope (matches fbcon + standard vt102): printable w/ UTF-8 +
// DECAWM autowrap, LF/CR/BS/TAB/BEL, CSI cursor moves
// (CUU/CUD/CUF/CUB/CNL/CPL/CHA/VPA/CUP/HVP), ED(J)/EL(K), SGR(m) incl
// 16-color + bright + 256-color + truecolor parse, DECSC/DECRC (ESC 7/8
// and CSI s/u), IND/RI (ESC D/M), RIS (ESC c), DECSET/RST autowrap
// (?7h/?7l), scroll region (CSI r), IL/DL/ICH/DCH, SU/SD. Unknown
// sequences are tolerated (consumed, no panic).

mod actions;
mod core;
mod csi;
mod osc;
mod parser;
mod sgr;
use osc::OSC_CAP;

/// Parser superstate (mirrors fbcon `CsiState`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CsiState {
    Ground,
    Esc,
    CsiParam,
    CsiInter,
    /// `ESC (` / `)` / `*` / `+` — awaiting the charset designator byte.
    Charset,
    /// `ESC #` — awaiting the DEC private byte (e.g. `8` = DECALN).
    Hash,
    Osc,
    OscString,
    DcsString,
}

impl Default for CsiState {
    fn default() -> Self {
        CsiState::Ground
    }
}

const MAX_PARAMS: usize = 16;
const MAX_INTER: usize = 4;

/// Reply-buffer capacity. Longest reply is CPR `ESC[<r>;<c>R` — at most
/// `2 + 5 + 1 + 5 + 1` bytes for 16-bit row/col decimals. 24 is ample.
const REPLY_CAP: usize = 24;

/// An owned, drained terminal answerback (DSR/CPR reply). Carries the
/// fixed-size buffer + valid length so the caller can drop the borrow on
/// the `Emulator` before injecting the bytes into the tty input ring.
#[derive(Copy, Clone)]
pub struct ReplyBytes {
    bytes: [u8; REPLY_CAP],
    len: usize,
}

impl ReplyBytes {
    /// The valid reply bytes (empty when no reply was pending). # C: O(1).
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Whether any reply is pending. # C: O(1).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Emulator parser state. Holds no screen data — that lives in `Vc`.
#[derive(Clone, Debug)]
pub struct Emulator {
    state: CsiState,
    params: [u32; MAX_PARAMS],
    /// Number of params seen minus 1 (index of the current param).
    param_count: u8,
    /// Whether the current param slot has received any digit.
    param_seen: bool,
    intermediate: [u8; MAX_INTER],
    inter_count: u8,
    private: bool,
    /// Which Gn slot an `ESC ( / ) / * / +` designator targets: the raw
    /// intermediate byte (`(`=G0, `)`=G1, `*`=G2, `+`=G3). VT100/VT102
    /// only render via G0/G1 (GL), but we accept all four designators.
    charset_slot: u8,
    utf8_pending: [u8; 4],
    utf8_len: u8,
    /// Linux console font-mapping mode (`SGR 11`/`12`, `vt.c` disp_ctrl):
    /// when set, incoming bytes are NOT UTF-8 decoded — each raw byte maps
    /// through CP437 to a glyph (this is how ncurses on `TERM=linux` draws
    /// box-drawing: `smacs`=`\E[11m`, raw CP437 bytes, `rmacs`=`\E[10m`).
    disp_ctrl: bool,
    /// `SGR 12` second alternate font: like `disp_ctrl` but XOR each byte
    /// with 0x80 first (Linux `toggle_meta`).
    toggle_meta: bool,
    /// IRM insert/replace mode (ANSI mode 4, `CSI 4h`/`CSI 4l`). When set,
    /// each printed glyph shifts the rest of the line right by its width
    /// before being placed (Linux `vt.c` `decim`); default replace.
    insert_mode: bool,
    /// DECCKM (`?1h`/`?1l`): when set, cursor keys send `ESC O x` (SS3)
    /// instead of `ESC [ x` (CSI). Read by the keyboard layer for the
    /// FOREGROUND VT (Linux `applkey` consults `vc_decckm`). `57§8`.
    app_cursor: bool,
    /// Bracketed paste (`?2004h`/`l`): when set, pasted text (selection
    /// paste) is wrapped in `ESC [ 200 ~` … `ESC [ 201 ~` so the receiving
    /// program can distinguish it from typed input. `57§8`.
    bracketed_paste: bool,
    /// Saw `ESC` (0x1b) inside an OSC/DCS string: the next byte decides if
    /// this is a 7-bit ST (`ESC \`) terminator or just payload. Prevents a
    /// bare `\` in a title from ending the string early (`57§14`).
    str_esc: bool,
    /// Collected OSC payload bytes (between `ESC ]` and the terminator),
    /// parsed by `osc::osc_dispatch` for color-control OSCs.
    osc_buf: [u8; OSC_CAP],
    osc_len: u16,
    /// Pending terminal answerback bytes (DSR/CPR reply per `CSI n`). The
    /// console driver drains this after each `feed`/`feed_bytes` and
    /// injects it into the tty INPUT ring so the program that issued the
    /// query reads its reply back (Linux `respond_string` →
    /// `tty_insert_flip_string`). Pure data here — no I/O in `vtdata`.
    reply: [u8; REPLY_CAP],
    reply_len: u8,
}

impl Default for Emulator {
    fn default() -> Self {
        Emulator {
            state: CsiState::Ground,
            params: [0; MAX_PARAMS],
            param_count: 0,
            param_seen: false,
            intermediate: [0; MAX_INTER],
            inter_count: 0,
            private: false,
            charset_slot: 0,
            utf8_pending: [0; 4],
            utf8_len: 0,
            disp_ctrl: false,
            toggle_meta: false,
            insert_mode: false,
            app_cursor: false,
            bracketed_paste: false,
            str_esc: false,
            osc_buf: [0; OSC_CAP],
            osc_len: 0,
            reply: [0; REPLY_CAP],
            reply_len: 0,
        }
    }
}
