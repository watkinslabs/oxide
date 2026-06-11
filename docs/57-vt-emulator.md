# 57 VT Emulator (ECMA-48 / VT100 / VT220 / xterm command interpreter)

DRAFT 2026-06-11. Dep:`01`,`02`,`07`,`08`,`28`,`49`,`50`,`55`. Provides: the escape/CSI/SGR/OSC interpreter that turns a tty byte stream into `Vc` grid mutations. Backend for every `/dev/tty<N>` glyph render (`49` fbcon) and serial console (`28`).

Scope: the terminal-emulation *command set* and *cell model*. NOT the VT multiplexer (switching, ioctls, keyboard — `50`), NOT color/font upload (`55`), NOT line discipline (`28`). One emulator instance per VT; `50` owns the instances.

Implementation: `crates/kernel/vt/{emulator.rs,vc.rs,palette.rs}`.

## 1 Architecture invariant (frozen intent)

1. **Byte-at-a-time state machine. No regex, no line buffering, no `alloc` on the feed path.** `#![no_std]`; the interpreter consumes one `u8` and mutates `Vc` in place. A regex/line-split tokenizer (as in host emulators that target std) is forbidden — it cannot run in-kernel and mis-handles sequences split across read() boundaries.
2. Partial sequences survive chunk boundaries by living in the state machine, not a re-fed string buffer. `feed_bytes` is resumable: feed `\x1b[`, then `31m` in a later call → same effect as one call.
3. Unknown finals/params are tolerated (consumed, no effect) — never panic, never desync. A malformed sequence resets to `Ground` at the first byte that cannot extend it.
4. Reference for *coverage* (which sequences exist): ECMA-48, `xterm` ctlseqs, Linux `drivers/tty/vt/vt.c`. Host emulators may be read for the command list, but their architecture (regex, GC'd strings) and their bugs (e.g. CNL implemented as cursor-up) are explicitly NOT replicated.

## 2 Parser states

| State | Enter on | Consumes | Exit |
|---|---|---|---|
| `Ground` | start / any reset | printable → glyph; C0/C1 → control | stays unless ESC/C1 |
| `Esc` | `0x1b` | intermediate/final of a non-CSI escape | → state per dispatch |
| `CsiParam` | `ESC [` | `0x30..0x3f` (digits `;` `:` `<=>?`) | `<0x40` intermediate → `CsiInter`; `0x40..0x7e` final → exec |
| `CsiInter` | `CSI` + `0x20..0x2f` | `0x20..0x2f` | `0x40..0x7e` final → exec |
| `Osc` | `ESC ]` | first byte routes | → `OscString` |
| `OscString` | OSC body | bytes until `BEL`/`ST` | `Ground` |
| `DcsString` | `ESC P` | bytes until `ST` | `Ground` |
| `Hash` | `ESC #` | one final (`8` = DECALN) | `Ground` |
| `Utf8` | UTF-8 lead in `Ground` | continuation bytes | emit glyph → `Ground` |

`CAN`(0x18)/`SUB`(0x1a) abort any sequence → `Ground` (SUB emits U+FFFD). `ESC` mid-sequence restarts at `Esc`.

## 3 C0 / C1 controls

| Byte | Name | Effect |
|---|---|---|
| `0x07` | BEL | bell (`50§16`); no screen change |
| `0x08` | BS | cursor left 1, clamp at col 0 |
| `0x09` | HT | cursor → next tab stop (`§9`), clamp at right margin |
| `0x0a`/`0x0b`/`0x0c` | LF/VT/FF | line feed (scroll if at margin bottom); CR too iff LNM/`linux` newline mode |
| `0x0d` | CR | cursor → col 0 |
| `0x0e` | SO | invoke G1 into GL |
| `0x0f` | SI | invoke G0 into GL |
| `0x1b` | ESC | → `Esc` |
| `0x84` | IND | index (down, scroll at bottom) |
| `0x85` | NEL | CR + index |
| `0x88` | HTS | set tab stop at cursor |
| `0x8d` | RI | reverse index (up, scroll at top) |
| `0x9b` | CSI | → `CsiParam` (8-bit) |
| `0x9c` | ST | terminate OSC/DCS |
| `0x9d` | OSC | → `Osc` (8-bit) |

## 4 ESC (non-CSI) finals

| Final | Name | Effect |
|---|---|---|
| `7` | DECSC | save cursor + attr + charset |
| `8` | DECRC | restore the DECSC state |
| `D` | IND | index |
| `E` | NEL | next line |
| `M` | RI | reverse index |
| `c` | RIS | full reset (clear, home, default attr, tabs, modes) |
| `( ) * +` | SCS | designate G0/G1/G2/G3 charset (next byte: `B`=ASCII, `0`=DEC special, `A`=UK) |
| `# 8` | DECALN | fill screen with `E` (alignment test) |
| `=` / `>` | DECKPAM / DECKPNM | keypad application / numeric mode |

## 5 CSI finals

Param defaults in `[]`. Coordinates 1-based on the wire, 0-based internally.

| Final | Name | Params | Effect |
|---|---|---|---|
| `A` | CUU | `[1]` | cursor up |
| `B` | CUD | `[1]` | cursor down |
| `C` | CUF | `[1]` | cursor right (clears pending-wrap) |
| `D` | CUB | `[1]` | cursor left |
| `E` | CNL | `[1]` | cursor down N, col 0 |
| `F` | CPL | `[1]` | cursor up N, col 0 |
| `G`/`` ` `` | CHA/HPA | `[1]` | cursor to absolute col |
| `d` | VPA | `[1]` | cursor to absolute row |
| `H`/`f` | CUP/HVP | `[1;1]` | cursor to row;col |
| `J` | ED | `[0]` | erase 0=below 1=above 2=all 3=all+scrollback |
| `K` | EL | `[0]` | erase 0=right 1=left 2=line |
| `X` | ECH | `[1]` | erase N chars at cursor (no shift) |
| `P` | DCH | `[1]` | delete N chars (shift left, blank fill) |
| `@` | ICH | `[1]` | insert N blanks (shift right) |
| `L` | IL | `[1]` | insert N blank lines in region |
| `M` | DL | `[1]` | delete N lines in region |
| `S` | SU | `[1]` | scroll region up N |
| `T` | SD | `[1]` | scroll region down N |
| `r` | DECSTBM | `[1;rows]` | set scroll region top;bottom |
| `s` | SCP | — | save cursor (ANSI.SYS) |
| `u` | RCP | — | restore cursor (ANSI.SYS) |
| `n` | DSR | `[0]` | 5→`\e[0n` (OK); 6→CPR `\e[row;colR` (`§13`) |
| `g`/`W` | TBC | `[0]` | 0=clear stop at cursor; 3=clear all |
| ` q` | DECSCUSR | `[1]` | cursor shape (block/underline/bar, blink) |
| `h`/`l` | SM/RM, DECSET/DECRST | — | mode set/reset (`§7`,`§8`) |
| `m` | SGR | `[0]` | graphic rendition (`§6`) |

`?`-prefixed `h`/`l` = DEC private (`§8`); bare = ANSI mode (`§7`).

## 6 SGR

| Code | Effect | Code | Effect |
|---|---|---|---|
| 0 | reset all | 27 | reverse off |
| 1 | bold | 28 | reveal (conceal off) |
| 2 | faint | 29 | strike off |
| 3 | italic | 30–37 | fg basic 0–7 |
| 4 | underline | 38;5;N | fg 256-color |
| 5 | blink | 38;2;r;g;b | fg truecolor |
| 7 | reverse | 39 | fg default |
| 8 | conceal | 40–47 | bg basic 0–7 |
| 9 | strike | 48;5;N | bg 256-color |
| 21 | double-underline (→ underline) | 48;2;r;g;b | bg truecolor |
| 22 | bold+faint off | 49 | bg default |
| 23 | italic off | 90–97 | fg bright 8–15 |
| 24 | underline off | 100–107 | bg bright 8–15 |
| 25 | blink off | | |

Bare `CSI m` ≡ `CSI 0 m`. 256-index and truecolor resolve to RGB at apply time and are stored as RGB in the cell attr (the palette is consulted once). Indexed colors track the active palette (`55`).

## 7 ANSI modes (SM/RM, no `?`)

| Mode | Name | Effect |
|---|---|---|
| 4 | IRM | insert vs replace on print |
| 20 | LNM | LF also does CR |

## 8 DEC private modes (DECSET/DECRST, `?`)

| Mode | Name | set / reset |
|---|---|---|
| 1 | DECCKM | cursor keys send app / cursor sequences |
| 7 | DECAWM | autowrap on / off |
| 12 | — | cursor blink on / off |
| 25 | DECTCEM | cursor visible / hidden |
| 1000/1002/1003 | mouse | report mode (button/motion/any) |
| 1006 | — | SGR mouse encoding |
| 1047 | — | alt screen (no save) |
| 1048 | — | save/restore cursor only |
| 1049 | — | save cursor + alt screen (`§11`) |
| 2004 | — | bracketed paste — wrap pasted input in `\e[200~`…`\e[201~` |

## 9 Cell & grid model

`Vc` = `cols × rows` flat `Cell` vec + cursor (x,y) + saved cursor + attr + scroll region + tab stops + scrollback ring (`49`). `Cell` = `{ cp: char, attr: Attr, width: CellWidth }`. `Attr` = `{ fg: Rgb, bg: Rgb, flags }`; flags = bold|faint|italic|underline|blink|reverse|conceal|strike|wide|wide_spacer.

### 9.1 Tab stops
Bool-per-column; default every 8 (`TAB_WIDTH`). HTS sets, TBC clears, HT advances to next set stop and clamps at the right margin (VT100).

### 9.2 Wide characters (East-Asian width)

Per Unicode EAW, a codepoint has print width 0 (combining), 1 (narrow), or 2 (wide: CJK, many emoji, double-width box-drawing). Model:

1. Width-2 glyph writes a **primary** cell (`ATTR_WIDE`) + a **spacer** cell (`ATTR_WIDE_SPACER`) in the next column; cursor advances 2.
2. Width-0 (combining mark) currently drops without advancing (a single-glyph cell can't store the mark) — preserves alignment; full composition is a later item.
3. Overwriting either half of a wide pair clears the *other* half to a blank carrying that half's colors — write-on-primary clears its spacer; write-on-spacer clears its primary.
4. A width-2 glyph with the cursor in the last column wraps first (autowrap) or is dropped (autowrap off) — it never straddles the right margin.
5. Width source: compiled-in EAW interval table (`eaw.rs`, `char_width(cp)`), binary-searched — no `unicode-width` crate.

Implemented: `cell.rs` (`ATTR_WIDE`/`ATTR_WIDE_SPACER`), `vc.rs` (`put_glyph_w`, `invalidate_wide_at`), `emulator.rs` (`print` width dispatch), `eaw.rs` (table).

### 9.3 Erase / scroll
ED/EL/ECH write blanks with the current bg (not the default) per ECMA-48. SU/SD/IL/DL/RI/IND scroll within `[scroll_top, scroll_bottom]`; lines leaving the top of the *full* screen (not a sub-region) enter scrollback.

## 10 Pending-wrap (deferred last-column wrap) — frozen semantics

VT100/xterm: printing a glyph into the last column writes it and sets a **deferred-wrap latch**; the cursor does NOT leave the last column. The *next* printable first wraps (CR+LF, scroll if needed) then prints. Any cursor-positioning command (CUF, CUP, CR, …) clears the latch without wrapping. This prevents a glyph in the last column from forcing a spurious blank line. (`Vc` carries this latch; freeze it.)

## 11 Alt screen

`?1049h`: save cursor+attr, switch to a cleared alternate grid. `?1049l`: discard alt grid, restore the main grid + saved cursor. `?1047` = alt grid without cursor save; `?1048` = cursor save/restore only. The alt grid has no scrollback. Implemented as a swap of grid+cursor+attr state.

## 12 UTF-8

`Ground` lead byte `≥0x80` enters `Utf8`; 2/3/4-byte sequences decoded by the lead-byte class. Overlong/invalid/truncated → U+FFFD, resync at the next lead. ASCII (`<0x80`) bypasses the decoder.

## 13 Answerback / queries (required for serial login)

Getty's terminal-size probe sends `\e[6n` (DSR-CPR) and blocks on the reply before printing the login prompt; an emulator with no answerback wedges serial login (`50`, vty-plan RC1). Required replies, injected into the tty input queue:

| Query | Reply |
|---|---|
| `\e[6n` (DSR 6) | `\e[<row>;<col>R` (CPR, 1-based) |
| `\e[5n` (DSR 5) | `\e[0n` (terminal OK) |
| `\e[c` / `\e[0c` (DA1) | `\e[?6c` (VT102) or `\e[?62;…c` (VT220) |
| `\e[>c` (DA2) | `\e[>0;<ver>;0c` |

## 14 OSC

`ESC ] Ps ; Pt (BEL|ST)`. Ps: 0/2 = window title (capture, no screen effect on a kernel VT), 1 = icon title, 4 = set palette color `index;spec`, 10/11 = default fg/bg, 104 = reset palette. Unknown Ps consumed and ignored. Terminator: `BEL` (0x07) or `ST` (`ESC \` or 0x9c).

## 15 Test contract (draft)

- Resumability: feeding any sequence one byte per `feed_bytes` call equals feeding it whole — proptest over a corpus of all `§4–§6` sequences.
- CSI coverage: each `§5` final drives the documented `Vc` mutation from a known start state (table-driven).
- SGR: 16-color, 256-color, truecolor, and every attribute flag round-trip into the cell attr.
- Pending-wrap: print to last column then one more glyph → wrap occurred exactly once, no blank line; CUF after last-column print clears the latch without wrapping.
- Wide chars: width-2 glyph occupies primary+spacer, advances 2; overwriting either half clears the other; width-2 at last column wraps; combining mark does not advance (`tests_wide.rs`).
- Alt screen: enter, scribble, leave → main grid + cursor restored byte-exact.
- UTF-8: 1/2/3/4-byte and invalid → U+FFFD, no desync.
- Answerback: `\e[6n` at row r col c → exactly `\e[r;cR` queued; `\e[c` → `\e[?6c`.
- Coverage ≥85% of `emulator.rs` + `vc.rs`.

## 16 Cross-spec

`28` (line discipline supplies the byte stream + receives answerback), `49` (fbcon renders `Vc` cells; scrollback ring), `50` (owns one emulator per VT; VT switch swaps the active `Vc`), `55` (palette + font for glyph resolution), `01` (Rgb/types).
