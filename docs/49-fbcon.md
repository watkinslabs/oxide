# 49 fbcon (kernel framebuffer console)

FROZEN 2026-05-09. Dep:`01`,`02`,`07`,`08`,`13`,`15`,`28`,`45`,`47`,`48`,`50`. Provides:graphical console glyph backend for `50` (VT).

Full Linux fbcon-equivalent surface per `linux/drivers/video/console/fbcon.c` + `linux/drivers/tty/vt/vt.c` console code paths. No deferrals.

## 1 Purpose

Linux fbcon-equivalent kernel module per `linux/drivers/video/console/fbcon.c`. Renders glyphs from a PSF font into a DRM dumb-buffer via `47`, scrolls in software, exposes ANSI/CSI escape parsing. Consumed by `50` (VT) when a VT is in `KD_TEXT` mode AND a graphics backend is bound; the serial console (`28` tty) stays as fallback when no graphics backend is available.

## 2 Invariants (frozen)

1. Font format PSF v1 (`PSF1_MAGIC=0x36 0x04`) and PSF v2 (`PSF2_MAGIC=0x72 0xb5 0x4a 0x86`) per `linux/include/uapi/linux/kd.h` + `pcscreen_font.h`. Compiled-in defaults: 8×16 IBM VGA, 8×8 mini, 16×32 SUN. Runtime font load via `KDFONTOP` (`50` VT layer).
2. Cell size matches loaded font; cell grid = `(xres / cw, yres / ch)`. Default 8×16 → 80×30 @ 640×480 / 80×25 @ 640×400 / 100×37 @ 800×600 / 128×48 @ 1024×768.
3. Backing surface: one DRM dumb-buffer per VT (allocated lazily on first write) sized to `xres × yres × bpp/8`; format honours the active fbdev pixel format per `48`.
4. Scrolling is software memmove on the backing buffer (top→bottom shift, last line cleared); fbcon issues a single virtio-gpu TRANSFER + FLUSH covering the dirty rect after each batch.
5. Full vt102 / xterm-256color emulation per `terminfo` `linux` + `xterm-256color` entries: CSI/OSC/DCS escape parsing, DECSET/DECRST modes, mouse (X10/normal/SGR), bracketed paste, OSC 52 clipboard, OSC 4/10/11/12 palette set/query, CSI `?7`/`?25`/`?47`/`?1049` (alt-screen), CSI `t` (window manipulation).
6. Color palette: 16-color VGA palette default; 256-color xterm cube; 24-bit truecolor via `CSI 38;2;R;G;B m`. Palette runtime-mutable via OSC 4 / `CSI ] 4 ; n ; rgb:RR/GG/BB ESC \`.

## 3 Public ifc

```rust
// crates/fbcon/src/lib.rs
pub fn init(drm: &dyn DrmDriver, conn_id: u32, mode: &Mode);

pub struct FbCon { /* per-VT state: cursor, attrs, scrollback */ }

impl FbCon {
    pub fn put(&mut self, byte: u8);                // ANSI parser feeds here
    pub fn put_str(&mut self, s: &[u8]);
    pub fn flush(&mut self);                         // commit dirty rect to FB
    pub fn resize(&mut self, cols: u32, rows: u32) -> KResult<()>;
    pub fn set_cursor_visible(&mut self, on: bool);
    pub fn fb_id(&self) -> u32;                      // DRM fb id
    pub fn cursor_pos(&self) -> (u32, u32);
}
```

## 4 PSF font header

```c
// PSF v2
struct psf2_header {
    u8  magic[4];      // 0x72 0xb5 0x4a 0x86
    u32 version;       // 0
    u32 headersize;    // 32
    u32 flags;         // bit 0 = has Unicode table
    u32 length;        // glyph count
    u32 charsize;      // bytes per glyph
    u32 height, width; // pixel dims per glyph
};
```

V1 parser supports v2 only (PSF v1 256-glyph 8×y header is half the size; rejected for now). Builtin font: `linux/lib/fonts/font_8x16.c` re-exported as a static byte-array.

## 5 ANSI / CSI subset

| Sequence | Meaning |
|---|---|
| `\x1b[<y>;<x>H` / `f` | cursor to (1-indexed row, col) |
| `\x1b[<n>A` / `B` / `C` / `D` | cursor up/down/right/left N |
| `\x1b[<mode>J` | erase: 0=cursor→end, 1=start→cursor, 2=full screen |
| `\x1b[<mode>K` | erase line: 0/1/2 |
| `\x1b[<n>S` / `T` | scroll up / down N lines (within DECSTBM region) |
| `\x1b[<n>P` | delete N chars |
| `\x1b[<n>@` | insert N blanks |
| `\x1b[<top>;<bot>r` | DECSTBM (set scroll region) |
| `\x1b[6n` | DSR — report cursor pos |
| `\x1b[?25h` / `?25l` | DECSET 25 — show / hide cursor |
| `\x1b[?7h` / `?7l` | DECSET 7 — autowrap on/off |
| `\x1b[<args>m` | SGR (see §6) |
| `\x1b 7` / `8` | DECSC / DECRC — save / restore cursor |
| `\x1b D` | IND — index (cursor down + scroll) |
| `\x1b M` | RI — reverse index |
| `\x1b c` | RIS — full reset |

## 6 SGR (Select Graphic Rendition) tokens

| Param | Meaning |
|---|---|
| `0` | reset all attrs |
| `1` | bold (renders bright color) |
| `2` | dim |
| `4` | underline (drawn as bottom-row pixels) |
| `5` | blink (v1: ignored) |
| `7` | reverse-video (swap fg↔bg) |
| `22` | normal weight |
| `24` | underline off |
| `27` | reverse off |
| `30..37` | fg = 8 color indices |
| `38;5;N` | fg = 256-color palette index |
| `38;2;R;G;B` | fg = 24-bit RGB |
| `39` | fg = default |
| `40..47` | bg = 8 color indices |
| `48;5;N` | bg = 256-color palette index |
| `48;2;R;G;B` | bg = 24-bit RGB |
| `49` | bg = default |
| `90..97` | fg = bright 8-color |
| `100..107` | bg = bright 8-color |

## 7 Glyph blit pipeline

For each cell at (col, row) writing glyph `g` with fg `F` and bg `B`:
1. Look up `g`'s row 0..h in the PSF font: 1 bit per pixel.
2. For each pixel row, write 8 BGRA pixels into the dumb-buffer at byte offset `(row*ch + py) * pitch + (col*cw + 0) * 4`.
3. Mark the cell rect dirty.

After a batch (e.g. one full line written), issue a single virtio-gpu `TRANSFER_TO_HOST_2D` + `RESOURCE_FLUSH` covering the bounding-box of dirty cells.

## 8 Scroll

When the cursor advances past `rows-1` (or CSI `S` requests):
1. memmove dumb-buffer rows `[1..rows]` → `[0..rows-1]`.
2. Memset bottom row to bg color.
3. Issue full-frame TRANSFER + FLUSH (one host pageflip).

Scrollback buffer: per-VT 1000-line ring of (col, attr, glyph) tuples; up-arrow on a paused-VT scrolls into history (Linux equivalent: `Shift+PageUp`).

## 9 Cursor

Block cursor drawn as inverted cell at `(cursor_col, cursor_row)`. Blinks at 2 Hz when visible. Blink runs on the timer subsystem — not its own thread.

## 10 Concurrency

- Per-VT `Spinlock<FbCon>` (lock class `Driver`).
- ANSI parser is single-threaded per VT; serial input from `28` tty drains into the parser via the VT's RX hook (per `50§3`).
- Multiple writers (kernel klog + userspace VT writes) serialize on the per-VT lock.

## 11 Failure modes

- DRM dumb-buffer alloc fail at boot: fbcon stays disabled; `50` falls back to serial-only output.
- Mode change while writing: dropped line of output is acceptable; ANSI parser resyncs on next `\n`.
- Invalid PSF magic: kassert at boot (compiled-in font must parse).

## 12 Test contract (frozen)

- Init smoke: bind to a virtio-gpu connector at boot; `init()` returns success; one full-frame BG fill visible.
- Write smoke: `put_str(b"hello\n")` renders 5 glyphs at row 0 + cursor at row 1 col 0.
- Scroll smoke: write `rows + 5` lines; verify line 0 contains what was originally line 5 (memmove correct).
- ANSI color smoke: `\x1b[31mRED\x1b[0m\n` renders RED in red, then attr resets.
- Cursor pos smoke: `\x1b[10;20H` sets cursor to row 9 col 19 (0-indexed in our addressing).
- Coverage ≥80% of `crates/fbcon`.

## 13 Wide / composing / bidi

UTF-8 input parsed to Unicode code points; East-Asian wide characters (CJK Unified Ideographs, Hangul Syllables, full-width forms per `EastAsianWidth.txt`) take TWO cells; cursor advance respects the width.

Combining characters (Unicode general category `Mn`/`Me`/`Mc`) merge into the previous cell's glyph stack; fbcon renders them by overlay-blitting each combining glyph onto the base cell's bitmap. Cell attribute storage is 64-bit per cell to fit (fg:24, bg:24, attrs:8, combining-stack-id:8).

Bidi reordering per UAX#9: when the active VT has `KD_RTL` enabled (Linux `fbcon=rotate:N`-style runtime flag), each line is reordered visually before rendering. Default is LTR.

## 14 GPU-accelerated glyph blit

Where the underlying driver advertises a hardware-accelerated rect-fill / rect-copy primitive (i915 BLT, amdgpu CB, virtio-gpu via VIRGL `glBlitFramebuffer`), fbcon delegates the per-line scroll memmove + the per-cell solid-color clear paths to GPU; falls back to CPU memmove for software-only drivers.

## 15 Subpixel + freetype

When a TrueType font is loaded via `KDFONTOP(KD_FONT_OP_SET_DEFAULT)` with a TTF blob, fbcon hands rendering to a kernel-bundled subset of FreeType (mono + grayscale only — LCD subpixel anti-aliasing lives in user-side renderers). Default fonts stay PSF.

## 16 Cross-spec

`47` (DRM dumb-buffer + atomic commit), `48` (fbdev shares the same backing buffer, so `dd > /dev/fb0` and fbcon writes coexist), `50` (VT layer drives this for tty1..6 in KD_TEXT mode), `28` (tty line discipline feeds keystrokes back to the active VT's stdin).
