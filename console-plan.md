# Console / VT / fbdev — 100% Linux-compat plan (no hacks)

Goal: the framebuffer console stack matches Linux's architecture exactly, so
real apps (btop, vim, less, mc, fbterm, X-less GUIs) behave identically.

## Validation status of the in-flight B54 work
- **Cursor (fix.md #3):** logic + unit tests correct (con_cursor honours
  `cursor_visible`, prior cell erased on move). NOT boot-verified visually.
- **DSR/CPR (fix.md #5):** logic correct (`ESC[6n`→`ESC[r;cR`, `ESC[5n`→`ESC[0n`,
  clamp→geometry) BUT the **reply-injection HANGS THE BOOT** — agetty/systemd's
  size probe + the injection wedges the tty before login. Must be redone the
  Linux way (below). B54 stays on its branch, not merged.

## MANDATE: be Linux, not "like" Linux
No oxide approach. No mixing an oxide approximation with a Linux veneer. The
console stack must BE the Linux design — the same data structures, the same
algorithms, the same ioctl semantics as `drivers/tty/vt/{vt.c,vt_ioctl.c}`,
`drivers/tty/n_tty.c`, `drivers/video/fbdev/core/{fbcon.c,fbmem.c}`. Where the
current code deviates (a hack, a fake no-op, an oxide-only shortcut, a
home-grown ring where Linux uses a flip buffer), **RIP IT OUT and reimplement
it exactly the way Linux does**. The Rust crate names stay (`vtdata`, `fbcon`,
`fbdev`, `tty`) but their internals become the Linux structures:
- `vtdata::Vc` → `struct vc_data` (the real fields + the real con_ops contract).
- `fbcon` → the Linux fbcon (the `consw` it registers, the real soft-cursor /
  font / unicode-map path).
- `fbdev` → `fb_info` + `fb_ops` + `fbmem.c` ioctl/mmap surface.
- `tty` → `n_tty` line discipline + the **flip-buffer** RX path (answerback,
  keyboard, serial all go through `tty_insert_flip_string` → `receive_buf`).

The Linux console stack:
```
app ── /dev/ttyN | /dev/console ── n_tty (ldisc) ── con_ops (vt.c)
                                                      │  vc_data[N]
                                                      │  consw (console_switch)
                                              fbcon (drivers/video/fbdev/core)
                                                      │  fb_ops
                                              fb_info  ←──  /dev/fbN (fbmem.c)
```
Each item below = audit the current code vs the Linux source, rip the deviation,
reimplement to match. No "oxide approach" survives.

---
## Item 5 — DSR/CPR replies (REDO the Linux way; fixes the boot hang + btop)
Linux: the VT driver's `respond_string()` writes the answerback into the
**tty's input flip buffer** via `tty_insert_flip_string()` + `tty_flip_buffer_push()`,
on the SAME tty the query arrived on, then n_tty delivers it to the reader. No
new lock taken in the write path; the flip buffer is the decoupling point.
- Plan: the emulator produces reply bytes (already done). The console driver
  must push them into the EXACT tty the writer wrote to (the controlling
  vc's tty), through the normal RX flip path, **never** holding the
  render/VT_STATE lock across the tty push, and **never** echoing the reply
  back out (answerback is input-only). The current hang is from injecting on
  the wrong tty and/or re-entering under a held lock.
- Accept: boot reaches login (no wedge); a probe (`printf '\033[999;999H\033[6n'; read -d R`)
  returns `ESC[<rows>;<cols>` = the fbcon geometry; btop sizes to the console.

## Item 3 — cursor visibility + repaint (finish + boot-verify)
Linux fbcon: `fbcon_cursor()` draws/erases the cursor by redrawing the cell;
`vc->vc_deccm` gates visibility; soft-cursor erases the prior position. B54's
logic matches — just needs the boot/visual gate (less/htop hide-show, no trail).

## Item 2 — real glyphs (Unicode + box-drawing + DEC)
Linux: each glyph is a font index; chars map via the font's **unicode map**
(`consolemap`/`conv_uni_to_pc`), with the VT's G0/G1 charset (DEC special
graphics) selected by SI/SO + `ESC(0`. fbcon blits the font bitmap for the
mapped index. oxide currently collapses non-ASCII to `?`.
- Plan: (a) load a real console font with a unicode map (PSF2 with its unicode
  table — the PSF structs are already present but unused); (b) implement
  `conv_uni_to_pc` (unicode→font-index, with the box-drawing/DEC ranges mapped
  to the font's line-drawing glyphs); (c) the emulator already stores unicode +
  DEC-special-graphics correctly — wire the renderer to map through the table
  instead of the ASCII-only path. No transliteration hacks.
- Accept: `ls --color`, `tree`, mc, vim box-drawing render real glyphs, not `?`.

## Item 1 — real fbdev (/dev/fbN)
Linux fbmem.c: `/dev/fbN` backed by `fb_info`; `FBIOGET_VSCREENINFO`/
`FBIOGET_FSCREENINFO` report real geometry; `FBIOPUTCMAP`/`FBIOGETCMAP` for
palette; `FBIOPAN_DISPLAY` pans; `FBIOBLANK` blanks; **mmap** maps the real
framebuffer so userspace draws directly.
- Plan: back `/dev/fb0` with the real virtio-gpu/efifb framebuffer memory;
  implement mmap (map the fb pages into the process AS); implement the missing
  ioctls (`FBIOGETCMAP`,`FBIOPUTCMAP`,`FBIOGET_VBLANK`,`FBIO_WAITFORVSYNC`)
  for real; make `FBIOPUT_VSCREENINFO`/`FBIOPAN_DISPLAY`/`FBIOBLANK` actually
  act (or return EINVAL for unsupported modes) instead of silent no-op success;
  expose `/dev/fb1..N` per CRTC/scanout. No fake EOF/success.
- Accept: a raw fbdev drawer (e.g. `fbtest`/`con2fbmap`/a small mmap blit)
  draws to the screen; `fbset` reads correct geometry.

## Item 4 — unify VT switching
Linux: `vt_ioctl(VT_ACTIVATE)` → `set_console()` → `change_console()` → one path
that does `redraw_screen()` (the consw switch) AND `complete_change_console()`
(input/fg + signals). oxide splits the FB view switch (consw) from the input
foreground (keyboard path).
- Plan: one `switch_vt(n)` that updates the active vc, the consw framebuffer
  view, AND the input foreground/`fg_console`, called by BOTH `VT_ACTIVATE`
  (ioctl) and the keyboard (Alt+Fn). Single source of truth for `fg_console`.
- Accept: `chvt N` (ioctl) and Alt+Fn both switch screen + input together.

## Item 6 — VT/KD ioctl surface
Implement, per `vt_ioctl`/`kd` semantics (drivers/tty/vt/vt_ioctl.c):
`VT_GETMODE`/`VT_SETMODE`/`VT_RELDISP` (process-controlled VT switching +
acquire/release signals), `VT_SENDSIG`, `VT_RESIZE`/`VT_RESIZEX` (with the
winsize + SIGWINCH), `TIOCLINUX` (subfunctions: screen dump, selection),
`KDFONTOP` (font get/set — ties to item 2), `KDSETLED`/`KDGETLED`/`KDSKBLED`.
- Accept: `kbd_mode`, `setfont`, `loadkeys`, `openvt`/`vlock` paths work.

## Item 7 — scrollback to userspace
Linux: scrollback via the keyboard (Shift+PgUp → `scrollfront()`) and `/dev/vcsa`
(the screen+attr snapshot device). The `Vc` already holds scrollback.
- Plan: wire Shift+PgUp/PgDn to the existing scrollback in `Vc`
  (consw `con_scrolldelta`), and expose `/dev/vcs`/`/dev/vcsa` reading the live
  screen + scrollback. No internal-only buffer.
- Accept: Shift+PgUp scrolls; `cat /dev/vcs0` dumps the screen.

---
## Order (dependency-aware)
1. **#5 redo** (DSR via tty flip buffer) — unblocks the boot + btop. SMALL.
2. **#3 finish** (cursor) — boot-verify the B54 logic. SMALL.
3. **#2 glyphs** (PSF unicode map + conv_uni_to_pc) — high user-visible value. MED.
4. **#4 VT switch unify** + **#6 VT/KD ioctls** (share the switch path). MED.
5. **#1 fbdev** (mmap + ioctls) — largest; needed for any fb userspace. LARGE.
6. **#7 scrollback** (Shift+PgUp + /dev/vcs). MED.

Each lands as its own branch+PR, Linux-correct, both-arch boot-verified (no
merge without `oxide login:` on x86 AND aarch64), spec-lint clean, hosted tests.
