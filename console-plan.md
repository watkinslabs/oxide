# Console / VT / fbdev / TTY — 100% Linux-compat plan (integrated)

Single source of truth. Synthesizes **fix.md** (original 10-item audit),
this plan's first pass (fix.md items 1–7), and **fixtty2.md** (post-impl audit
of remaining ownership/integration/architecture debt).

MANDATE (unchanged): BE Linux, not "like" Linux. Where the code deviates (a
hack, a fake no-op, an oxide-only shortcut, a home-grown path where Linux uses
a flip buffer / one tty object), RIP IT OUT and reimplement it the way
`drivers/tty/{vt,n_tty,pty,vc_screen}.c`, `drivers/video/fbdev/core/*` do.

The Linux stack:
```
app ─ /dev/{ttyN,console,pts/*,ttyS*} ─ ONE TtyStruct ─ N_TTY ldisc ─ driver
                                                          │            ├ vt.c (con_ops) ─ vc_data[N] ─ fbcon ─ fb_info ─ /dev/fbN
                                                          │            └ uart / pty
                                              keyboard ───┘ (→ fg vc's tty input)
```

---

## Part A — surface items (fix.md 1–7): DONE, with caveats

Shipped as PRs #1701–#1708 (both arches boot, host-tested, spec-lint clean).
fixtty2.md confirms these are real; the per-item caveats below are the residue
that Part B closes.

| # | Item | PR | Status / caveat (fixtty2) |
|---|------|----|---------------------------|
| 5 | DSR/CPR answerback (deferred flip-buffer) | #1701 | DONE |
| — | /dev/console → vc_data output + fb render | #1701 | output/echo tees to fbcon; **input still split** (see B0) |
| 3 | cursor visibility + repaint | #1701 | DONE |
| 2 | real glyphs (PSF2 + conv_uni_to_pc) | #1702 | DONE; **width>8 fonts rejected** (B6) |
| 4 | unify VT switching (one `vt::activate`) | #1703 | DONE; still calls `tty::live::set_foreground` (B4) |
| 6 | VT/KD ioctls (mode/leds/resize/TIOCLINUX) | #1704 | partial: **VT_SENDSIG missing, TIOCLINUX only subfn 6** (B2); resize is metadata+signal only (B3) |
| 6 | KDFONTOP + PIO/GIO_UNIMAP (setfont) | #1705 | DONE (width≤8) |
| 6 | VT_PROCESS handshake (relsig/acqsig/RELDISP) | #1706 | partial: **WAITACTIVE stale, RELDISP no owner check, ownership = bare pid** (B1) |
| 1 | real /dev/fb0 (geometry, mmap, ioctls) | #1707 | DONE |
| 7 | scrollback (Shift+PgUp) + /dev/vcs,vcsa | #1708 | DONE |

---

## Part B — architecture + correctness debt (fix.md 8–10, fixtty2 1–10)

This is the work that was NOT in the first plan pass and is the real remaining
road to Linux-compat. Ordered by user impact + dependency.

### B0 — framebuffer + keyboard login [DONE — PR pending merge]
Fixed: keyboard → `tty::live::set_kbd_sink` → `console::static_console::rx_byte`
(the system console's N_TTY RX; echo already mirrors to fb). Plus a timer-tick
`InputDrain` fallback (arm GICv3/ITS input MSI doesn't reliably fire — same
pattern as the net-rx/blk tick fallbacks). Verified on BOTH arches with REAL
virtio-keyboard `send-key` injection via QMP (`tools/boot-smoke-kbd-login.sh`):
typed `alice`/`swordfish`/`id` → `uid=1000(alice)`. Original analysis below.


Symptom: at the physical screen you cannot type into `oxide login:` — getty
never sees keystrokes. (Serial login works; the login smoke passes over serial.)
Root cause = the split (B4): keyboard → `tty::live::push_and_wake_fg` →
`FOREGROUND_VT` numbered ring (vt 1..63), but `console-getty` reads
`/dev/console` = `static_console` (a serial `TtyStruct` fed ONLY by
`drv_serial` UART RX). Two input sinks; getty's isn't the one the keyboard
feeds. Output/echo already reaches fbcon (`KernelUart::emit` → `vt_console_sink`).
- **Immediate fix:** route the keyboard to the system console's input —
  feed `console::static_console::rx_byte` (the same N_TTY RX path the UART
  uses) so getty gets cooked, echoed line input on the framebuffer.
- **Real fix:** B4 (one console tty; keyboard → the fg console's single input).
- **Accept:** boot graphical, type `alice`/`swordfish` at the screen → shell;
  echo visible on the fb. Add a keyboard-input integration test/probe.

### B1 — VT_PROCESS correctness (fixtty2 1,2,3)
- **VT_WAITACTIVE** must block until the (possibly deferred) switch completes,
  not return a stale bookkeeping compare. Needs a waitqueue keyed on the target.
- **VT_RELDISP** must validate the caller IS the foreground VT's registered
  process-mode owner before completing/refusing the handoff (trust model).
- **Ownership** must be a task handle/reference (revalidated against live task +
  generation), not a bare pid — survives task exit + pid reuse.

### B2 — finish the VT/KD ioctl surface (fixtty2 4)
- **VT_SENDSIG**, the rest of **TIOCLINUX** subfunctions (selection, screen
  dump, cursor, blank-interval, etc.), VT_GETHIFONTMASK. "Implemented enough
  to look real" → actually Linux-compatible.

### B3 — real live VT resize (fixtty2 5)
- **VT_RESIZE/VT_RESIZEX** must resize the actual per-VT `Vc` (cells, history,
  scroll region) + fbcon backing + winsize + SIGWINCH **together**, not just
  store rows/cols metadata. Reflow the live screen.

### B4 — collapse onto ONE tty stack (fix.md 9, fixtty2 6,7) — BIGGEST
The structural bug. Two sources of truth (`tty::live` per-VT rings vs
`TtyStruct`/`NTty` core) → termios/signal/blocking/EOF/pgrp/winsize semantics
drift by path. Target: ONE `TtyStruct` model for console + serial + pty.
- Numbered VTs (`/dev/ttyN`) get a real `TtyStruct` (N_TTY ldisc) whose driver
  is the vt console (con_ops → vc_data → fbcon), replacing the `tty::live` ring
  + ad-hoc line editing + termios store + pgrp/session store + wake queues +
  answerback injection + poll.
- The system console (`/dev/console`) = the foreground vc's tty (one input, one
  output, one emulator) — subsumes B0.
- `TtyStruct::ioctl()` owns the behavior (B-7) instead of syscall-side decode glue.
- One authoritative store for termios / winsize / sid / fg pgrp.
- Delete `tty::live` and its `'\0'`-EOF sentinel + best-effort pgrp shortcuts.
- `tty::init()` (currently returns NotImplemented) wired as the real entry.
- Sequencing: foundation-first (give numbered VTs a real TtyStruct) BEFORE
  retiring `tty::live` callers — never a legacy+fallback bolt-on.

### B5 — finish Linux tty semantics in the unified core (fix.md 10, fixtty2 8,9)
- Blocking reads **signal-interruptible** (EINTR/restart) the Linux way, not
  just input/EOF wakeups.
- Noncanonical **VMIN+VTIME** timing (VTIME is currently simplified away).
- Driver lifecycle **open/close/hangup** with real call sites + ownership.
- **PTY** hangup, stopped-output flow control, canonical-edit edge cases — stop
  being approximations (matters once job control + tmux/screen run).

### B6 — font widths > 8 (fixtty2 10)
- The PSF/conv_uni_to_pc path hard-restricts width≤8 (1 byte/scanline). Support
  wider cells (Terminus etc.): multi-byte rows in `glyph_row` + the renderer.

---

## Order (dependency-aware)
1. **B0** keyboard→console input — unblocks framebuffer login NOW (small; the
   first slice of B4's input unification).
2. **B1** VT_PROCESS correctness (WAITACTIVE/RELDISP-owner/ownership) — closes
   the trust + lifetime holes in shipped #1706.
3. **B2** VT_SENDSIG + TIOCLINUX rest; **B6** font width>8 (independent, small).
4. **B3** real live resize.
5. **B4** collapse onto one tty stack — the big foundation; do it properly
   (numbered-VT TtyStruct first, then retire tty::live, then delete).
6. **B5** finish tty semantics (VMIN/VTIME, signal-interruptible, hangup, PTY).

Each lands as its own branch+PR, Linux-correct, both-arch boot-verified (no
merge without `oxide login:` on x86 AND aarch64 — AND for B0, a real keyboard
login), spec-lint clean, hosted tests. Boot reaching the login PROMPT ≠ login
works — gate on actual login (serial AND framebuffer keyboard).
