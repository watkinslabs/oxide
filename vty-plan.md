# vty-plan — full Linux-compliant TTY/VT remediation

Status: MOSTLY COMPLETE (2026-06-11). Goal: the console (serial AND framebuffer)
behaves like a real Linux terminal — all signals, all job control, full
ECMA-48/vt100/vt220/xterm command set, both arches. No stubs, no "narrow smoke
gate passes." Verified live under qemu on x86_64 AND aarch64.

## Completion status (2026-06-11)

DONE (merged, both arches reach `oxide login:`):
- **RC3 emulator command set** — DA/DECID, IRM insert mode, C1 8-bit controls,
  OSC/DCS ST-terminator fix (#1769); OSC 4/104/10/11 color control + per-VC
  palette (#1770); DECCKM `?1` cursor-key app mode + bracketed paste `?2004`
  (#1771). Earlier: ECH, alt-screen, SGR 2/3/5/8/9 + resets, wide chars, Linux
  font-select/CP437 (#1768). emulator.rs split into `emulator/{mod,sgr,osc}.rs`.
- **RC4 job control** — SIGTTIN/SIGTTOU + TOSTOP background-pgrp gate (Linux
  `tty_check_change`, host-tested `tty::jobctl::decide`) (#1772); pty
  master-hangup SIGHUP+SIGCONT drain (#1773).
- **RC2 (re-scoped)** — the 2026-06-11 audit was STALE: fbcon `fg`, keyboard
  target, and `vt::ACTIVE_VT` already init to 1 and are written together by the
  sole writer `vt::do_switch`; the keyboard already follows the foreground VT;
  getty on `/dev/console` already resolves to the foreground VT. The one real
  functional bug — VT/KD ioctls on `/dev/console` hit a dead `ino_low==1` branch
  — is fixed (#1774): alias → `vt::active()`, `/dev/ttyN` → VT N.

REMAINING (documented honestly; not yet done):
- **Mouse reporting** (`?1000/1002/1003/1006`, SGR1006) — needs a real pointer
  pipeline (accumulate EV_REL/EV_ABS + BTN_* → cell coords via fbcon geometry →
  encode → inject to fg tty). Emulator-only flag storage would be compatibility
  theater. X11/Wayland already get raw events via `/dev/input/event0`; VT
  xterm-mouse is only for terminal apps on the bare console. Sequence with
  graphics bring-up.
- **Step B / RC5 cleanup** — collapse the 3 synced foreground atomics to one
  canonical reader (`vt::active()`) + retire `tty::live`. NO behavior change
  (runtime already correct); pure hardening so it can't drift. Low priority.
- **RC4 follow-ups** — auto-ctty on first open, session enforcement on
  TIOCSCTTY/TIOCSPGRP. Current explicit-TIOCSCTTY getty flow works; strict
  enforcement risks the login path for marginal value. Do with care + heavy
  boot verification.
- **RC1 serial answerback — REASSESSED, NOT the Linux way as prescribed.** The
  plan proposed kernel-side CPR/DA answerback on the serial tty. But a real
  Linux serial line does NOT synthesize terminal-query replies — the CONNECTED
  terminal does; kernel-side serial answerback would double-reply and corrupt
  real-terminal sessions. The fbcon VT answers because IT is the terminal
  emulator; ttyS0 is a raw line. The SMP≥2 console-getty wedge (state.md) is a
  separate concurrency bug, not an answerback gap. Do NOT implement kernel-side
  serial answerback.
- **docs/57 stays DRAFT** until mouse lands (its §8 lists mouse modes).

Grounded in a 5-agent code audit (2026-06-11) since partly superseded above.
Every claim below cites file:line.

## Root causes (confirmed live + in code)

### RC1 — serial login blocker: no terminal-query answerback on serial  [CRITICAL]
CORRECTED after live testing (the "timer not ticking" theory was REFUTED:
`sleep 2; echo X` printed X on its own with zero input — idle output flushes,
ticks fire, timed wakeups work, post-login interactive I/O is fine).
The real bug: getty's terminal-size probe sends DSR `\e[6n` (after
`\e[32766;32766H` homing) and blocks reading the CPR reply (`\e[row;colR`)
BEFORE it prints `oxide login:`. The **serial console tty has NO answerback
path** — `static_console`/`serialtty` never answer `\e[6n`/`\e[c`
(grep: zero DSR/answerback refs). So on serial the probe never completes →
prompt never appears; the first keystroke unblocks it. On a real terminal the
terminal's own CPR reply races into the username read → garbage user →
"login incorrect" → getty respawns = the user's "type name, it resets" symptom.
- The framebuffer VT ALREADY answers DSR/CPR via `fbcon/src/answerback.rs`
  (emulator answerback queue → tty input, deferred/lock-safe). Serial must get
  the SAME: run the query-answerback responder on the serial console tty so
  `\e[6n`→CPR and `\e[c`→DA are generated kernel-side into ttyS0's input ring,
  immediately + before the username read (no dependence on the remote terminal,
  no contamination race).
- Verify-left: hosted test feeding `\e[6n` to the serial console ldisc asserts a
  CPR appears in its input ring; live gate = `oxide login:` appears on serial
  with NO keystroke, then `root`+Enter → shell.

### RC2 — black framebuffer / graphical login dead: VT-identity split  [CRITICAL]
getty runs on fbcon **vc 0**, but every foreground mechanism (VT_ACTIVATE,
Ctrl-Alt-Fn, keyboard target, `/dev/tty1`) targets **vc 1..N**. Three disagreeing
"foreground" notions: `ACTIVE_VT=1` (`vt/src/lib.rs:290`), keyboard fg=1
(`tty/src/live.rs:23`), fbcon fg=0 (`fbcon/src/kernel.rs:179`), getty writes vc0
(`console/src/lib.rs:139-143`). Any VT switch strands getty offscreen → black.
Keyboard input is hard-pinned to vc 0 (`tty/src/live.rs:46` → `static_console::
rx_byte`), ignores `foreground()`. Real Linux: console getty runs on tty1, a
numbered VT that IS the default foreground.

### RC3 — VT emulator incomplete: garbage rendering  [HIGH]
Command set now specced in **docs/57** (ECMA-48/VT100/VT220/xterm interpreter +
cell model). LANDED: ECH, alt-screen, truecolor, **wide chars (East-Asian
width: primary+spacer cells, EAW table `eaw.rs`, cursor advance by width,
overwrite invalidation)**, **SGR 2/3/5/8/9 + resets 22/23/25/28/29** (faint/
italic/blink/conceal/strike), **SGR 10/11/12 Linux font-select +
disp_ctrl/CP437 (`cp437.rs`)** — fixes box-drawing on TERM=linux
(ncurses smacs `\E[11m` + raw CP437 corner/line bytes were UTF-8-misdecoded;
now mapped to the box codepoints the font already has). Single live parser
`vt/src/emulator.rs`. Remaining vs real terminal:
- **ECH `CSI X`** — absent (no `b'X'` arm). ncurses/systemd use it constantly →
  stale glyphs.
- **Alternate screen `?1049/?47/?1047`** — no alt buffer in `Vc`. vim/less/htop/
  pager wipe primary to black, never restore. (Also a black-screen cause.)
- **DA `CSI c` + DECID `ESC Z`** — no reply; DA-probing programs stall.
- **Bracketed paste `?2004`**, **DECCKM `?1`** app-cursor, **keypad `ESC =/>`** —
  dropped; bash readline + full-screen apps assume them.
- **OSC 4/104 palette**, **OSC ST parse bug** (lone `\` ends OSC), **DCS not
  answered + ESC-mid-DCS misroute** (`emulator.rs:167-169` can leak payload as
  commands), **C1 8-bit controls** (0x80-0x9f), **mouse `?1000/1002/1003/1006`**.

### RC4 — tty signals + job control gaps  [HIGH]
`Sig` enum (`tty/src/ldisc/mod.rs:44`) only has Hup/Int/Quit/Tstp. Working: ISIG
^C/^\/^Z → fg pgrp, TIOCG/SPGRP, TIOCSCTTY, SIGWINCH, winsize, stop/cont machinery.
MISSING/BROKEN:
- **SIGTTIN** background-pgrp read — no check in `000_read.rs`. Spec `28§6`.
- **SIGTTOU + TOSTOP** background-pgrp write — no TOSTOP bit, no check in
  `001_write.rs`. Spec `28§6`.
- **SIGHUP on pty master close BROKEN** — `pty.rs:645` sets `pending_sighup`,
  `devpts/lib.rs:80-82` never drains it.
- **SIGCONT after SIGHUP** on hangup — `core.rs:504` sends only Hup.
- **session-wide SIGHUP** (not just fg pgrp) — spec `28§6/§10`.
- **orphaned process group** handling — absent (SIGHUP+SIGCONT to stopped
  members; bg I/O → EIO).
- **TIOCNOTTY on pty** no-op (`016_ioctl.rs:337`).
- **auto-ctty on first open** w/o O_NOCTTY — absent. Spec `28§2`.
- **session-match enforcement** on TIOCSCTTY/TIOCSPGRP — absent (EPERM cases).

### RC5 — tty::live not retired  [MEDIUM]
Duplicate ring/termios/ldisc stack genuinely deleted (changelog half-true), but
`tty::live` survives as a 4-fn keyboard router with the RC2 foreground bug. Live
sites: `kmain.rs:386`, `drv-virtio-input/src/drain.rs:143`, `016_ioctl.rs:687`,
`vt/src/lib.rs:395`, `console/src/lib.rs:267`. Fully retire after RC2.

### RC6 — docs lie  [MEDIUM]
CHANGELOG "ONE unified TTY stack, legacy tty::live retired" + state.md/state2.md
"real VT100" overclaim. Fix to match reality. Audit docs/28 for any contract the
code must meet that's unstated.

## Execution order (each = own branch+PR, lockstep x86+arm, live-verified)

- **P17-01 tcflush** (RC1): implement TCFLSH (0x540B) TCIFLUSH/TCOFLUSH/TCIOFLUSH
  + make TCSETSF actually flush input + TCXONC (0x540A) flow control. agetty/
  login/bash `tcflush(TCIFLUSH)` is currently a no-op → stale terminal-query
  answerback (CPR) + early keystrokes contaminate the username read → login
  fails → getty respawns ("it resets"). Need `flush_input()`/`flush_output()` on
  TtyStruct+NTty (clears canon+read queues, out_hold), routed for console + pty.
  Hosted test: inject stale bytes, TCFLSH(TCIFLUSH), assert read returns nothing.
  Live gate: `root`+Enter → shell, repeatably, both arches.
  NOTE (verified live): default termios has IXON OFF so the ldisc write is
  synchronous — the prompt-withhold seen over the qemu-MCP serial bridge is a
  bridge artifact (post-login output flushes fine); the REAL serial login bug is
  the missing input-flush above + terminal-query answerback timing.
- **P17-02 sig-enum+jobctl** (RC4): add Sig::Ttin/Ttou/Cont; SIGTTIN read gate,
  SIGTTOU/TOSTOP write gate, fix pty SIGHUP drain, SIGCONT+session SIGHUP,
  orphan-pgrp, TIOCNOTTY pty, auto-ctty, session enforcement. Hosted ldisc tests
  per case + live ^C/^Z/bg-job check.
- **P17-03 emulator-core** (RC3a): ECH, DA/DECID, SGR 2/3/5/9+resets, DECCKM,
  keypad, bracketed-paste store, OSC4/104, OSC/DCS parse fixes, C1. Hosted
  vt100 tests per sequence.
- **P17-04 altscreen+mouse** (RC3b): alternate screen buffer in `Vc`
  (?1049/?47/?1047 save+restore), mouse reporting ?1000/1002/1003/1006/SGR1006.
- **P17-05 fbcon-unify** (RC2+RC5): vc1 default foreground; /dev/console →
  foreground VT; foreground-aware keyboard; getty on tty1; activatable/unified
  fg; delete tty::live. Gate: framebuffer keyboard login via QMP send-key on
  both arches (tools/boot-smoke-kbd-login.sh), screen NOT black, echo follows
  VT switch.
- **P17-06 docs** (RC6): rewrite CHANGELOG tty claims, state.md, docs/28 deltas,
  delete dead scratch md. spec-lint clean.

## Discipline
- spec-before-code OK: docs/28 FROZEN 2026-05-02.
- Verify-left: hosted `cargo test` over ldisc/emulator fixtures is the dev loop;
  qemu MCP (one warm VM) for the live gates; full `make smoke` both arches before
  each push.
- spec-lint clean before every commit+PR. No magic literals (Errno/Signum/flags
  typed). SAFETY ≥30 chars. ≤1000 lines/file.
- Both arches every PR (lockstep). No x86-first.
