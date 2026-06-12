# state — session hand-off

Branch: **main** (clean). All this session's work merged.

## Merged this session (vty-plan completion, 7 PRs)
- #1769 P17-09 vt: DA/DECID answerback, IRM insert mode, C1 8-bit controls,
  OSC/DCS ST-terminator fix. emulator.rs relocated to `emulator/mod.rs`.
- #1770 P17-10 vt: OSC 4/104/10/11 color control + per-VC palette. emulator
  split into `emulator/{mod,sgr,osc}.rs` (was at 1000-line cap).
- #1771 P17-11 vt: DECCKM `?1` cursor-key app mode (arrows → SS3 `ESC O x`) +
  bracketed paste `?2004` (PASTESEL wrap). Foreground mode read via IoC
  fn-pointer queries in `tty::live` (keyboard driver has only a `tty` dep).
- #1772 RC4a tty: SIGTTIN/SIGTTOU + TOSTOP job control. Pure decision
  `tty::jobctl::decide` (host-tested, mirrors Linux `tty_check_change`);
  `console::jobctl::check` gathers live ctx + gates console/serial r/w.
- #1773 B109 pty: SIGHUP+SIGCONT to slave fg pgrp on master last-close
  (`on_release` set `pending_sighup` but never delivered it).
- #1774 B110 tty: VT/KD ioctls on `/dev/console` act on active VT, `/dev/ttyN`
  on VT N (dead `ino_low==1` branch fixed).

## vty-plan status — see vty-plan.md "Completion status"
Emulator command set + job-control core + RC2 functional bug DONE. Remaining
(documented, deliberately deferred): mouse reporting (needs pointer pipeline —
emulator-only would be theater), Step B/RC5 cleanup (no behavior change),
RC4 auto-ctty/session-enforcement (login-path risk), and **RC1 serial
answerback — reassessed as NOT the Linux way (a serial line's terminal answers
queries, not the kernel); do NOT implement kernel-side serial answerback.**
docs/57 stays DRAFT until mouse lands.

## NOW WORKING: linux2.md loop
Per user: after the plan, loop linux2.md — validate each gap against code, then
implement the REAL Linux behavior (no hacks/theater). CORE RULE (memory
`feedback_linux_way_per_task_gate`): for EVERY task ask "is this the Linux
way?"; name the exact Linux mechanism it mirrors; correct before shipping.

linux2.md priority order (§6): 1 shared-lib runtime both arches (esp aarch64
TLS/IFUNC/versioning/dlopen) → 2 PID1/login/PAM/NSS → 3 namespaces+mount+rootfs
→ 4 net control-plane (rtnetlink) → 5 io_uring_register (returns 0 uncond) →
6 ext4 extent depth/scale → 7 X11/Wayland graphics stack.

## First task next session
Begin linux2.md. Suggested first contained win: **io_uring_register** (§2.7,
`crates/kernel/syscalls/src/427_io_uring_register.rs` returns 0 unconditionally)
— implement real Linux registration (fixed buffers/files, ring visibility).
First validate against code, then implement. `git -C /home/nd/oxide2 log
--oneline -8 main` for context.
