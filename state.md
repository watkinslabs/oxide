# state — session hand-off

Branch: main. Last merged: #1738 (P17-05 serial/fb console split).
Active roadmap: **vty-plan.md** (P17-01..06).

## Headline
User: terminals must be done THE LINUX WAY (serial + framebuffer are SEPARATE
devices, not one mirrored /dev/console). Landed the real device separation.

## Landed this session
- **#1736 (P17-01 tcflush):** TCFLSH/TCSETSF input flush — stale terminal-query
  answerback no longer contaminates the username (getty-respawn login bug).
- **#1738 (P17-05 serial/fb split):** the big one. Serial (`/dev/ttyS0`) and the
  video VTs (`/dev/tty1..N`, `/dev/console`) are now SEPARATE tty devices:
  - /dev/console,/dev/tty,/dev/tty0 → foreground video VT (vt_tty); renders to
    fbcon ONCE. /dev/ttyS0 → SerialInode, serial-only, own 80x24 winsize.
  - `console::route(ino)` centralizes device selection (low-byte 0xFD fg-VT /
    0xFE serial / N=VT); all 10 ioctl sites use it.
  - KernelUart::emit no longer mirrors to fbcon → **double-print fixed**.
  - keyboard → vt_tty(foreground()). fbcon fg slot 1 == /dev/tty1 == /dev/console
    (ONE foreground notion → fixes the VT-identity black screen).
  - serial-getty-ttyS0.service added + wired into default.target.
  - **Verified live both arches:** both gettys start; serial login → uid=0,
    tty=/dev/ttyS0, no escape-soup; framebuffer renders text (not black).
    Pre-push boot-smoke PASS x86+arm.

## How Linux does serial+graphical (the rule, now implemented)
Separate devices, never mirrored as terminals. printk → all consoles;
interactive I/O → per-device. Video VT = default /dev/console; getty per device
(console-getty on /dev/console + serial-getty@ttyS0). Each tty: own winsize
(serial 80x24 until remote SIGWINCH; VT = fb cell grid).

## Open / next (vty-plan)
- **Graphical keyboard login** — verify via QMP send-key
  (tools/boot-smoke-kbd-login.sh) that typing at the framebuffer console logs in
  (console-getty on the video VT). The MCP can't inject framebuffer keys.
- **console-getty respawns once on arm** ("restart counter at 1") — minor; the
  video-VT getty deactivates+restarts on first boot. Investigate.
- **P17-02 job-control signals** (RC4) — Sig enum lacks Ttin/Ttou/Cont;
  SIGTTIN/SIGTTOU/TOSTOP gates, pty SIGHUP drain, SIGCONT-on-hangup, orphan-pgrp.
- **P17-03/04 emulator** (RC3) — ECH, alt-screen ?1049, DA reply, SGR
  italic/dim/blink/strike, bracketed paste, DCS fix.
- **P17-06 docs** — CHANGELOG/docs/19/docs/28 reflect the device split.
- Known SMP=2 TCG flake: #UD at oxide_syscall_entry on cpu=1 (pre-existing AP
  race; smoke retries past it). Not console-related.

## First command next session
    git checkout -b P17-02-jobctl-signals
    grep -n "pub enum Sig" crates/kernel/tty/src/ldisc/mod.rs

## Discipline reminders
- THE LINUX WAY: implement the real subsystem; settled Linux behavior is NOT an
  AskUserQuestion. [[feedback_linux_way_no_design_questions]]
- Kill stale qemu-system before boot-smoke (vhost-vsock CID/port conflict makes
  the pre-push hook falsely fail). Don't `pkill -f qemu` (matches your own shell)
  — use `pkill -f qemu-system`.
- spec-lint clean + boot-smoke both arches every PR.
