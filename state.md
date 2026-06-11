# state — session hand-off

Branch: main. Last merged: #1736 (P17-01-tcflush). Active roadmap: **vty-plan.md**.

## Headline
User reported: can't log in (serial AND graphical), console "renders like
garbage, nowhere near vt100." Drove the live VM (qemu MCP) + a 5-agent code
audit; the changelog over-claimed (console+drivers "done"). Corrected the
diagnosis and started the TTY/VT remediation program (vty-plan.md, P17-01..06).

## What's PROVEN (live, both KVM+TCG)
- Kernel/login/shell are functionally sound: `root` → shell → `id` → `uid=0`;
  `sleep 2; echo X` flushes on its own → timer ticks + idle output flush WORK.
- Default termios has **IXON off** → ldisc write is synchronous. The "prompt
  appears only on input" seen over the qemu-MCP serial bridge is a BRIDGE
  artifact, not a kernel stall. (Refuted the "LAPIC timer dead" theory.)

## Root causes (vty-plan.md has full file:line detail)
- **RC1 serial login** = missing `tcflush` → stale terminal-query answerback
  (`ESC[r;cR`, kernel-injected during boot) + type-ahead contaminate the
  username read → login fails → getty respawns ("it resets"). **FIXED in
  #1736** (TCFLSH/TCSETSF input flush). NOTE: the qemu-MCP can't reproduce the
  contamination (it doesn't auto-reply to `ESC[6n`), so the *live* end-to-end
  serial-login fix needs confirmation on a REAL terminal / boot-smoke-login.sh.
- **RC2 graphical login (black screen)** = VT-identity split: getty runs on
  fbcon vc0 but VT switching + keyboard target vc1..N; keyboard hard-pinned to
  vc0 ignoring foreground(). CONFIRMED, not yet fixed. (P17-05)
- **RC3 emulator gaps** (garbage render): no ECH `CSI X`, no alt-screen
  `?1049/?47`, no DA `CSI c`/DECID reply, missing SGR dim/italic/blink/strike,
  no bracketed-paste/keypad, OSC/DCS parse bugs. CONFIRMED. (P17-03/04)
- **RC4 job-control signals**: `Sig` enum only has Hup/Int/Quit/Tstp — MISSING
  SIGTTIN/SIGTTOU/TOSTOP, broken pty SIGHUP drain, no SIGCONT-on-hangup, no
  orphan-pgrp, TIOCNOTTY-on-pty no-op, no auto-ctty. CONFIRMED. (P17-02)
- **RC5 tty::live not retired** (changelog lied) — survives as buggy kbd router.
  Retire after RC2. (P17-05)
- **RC6 docs lie** — fix CHANGELOG/state.md/docs/28 + delete dead scratch md.

## Open / next (autonomous: "both, serial first; don't stop")
1. **Confirm RC1 end-to-end** on a real terminal (boot-smoke-login.sh x86/arm)
   — the MCP can't show the contamination fix. If serial login still flakes,
   the answerback-timing (deferred tick-drain delivering CPR after agetty's
   size-read times out) needs addressing too.
2. **P17-02 job-control signals** (RC4) — pure, hosted-testable, directly
   serves the user's "support ALL SIGNALS" demand. Add Sig::Ttin/Ttou/Cont +
   the read/write gates + pty SIGHUP drain.
3. **P17-05 fbcon VT-unify** (RC2) — the graphical-login fix (vc1 default fg,
   /dev/console→foreground VT, foreground-aware keyboard, getty on tty1).
4. **P17-03/04 emulator** (RC3) — ECH, alt-screen, DA, SGR attrs, brkt paste.
5. **P17-06 docs**.

## First command next session
    ./tools/boot-smoke-login.sh x86 600   # confirm #1736 fixed serial login
    git checkout -b P17-02-jobctl-signals
    grep -n "pub enum Sig" crates/kernel/tty/src/ldisc/mod.rs

## Discipline reminders
- spec-before-code OK (docs/28 FROZEN). spec-lint clean every commit/PR.
- Lockstep BOTH arches every PR. Verify-left: hosted cargo test is the dev loop,
  qemu MCP for live gates. qemu-MCP serial bridge buffers — verify real login
  via boot-smoke-login.sh, not MCP keystrokes.
- Don't `git add -A` blindly (it swept scratch md into #1736; D03 cleaned up).
