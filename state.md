# Session hand-off — B66 is the CONFIRMED-GOOD baseline (login works); my signal/IRQ work caused chaos

## CONFIRMED THIS SESSION (user-verified)
- **main == B66 tree (PR #1635). Login + boot work reliably ("works perfect" — user-tested).**
- My session's kernel-BEHAVIOR changes (B67→F412) made login CHAOTIC/intermittent (a race)
  and the keymap boot-wedge intermittent. Reset to the exact B66 tree fixed it.
- Suspect ranking for the race: **F410** (rewrote the EVERY-TICK IRQ entry/exit asm — added
  6 callee-saved saves + new fork scaffold + frame-offset shift; a subtle bug there corrupts
  preempted/forked tasks intermittently) > B67 futex parking > F411 rt_sigframe > B68 timerfd.
- The pre-push smoke did NOT catch it: it only checks `oxide login:` APPEARS, not that login
  → shell SUCCEEDS, and not repeatedly (the race is intermittent). **Any future scheduler/
  signal/IRQ change MUST be verified by repeated actual login→shell, not the smoke.**

## What B66 has (kept, working)
HHDM full direct map (>4GB RAM), disk-based rootfs (virtio-blk ext4, root+home imgs),
virtio-blk multi-sector perf, CI stub-blobs, 38 vendored tools, x86_64-musl-g++.

## What was DROPPED in the reset (redo carefully, one at a time, login-verified)
- futex WAIT_BITSET/WAKE_BITSET (B67) — made starship launch; **redo first, ALONE, verify
  repeated login still works** (it changed futex parking → could be the race, or innocent).
- timerfd ABSTIME (B68) — Go netpoller timer.
- rt_sigframe types/build/restore + IRQ full-GP save + async delivery (F409-F412) — the
  Go async-preemption mechanism. F410 (IRQ asm) is the prime chaos suspect — redo it LAST
  and most carefully, with repeated login + fork stress, in an env that can DRIVE qemu.

## Go-tools goal status: NOT achieved
duf/glow/micro (Go) need async signal delivery (SIGURG to a userspace-spinning thread). The
mechanism was built (F409-F412) but destabilized login → reverted. Redo requires a verify
loop that actually logs in + runs the tool repeatedly. starship (Rust, futex-only) DID work
under B67 — re-landing futex alone may restore starship without the IRQ-asm risk.

## HARD-LEARNED: this sandbox CANNOT drive/observe QEMU (root of tonight's thrash)
- QEMU works ONLY: foreground, short (<~30s), direct, NO stdin redirect:
  `timeout 30 qemu ... -serial stdio > /tmp/x.log 2>&1`, read the file SEPARATELY.
- FAILS: backgrounded qemu (reaped→empty), stdin pipe/`<file`/unix-socket/python-subprocess,
  cmds >~120s (tool kills+discards output). So I cannot drive interactive login. AGENTS can
  (different harness); or the USER runs `make qemu-x86` + login + pastes. USE THAT to verify.
- klog debug traces FLOOD serial + WEDGE boot — earlier "0 switches" readings were artifacts.
  Use TARGETED (arm-on-execve) traces only. Bash: foreground `sleep` BLOCKED; `set -e` aborts
  on any non-zero (guard `|| true`). SKIP_SMOKE=1 only when logically boot-safe (e.g. exact
  prior-passed tree).

## Known separate intermittent bug: keymap boot-wedge
Kernel stalls right after `keymap loaded: US QWERTY` (kmain.rs:649, before userspace), in
B66 too. Likely tty-write yield-point / CAT-smoke wedge class. Retry boot gets past it.

## Minor: /etc/machine-id EIO at boot; merged-/usr cosmetic taint.

## Counters: F=412, B=71, C=09, D=92. Author Chris Watkins <chris@watkinslabs.com>.
