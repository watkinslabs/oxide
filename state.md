# Session hand-off — RESET to F411 (login known-good); Go-async reverted

## State of main NOW
- **Reverted F412 (async signal delivery) + B69** (B70 #1633) → back to the F411 code where
  login was VERIFIED working (shell + commands, by me + an agent). Kept: futex WAIT_BITSET
  (B67), timerfd ABSTIME (B68), full rt_sigframe build/restore on the SYSCALL path (F409-411).
- Why: F412's `try_deliver_async_irq` (async IRQ-exit signal delivery) corrupted the
  interrupted user frame → login crash; B69 disabled it but login still didn't complete;
  cleanest fix = revert to F411 known-good. Go async-preemption (duf/glow/micro) is NOT
  solved — redo it in an env where the boot can be observed/driven.

## Known separate bug: intermittent keymap boot-wedge
Boot sometimes stalls right after the KERNEL prints `keymap loaded: US QWERTY`
(kmain.rs:649 — early kernel init, BEFORE userspace). Pre-existing + intermittent (F411 too).
Next kmain steps: virtio-net legacy init, ptrace install, `smoke::elf::run_as_task` (first
user ELF), spawn_timer_driver, halt_forever. Likely the tty-write yield-point / CAT-smoke
wedge class. Retry boot usually gets past it. Real fix = the tty ONLCR yield-point gap.

## HARD-LEARNED: this sandbox cannot drive/observe QEMU (do not relearn)
- QEMU works ONLY: foreground, short (<~30s), direct, NO stdin redirect:
  `timeout 30 qemu ... -serial stdio > /tmp/x.log 2>&1` then read the file SEPARATELY.
- FAILS here: backgrounded qemu (reaped → empty), stdin pipe/`<file`/unix-socket/python-
  subprocess (all empty/fail), commands >~120s (tool kills + discards output).
- So I CANNOT drive interactive login/commands. AGENTS can (different harness) — delegate
  boot+input verification, OR have the USER run `make qemu-x86` + login + paste.
- Debug traces via klog FLOOD the serial + WEDGE boot — the "0 switches / killer never ran"
  readings earlier were flood artifacts. Use TARGETED (arm-on-execve) traces only.
- Bash tool: foreground `sleep` BLOCKED; `set -e` aborts on any non-zero (guard `|| true`).
- pre-push smoke is the only reliable boot gate; SKIP_SMOKE=1 when env can't run it + change
  is logically boot-safe (e.g. reverting to prior smoke-passed code).

## NEXT
1. Confirm login works on main (user/agent boot — I can't). 
2. Go-async-preemption REDO (in verifiable env): the bug was `try_deliver_async_irq` rewriting
   the live IRQ iretq/eret frame (FrameSrc::Irq path in sig_dispatch.rs) clobbering the
   resumed user context. Needs careful frame-source handling + a USER test (login must not
   crash while a signal is delivered) before re-landing.
3. keymap boot-wedge (tty yield); /etc/machine-id EIO; merged-/usr layout (cosmetic taint).

## Counters: F=412, B=70, C=09, D=91. Author Chris Watkins <chris@watkinslabs.com>.
