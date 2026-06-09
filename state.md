# Session hand-off — flaky x86 login ROOT-CAUSED + FIXED; diag suite landed (B75)

## Branch B75-login-hang-diag → PR #1658 (pushed). Diagnostics + the fix.

## THE FIX (dominant bug, verified)
Flaky x86 SMP=2 login = **PID 1 (systemd/ld-musl) exited 127** because its
stdout/stderr fds were EBADF. Cause: `run_as_task` (smoke/elf.rs) did `sti`
*before* spawning PID 1; the spawn enqueues the task Runnable + sets
need_resched BEFORE the caller installs the console fd table — a timer tick
in that window ran PID 1 fd-less → `writev`=-9 (EBADF) → exit_group(127) →
silent hang. 2-vCPU QEMU timing hit the window ~25%; SMP=1 ~never. arm was
immune (keeps IRQs masked until its idle loop, after fd-setup).
FIX (618ee718): move `sti` to AFTER the init spawn so PID 1 is fully formed
before first schedule. **Verified: 18× SMP=2 boots, 0 INIT-DEATH** (was ~25%).

## RESIDUAL (separate, rarer ~5% — under investigation at hand-off)
1/18 boots: systemd STARTS (banner + "Applying preset policy") then HANGS —
no exit, no fault, never reaches "Reached target"/login. Different from the
127 bug (that was pre-banner). `/tmp/vf-wedge-1.log`. hunt4 (/tmp/hunt4.sh,
25 rounds w/ boot-smoke sysrq-on-timeout) running to catch it WITH a task
dump (what is systemd parked on?). Next: read /tmp/r2-*.log + /tmp/bs4-*.out.

## DIAGNOSTICS SUITE (all built+verified this session, default-ON, R06-clean)
- `[INIT-DEATH]` — PID 1 exit announced loudly + task dump (060_exit.rs).
- Recent-syscall ring (sched::diag) — last 512 (tid,nr,ret); dumped on
  INIT-DEATH. This is what revealed writev=-9. Recorded at dispatch return.
- Liveness watchdog (Runnable spin >10s), per-task last-syscall.
- Default-ON fault/oops printer both arches (was debug-irq-gated → silent
  halt). any(debug-irq,debug-watchdog); zero bytes on healthy boot.
- Per-CPU heartbeat + cross-CPU hard-lockup detector (works on arm: APs run;
  x86 AP never starts so no 2nd observer there).
- NMI backtrace (x86): send_nmi_ipi + vec-2 print+iretq handler; sysrq.
- sysrq over serial: `<NUL>t` tasks `<NUL>w` summary `<NUL>c` per-cpu
  `<NUL>b` backtrace-all. boot-smoke injects on timeout (held-open FIFO).
- SSH hostfwd gated behind OXIDE_QEMU_SSH_FWD (default off; killed port-2222
  collisions).

## TEST RESULTS
- arm SMP=2: 10/10 login (immune — real APs run, masked-IRQ spawn ordering).
- x86 SMP=2 pre-fix: ~25% INIT-DEATH 127. post-fix: 0/18 (+ 1 residual hang).

## KNOWN GAPS (documented, not bolt-on'd)
- x86 cross-CPU observer: blocked — bring_up_aps_x86 returns 0 (AP never
  starts; TRAMP_PA RAM-corruption bug + gated P4 sched). Out of phase.
- arm FIQ register-dump poke: not wired (cross-CPU heartbeat covers arm).

## ENV NOTE
Agent bash sandbox kills background qemu unless dangerouslyDisableSandbox;
multi-line heredocs get newline-collapsed → write scripts via Write tool,
run as one line. SMP=2 verified via these /tmp/hunt*.sh loops; MCP is SMP=1.

## Counters: F=423, B=75, C=10, D=95. Author Chris Watkins <chris@watkinslabs.com>.

## First task next session
Read hunt4's captured residual dump (/tmp/r2-*.log) → identify what systemd
is parked on after "Applying preset policy" (~5%). Then fix that, re-verify.
