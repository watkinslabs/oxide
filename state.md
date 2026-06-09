# Session hand-off — signal-delivery / Go-async-preemption

## What works NOW (on main, both arches boot)
- **Login works again** (B69 #1630). Boots GRUB→systemd→getty→login→shell.
- Merged this session: futex WAIT_BITSET (B67, starship launches), timerfd ABSTIME (B68),
  full rt_sigframe ABI types+IRQ-GP-save+build/restore on the SYSCALL path (F409/F410/F411),
  Task.cpu stamping in swap_current + owner-CPU wake routing (F412, the safe part).

## THE remaining broken thing: Go tools (duf/glow/micro) don't run
They need ASYNC signal delivery (SIGURG to a userspace-spinning thread on timer-IRQ exit).
F412 added `try_deliver_async_irq` (lapic.rs timer+resched arms, gic.rs) — but it CORRUPTS
the interrupted user frame → **login crashed back to getty**. DISABLED in B69 (the 3 call
sites are commented; search `DISABLED (B69)`). The syscall-tail delivery (F411) is unaffected.

### The bug to fix before re-enabling async delivery
`try_deliver_async_irq` (crates/kernel/fs/src/sig_dispatch.rs ~:644) builds the rt_sigframe
from the live IRQ frame (FrameSrc::Irq) and rewrites that IRQ frame IN PLACE (rip/rsp/rdi/
rsi/rdx). Something in the build-from-IRQ-frame OR the in-place rewrite clobbers the resumed
user context → crash. Suspects: (a) read_regs_x86 FrameSrc::Irq mapping (IrqFrameX86→sigcontext,
sig_dispatch.rs ~:131); (b) the new_sp/red-zone math writing over live user stack; (c) rewriting
the IRQ frame's GP slots that the epilogue pops vs the iretq frame. Debug with a TARGETED trace
(only the spinning binary), NOT the global klog traces — those FLOOD the serial and WEDGE boot
(that wasted hours; the "0 switches / killer never ran" readings were trace-flood artifacts).

## CRITICAL: test-harness reality in THIS sandbox (do not relearn the hard way)
- QEMU ONLY works run DIRECTLY in the foreground, short (<~30s), NO stdin redirect/pipe/socket.
  `timeout 30 qemu ... -serial stdio > /tmp/x.log 2>&1` then read the file in a SEPARATE call.
- Backgrounded qemu (`&` / run_in_background) gets REAPED → empty output. stdin pipe/`<file`/
  unix-socket/python-subprocess ALL fail here (sandbox). So I CANNOT drive interactive login/
  commands. AGENTS can (different harness) — delegate boot+input verification to an agent, OR
  ask the USER to run `make qemu-x86` + login + paste (they have a working interactive QEMU).
- Boot-time smokes (oxide-smokes.sh: sigurg_async_smoke + duf, gated on /etc/oxide-init-smokes)
  run via the rc script (rootfs.rs ~818-830) AFTER systemd+network — later than a 30s capture.
- The pre-push hook smoke works (boots both arches) but is the only reliable boot gate I have.
  SKIP_SMOKE=1 git push when the env can't run it + the change is logically boot-safe.
- The Bash tool: foreground `sleep` is BLOCKED; long (>~120s) commands get killed + output
  discarded; `set -e` aborts on any non-zero (guard every fallible cmd with `|| true`).

## Minor real issues seen at boot (not the crash)
- `Failed to truncate /etc/machine-id: I/O error` — systemd write to ext4 file returns EIO.
- `System is tainted: unmerged-usr:unmerged-bin:var-run-bad` — cosmetic (rootfs not merged-/usr,
  /var/run not a symlink to /run). Harmless.

## NEXT (in order)
1. Fix the async-delivery IRQ-frame bug (verify via a targeted trace + a USER test of login NOT
   crashing while a signal is delivered). Re-enable the 3 calls. Then verify sigurg_async_smoke
   PASSES + duf/glow/micro launch.
2. (later) /etc/machine-id EIO; merged-/usr layout; futex/wait_list owner-CPU routing matters
   once x86 AP scheduling is live (smp_x86.rs APs currently park in cli;hlt).

## Counters / workflow
max F=412, B=69, C=09. Author Chris Watkins <chris@watkinslabs.com>, no Co-Authored-By.
spec-lint clean before commit. Branch-per-change, gh pr merge --delete-branch.
