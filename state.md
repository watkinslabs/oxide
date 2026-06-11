# state — session hand-off

Branch: B92-reap-pgid-wait-semantics (PR open). Investigated the "console
zombie" bug with the debug-reap trace. **Result overturns the prior framing.**
Roadmap: vty-plan.md.

## Landed this session (B92)
Reaping is PROVEN correct (trace + exhaustive case analysis + host tests) — the
prior "zombie on every console exit" framing was a mis-diagnosis from a trace
captured *before* the reap_one dump existed. B92 hardens + completes the path:
- Single source of truth `registry::wait_pid_matches` for all four POSIX wait4
  pid forms (-1/0/+tid/-pgid); used by reap_one/peek_one AND take_child_stop_event.
- Fixes real gaps: reap_one/peek_one silently dropped pid==0 and pid<-1 (so
  `waitid(P_PGID)` never reaped); take_child_stop_event matched pid>0 by VPID
  (wrong — clone returns the kernel tid; init-NS children have vtgid=0 so a
  specific-pid WUNTRACED wait never matched).
- 5 host unit tests (registry::wait_match_tests). spec-lint clean, both arches build.

## Headline
The state.md "every program exit leaves a Z zombie on the console" bug does
**NOT reproduce on the current tree at SMP=1**. With the new `reap_one` trace
(#1744) we can finally see the ZOMBIES list at reap time, and reaping is
CORRECT. The prior hypotheses were drawn from a trace captured *before*
reap_one tracing existed.

A *different*, real SMP=2 regression surfaced instead (below).

## How it was reproduced (harness — reusable)
Boot is driven by `make qemu-x86` (the qemu-MCP can't: it omits the root
virtio-blk disk → panics at kmain.rs:627). x86 serial = stdio; console = fb.
- `OXIDE_QEMU_QMP_SOCK=/tmp/oxide-qmp.sock` exposes QMP → inject **framebuffer**
  keystrokes into tty1 via `send-key` (helper: `/tmp/qmp_type.py line "ls"`).
- Serial driven via a FIFO kept open by a `sleep infinity` writer.
- Launch (headless, KVM):
    OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_KVM=1 OXIDE_QEMU_QMP_SOCK=/tmp/oxide-qmp.sock \
      setsid bash -c "exec make qemu-x86 SMP=N FEATURES=debug-reap > LOG 2>&1 < /tmp/oxide-qin" &
- klog/traces go to **serial** regardless of which tty triggered them.
- QMP `screendump`→PPM→ascii to read the fb console headless.

## SMP=1 findings (clean)
- Logged into BOTH ttyS0 (serial, via FIFO) and tty1 (console, via QMP send-key).
- Ran `ls`, `id`, `pwd`, `true`, `ls /`, `ps` on the console (~10 cmds).
- **Every** child reaped: `reap_one` finds the zombie (parent_tid match, bash
  uses pid=-1) → removed → next reap_one shows zombies_total=0. `ps`: no Z.
- Specific-pid reaps (login/PAM, parent=4096 pid=4104/05/06) also reap fine —
  so the "wait4 specific-pid mismatch" hypothesis is also dead.
- console-getty Started and NEVER Deactivated (stayed up the whole session).

## SMP=2 findings (THE real lead)
- System boots fully ("Reached target Oxide Default Target", startup 4.5s).
- **console-getty Started then Deactivated IMMEDIATELY** (dies right after start)
  → no fb-console login possible. Under SMP=1 it stays alive. This is the real
  regression behind "console broken under more CPUs".
- Its corpse is the zombie (tid=4096, parent_tid=0xC0DE0002 = systemd/PID1).
  systemd DID reap it via the signalfd/SIGCHLD path, but there's a transient
  race: cgroup-destroy ran before the reap → "Failed to destroy cgroup
  /system.slice/console-getty.service: Directory not empty" (line ~1537).
- serial-getty (ttyS0) separately wedges in its DSR `[6n` handshake loop and
  never prints "oxide login:" (worked under SMP=1). Couldn't get an SMP=2 shell.

## FIRST THING NEXT SESSION (after B92 merges)
Find why **console-getty exits immediately under SMP=2** (the actual bug).
Boot `make qemu-x86 SMP=2 FEATURES=debug-reap` (+ maybe debug for tty/vt) and
trace console-getty's exit: what syscall/path makes it exit ~0 right after
start. Suspect the fb console / vt_tty open/lock/ioctl path is not SMP-safe
(console-getty runs on /dev/console = fb). NOT a reaping bug — reaping is fine.
Second: serial-getty DSR-loop wedge under SMP=2 (separate getty/console issue).

## Code map (confirmed correct on SMP=1)
- Normal exit: 060_exit.rs:77/85 mark_done+signal_child_exit → schedule().
- Crash exit (SIGSEGV): mm-pmm/src/user_as/signal.rs:241-250 — SAME shape.
- zombies.rs: signal_child_exit:86 wakes parent on the LOCAL rq (no cross-CPU
  migration at wake → parent picked same CPU → its finish_task_switch drains
  reap_pending BEFORE its reap_one; this is why SMP=1/2 reaping is robust).
- reap_one:283 (pid=-1 any, pid>0 == kernel tid). clone returns kernel tid, so
  parent waitpid(kernel-tid) matches — no vpid/tid mismatch.
- reap_pending is per-CPU (runqueue.rs GLOBALS[cpu]); drained in
  oxide_finish_task_switch (schedule.rs:160), incl. first-run trampoline
  (hal-x86_64 context.rs:88). Only the boot-anchor idle skips it.

## Discipline
- THE LINUX WAY, real subsystem, no blind sched/MM patches.
- spec-lint clean + both arches every PR. Kill stale qemu (pgrep -f, comm is
  truncated >15 chars) before smoke. Dev shell is set -e → guard kill chains
  with `|| true` or they abort the rest of the script.
- Memories: project_tty_vt_remediation, project_pmm_double_free_teardown,
  feedback_linux_way_no_design_questions.
