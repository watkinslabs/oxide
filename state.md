# state — session hand-off

Branch: main @ f0b0e75b. Active work: **console zombie bug** (reap path).
Roadmap: vty-plan.md. MCP note: drive qemu via the qemu MCP (it dropped mid last
session; restart reconnects it). debug builds are flood-free now — use debug-reap.

## FIRST THING NEXT SESSION
Reproduce the zombie + capture the reap_one trace, which pins the bug:
    make qemu-x86 FEATURES=debug-reap        # (MCP: qemu_start, or boot-smoke)
    # log in on the CONSOLE (graphical window), run `ls`, let it return
    # grep serial for: signal_child_exit | wake_wait4_parent | reap_one | zombie tid
The `reap_one` line shows the ZOMBIES list at reap time → answers the open question.

## The bug (console: every program exit leaves a Z zombie; serial reaps fine)
Reproducible EVERY exit on the framebuffer console. Captured trace (console, real):
    signal_child_exit child=4102 parent_tid=4100 parent_upgrade=1
    wake_wait4_parent  parent_tid=4100 wait4_waiters_found=1
So the WAKE path WORKS: parent found (Weak upgrade ok → SIGCHLD sent), parent WAS
parked in wait4 (waiters_found=1 → woken). Yet the zombie persists → the **reap
itself** fails after the wake. The `reap_one` trace (added this session, #1744)
will show whether the zombie is even IN the ZOMBIES list, or a parent/pid mismatch.

### Ruled out (by code reading)
- clone returns child_tid (kernel tid); reap_one matches t.tid==pid → consistent
  (NOT a vpid/tid mismatch in the basic path).
- exit_group(231) routes to sys_exit (060_exit.rs) which DOES call
  signal_child_exit (line 85). So the exit path isn't bypassing SIGCHLD.
- Zombie enqueue: sys_exit → schedule() → prev is Zombie → stashed in per-CPU
  `reap_pending` (schedule.rs:455) → INCOMING task's oxide_finish_task_switch
  (schedule.rs:160-165) drains it → enqueue_zombie into ZOMBIES. Looks correct.

### Leading hypotheses (the reap_one trace decides)
1. Zombie marked Z (shows in ps) but NOT in ZOMBIES list when parent's reap_one
   runs (reap_pending drain race / wrong task drains it) → reap_one finds nothing.
2. Parent 4100's wait4 is for a DIFFERENT pid than 4102 (shell has >1 child;
   wake_wait4_parent wakes ALL waiters for the parent regardless of pid, but
   reap_one(4100, specific_pid) won't match 4102) → 4102 never reaped.
Key files: 061_wait4.rs (loop), zombies.rs (reap_one:274 w/ trace, signal_child_exit:86,
wake_wait4_parent:176), schedule.rs (149 finish_task_switch, 450 zombie stash).

## Diagnostics in place (cfg-gated, zero default cost)
- **debug-pmm** (#1741): PMM double-free culprit ring (free Location). For the
  crash-teardown double-free (latent; only on a crashing process; arrow fix
  removed the htop-crash trigger so it stopped recurring).
- **debug-ssh** (#1742): exit/wait4/signal-child trace — BUT also enables the
  per-syscall flood → unusable (floods serial, blocks login).
- **debug-reap** (#1743, #1744): ONLY the reap traces (signal_child_exit +
  wake_wait4_parent + reap_one zombie-list dump), NO syscall flood. USE THIS.

## Landed this session (console/tty)
- #1736 tcflush (TCFLSH/TCSETSF input flush) — stale-answerback login fix.
- #1738 serial/fb console SPLIT (P17-05): /dev/ttyS0 serial-only; /dev/console &
  tty1..N = video VTs (vt_tty), rendered once; keyboard→fg VT; fbcon fg slot 1;
  serial-getty@ttyS0 + console-getty both run. Verified both arches.
- #1740 arrows/nav/F keys → escape sequences on the fb console (keymap). NOTE:
  this also stopped htop crashing → stopped the double-free panic recurring.

## Still open (from user testing the console)
- **Zombies** (above) — THE active bug.
- **100% CPU when ≥2 htops** — poll-spin: sys_poll (007_poll.rs:106) parks with a
  20ms RESCAN_NS fallback (poll wait-queue not woken by all ready-sites); 2
  non-sleeping pollers peg a core under the cooperative scheduler. Likely same
  root as zombies (video-VT wake path). Fix candidate: wire vt_tty input →
  notify_poll_waiters so poll sleeps the full timeout.
- Rendering (line-draw/blocks): per the screenshot it actually renders fine now;
  not a priority.
- "Only 1 CPU" = default SMP=1; use `make qemu-x86 SMP=2`. Not a bug.

## Discipline
- THE LINUX WAY, real subsystem, no blind MM patches (don't mask the double-free).
- spec-lint clean + both arches every PR. Kill stale qemu-system before smoke
  (vsock CID conflict false-fails). Don't `pkill -f qemu` (matches own shell).
- Memories: project_pmm_double_free_teardown, project_tty_vt_remediation,
  feedback_linux_way_no_design_questions.
