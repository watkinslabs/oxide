# state — session hand-off

Branch: main @ 185b372d. x86 SMP=2 boots; poll/select/epoll wakes are wired.
Roadmap: vty-plan.md.

## Landed this session (4 PRs, all merged, both arches green)
- **#1746 (B92):** unified wait4 child-selection predicate
  (`registry::wait_pid_matches`, -1/0/+tid/-pgid) for reap_one/peek_one +
  take_child_stop_event; closed pid==0/pid<-1 reap gap (waitid(P_PGID)) + the
  take_child_stop_event vpid-vs-tid bug. The "console zombie" bug was a
  MIS-DIAGNOSIS — reaping is correct. See [[project_console_zombie_resolved]].
- **#1747 (B93): the real SMP bug.** x86 AP (`ap_main_x86`) never enabled two
  per-CPU CPU features the BSP does: syscall MSRs (`install_syscall_msrs`) +
  SSE (`enable_sse`: CR0.MP, CR4.OSFXSR|OSXMMEXCPT). A user task on the AP #UD'd
  (syscall, or the first SSE insn — musl uses them everywhere) → halted the AP →
  boot wedged. Now at full CR0/CR4/MSR parity with the BSP. Added
  `OXIDE_QEMU_GDB=1` (xtask) → gdb stub on :1234 (how it was pinned). See
  [[project_smp_ap_cpu_state]].
- **#1748 (B94):** wire `notify_poll_waiters`/`notify_epoll_waiters` at the tty
  RX + hangup sites. `notify_poll_waiters` had ZERO callers — poll/select on the
  console never woke on input (lagged ~100 ms).
- **#1749 (B95):** extend the poll-wake to AF_UNIX sockets, pipes (all 6
  readiness sites), and eventfd. Every fd poll-bit transition now wakes
  poll/select/epoll waiters; pipes/eventfd previously woke NEITHER global list.

## SMP=2 status: reliable
Across the B93/B94/B95 pre-push hooks, SMP=2 reached login on BOTH arches every
time (attempt 1) — 6 clean boots. The B93 SSE fix appears to have also killed
the documented "systemd exits ~25% right after keymap" flaky race (that was a
process hitting the SSE #UD on the AP). No residual flake observed.

## Open / next
- **Remaining poll-wake sites (larger, NOT clean single-site):** `timerfd`
  (clock-driven — poll computes from monotonic_ns vs expiry, no event site;
  needs the deadline scanner to wake pollers on expiry; the ~100 ms rescan is
  the current mechanism) and **TCP sockets** (net/sock*.rs, tcp_conn.rs —
  data-arrival sites in the net stack wake NEITHER global list; bounded by the
  100 ms rescan). signalfd is already covered (signal delivery wakes the
  target via wake_task_for_signal). The bounded sites (tty, pipe, unix socket,
  eventfd) are done (#1748/#1749).
- **100% CPU with ≥2 htops** (state.md's old poll-spin item): the console
  poll readiness is ALREADY correctly gated (n_tty poll → has_input;
  console/lib.rs:144 fix) and poll now sleeps + wakes correctly (B94/B95). If a
  100% spin still reproduces it's htop-specific (/proc read loop), NOT a kernel
  poll bug — needs a live htop-on-fb-console repro to confirm, don't blind-fix.
- Resume the vty-plan.md / phase ladder (`00§3`) — audit the lowest unfinished
  phase before starting a branch.

## Diagnosis tools that worked (reuse)
- **GDB for SMP wedges:** `OXIDE_QEMU_GDB=1 make qemu-x86 SMP=2 FEATURES=debug-reap`,
  boot to the wedge, `gdb -q -nx -batch -x cmds ELF` → `target remote :1234`,
  `info threads`, per-vCPU `bt`/`p/x $cr0`/`p/x $cr4`/`x/4i $rip`. The in-kernel
  serial-sysrq dump is unreliable when a CPU is halted (UART not polled).
- Fast loop = host tests (`cargo test -p <crate>`) + the pre-push hook as the
  boot gate. Do NOT inner-loop on full boots.

## Harness hygiene (cost real time this session)
- ALWAYS `pkill -9 -x qemu-system-x86_64` + confirm `fuser
  kernel/blobs/root-x86_64.img` free before booting (overlapping VMs fight the
  write lock). Orphaned qemus reparent to the agent/systemd --user.
- Dev shell is `set -e`: a `git push` after a `pkill`/`fuser` chain aborts
  before the push — run `git push` as its OWN command.
- `pgrep -f "githooks/pre-push"` matches your OWN waiter loops (false "hook
  running"). Check `git ls-remote` for the real push state.

## Discipline
- THE LINUX WAY; no blind sched/MM/poll patches; no hypothesis fixes (the
  zombie + poll-spin both turned out mis-diagnosed). spec-lint clean + both
  arches every PR. Memories: project_smp_ap_cpu_state,
  project_console_zombie_resolved, feedback_verify_left_no_bolton.
