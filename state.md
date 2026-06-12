# state — session hand-off

Branch: **main** (clean). All this session's work merged.

## Merged this session
- #1768 P17-08 VT font-select SGR 10/11/12 + CP437 — box-drawing corners on
  TERM=linux (htop symptom #2). New crates/kernel/vt/src/cp437.rs (data table;
  font untouched). disp_ctrl mode: SGR 11 = CP437 direct, 12 = +toggle_meta,
  10 = back to UTF-8.
- Softirq subsystem made Linux-faithful end-to-end (CPU-STALL root cause was a
  softirq livelock, NOT the VT branch — wedged CPU RIP was in
  drv_virtio_net::modern::rx_drain_softirq via run_pending looping unbounded):
  - #1764 B105 __do_softirq restart gate (MAX_SOFTIRQ_RESTART=10 + time + need_resched)
  - #1765 B106 ksoftirqd kthread (deferral target)
  - #1766 B107 per-CPU PENDING/IN_PROGRESS + per-CPU pinned ksoftirqd + per-CPU
    drain from every CPU's irq_exit (was BSP-only global)
  - #1767 B108 local_bh_disable/local_bh_enable/spin_lock_bh on preempt_count
    (Linux bit-field SOFTIRQ field); IN_PROGRESS bool retired; sched::bh module
  See auto-memory project_softirq_livelock.md for the full structure.

## htop symptoms (SMP=4) — all CLOSED
1. 1 CPU -> #1763 (dynamic /sys cpu). 2. box corners -> #1768. 3. CPU-STALL ->
   softirq livelock, #1764-#1767.

## Open / next candidates
- Softirq optional follow-ups (NOT blockers): live RX-flood verification under
  qemu MCP (gate trip + ksoftirqd takeover never watched live); /proc/softirqs
  per-CPU counters (oxide counters still global diag). Two deliberate
  divergences kept + documented: raise() no process-ctx wakeup_softirqd
  (fbcon/klog under rq-lock reentrancy risk); ksoftirqd 100ms park backstop.
- vty-plan RC3 remaining (docs/57): DA/DECID answerback, DECCKM ?1, bracketed
  paste ?2004, IRM insert, OSC palette 4/104. RC1: console-getty DSR wedge at SMP>=2.
- Pre-existing unmerged branches: B73-console-autologin, P16-01-uts-ns-fork-inherit.

## First task next session
Pick lowest unfinished phase-17 tty/login item (vty-plan RC3) OR audit phase
ladder per 00§3. `git -C /home/nd/oxide2 log --oneline -10 main` for context.
