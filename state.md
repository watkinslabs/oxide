## Handoff: kalloc/Arc corruption hunt — 2 fresh concrete leads, root cause still open

### Headline
Long-running hunt for a memory-corruption bug that crashes every boot around the
`[ZRAM-SYSFS] disksize=...` event (bare `debug-boot` smoke, ~15-25s repro, see
recipe below). 9 real, independently-valuable UAF/race bugs fixed and merged this
session (B1325-B1331, list at bottom) — NONE confirmed as the actual root cause;
corruption still reproduces after all of them. This session's newest work (below)
found two fresh, non-kalloc-internal crash samples that point at a specific new
class of bug: something frees an object while a raw pointer into it is still live,
and the freed memory gets legitimately reused/reinitialized by kalloc, silently
scribbling a live-looking object. **Not yet fixed — this is the actual open task.**

### NEW this session: two fresh crash samples, same smp=1 fast repro
Hardware-watchpoint diagnostic (`debug-hw-watchpoint`, DR0-DR3-based, catches a
write to a freed HoleHdr's rip live) was extended with disarm-on-legitimate-realloc
and re-tested: **all hits still resolve to legitimate kalloc-internal code**
(`HoleList::add_free_region`/`alloc`, `AddressSpace::new` memset). This angle is
conclusively exhausted — don't revisit it.

Went back to the plain `smp=1` repro instead. Two boots of the same build hit two
DIFFERENT crash shapes at the same trigger point (confirms the non-determinism is
real, not build-dependent):

1. **rip=0 kernel-mode instruction-fetch fault — a `ret` popped a zeroed value.**
   `rsp`/`rbp`/`rbx`/`r12`/`r15` all resolved into `kalloc::STATIC_HEAP` (executing
   on a kalloc-backed kernel stack, expected). `r13` == exactly
   `sched::live::runqueue::GLOBALS`. This is `oxide_context_switch`'s `ret`
   (`crates/arch/hal-x86_64/src/context.rs`) popping a saved-RIP slot that should
   hold a valid code pointer but holds `0`. `oxide_finish_task_switch`
   (`crates/kernel/sched/src/live/schedule/switch.rs`) ALREADY documents fixing one
   instance of exactly this bug class (write `switched_from->on_cpu=false` BEFORE
   draining `reap_pending`, else the write lands in freed-then-reused memory — "the
   ~55s live-gnome heap-corruption blocker"). This sample is almost certainly the
   same bug class recurring at a different site. Checked `zap_other_threads()`
   (execve de-threading) — doesn't apply here (single-threaded process, no
   siblings). **The specific extra raw-pointer-outlives-last-Arc site is not yet
   found.**

2. **Different boot: `#PF` read, `cr2=0x10` (null+0x10 deref), kernel mode**, inside
   `net::sock::inode::InetFileOps` (`ioctl_int`/`poll_open_file` per addr2line).
   Registers again resolve into `kalloc::STATIC_HEAP`. ~15ms earlier in the SAME
   boot: `[B288 dgram .../journal/socket pid=3235774466]` — `sched::live::current()
   .map(|t| t.tgid.load(...))` (`crates/kernel/net/src/lib.rs:191`) read back a
   garbage pid (3235774466 = 0xC2E0C142, not a real tid). Second independent piece
   of evidence for the same "live object read/written after its backing memory was
   freed and reused" bug — this time hitting `Task.tgid` instead of a HoleHdr or a
   saved-RIP slot. Supports: this is a generic UAF at the allocation level (kalloc
   frees something still-referenced), not a kalloc-internal logic bug.

### New diagnostic added this session (in tree, not yet a PR)
`crates/kernel/sched/src/task/lifetime.rs`: `Task::drop` now emits `[TASK-DROP]
tid=... stack_top=0x... stack_len=0x...` under `debug-boot`. Checked both samples
above against it — **neither crash address overlapped a recently-dropped Task's
stack range**, so the bug is NOT "a whole Task (and its stack) gets fully dropped
while still scheduled." It's narrower: some other object (maybe `InetFileOps`,
maybe a smaller sub-allocation) is what's getting freed too early. Worth a small
standalone PR on its own (cheap, real, useful for future sessions) even before the
root cause is found.

### Concrete next steps (priority order)
1. **Chase sample 2 first — most specific lead.** Find `sched::live::current()`'s
   implementation (per-CPU "current task" pointer, likely
   `crates/kernel/sched/src/live/schedule.rs` or similar). Check whether it can be
   read from a context (IRQ/softirq) that races the owning CPU's own
   `rq.swap_current` — reproduces at `smp=1`, so any race here is IRQ-vs-process on
   ONE CPU, not cross-CPU. Also find what allocates/frees `InetFileOps` and check
   for a socket-close-vs-still-epoll'd/still-fd-table'd race (same shape as the
   already-fixed `fd_table`/`mm`/`exe_path` Task-field UAFs, but on a socket object
   instead of a Task field).
2. Sweep `net`/`sock` crates for the SAME shape as the already-fixed `on_cpu` bug:
   an `Arc::into_raw`/`Arc::from_raw` pair where something writes through the raw
   pointer after a sibling path may have already reconstituted+dropped the Arc.
   This area hasn't been swept yet (prior sweep this session covered only
   sched/Task fields: fd_table/mm/exe_path/parent_arc/cmdline/environ/rlimits).
3. Do NOT return to the hardware-watchpoint approach (exhausted) or loop >2-3 boots
   chasing one hypothesis — user has explicitly forbidden boot loops. Read code /
   grep for the raw-pointer-outlives-Arc pattern first; boot only to confirm a
   specific fix.

### Fast-repro recipe
```
mcp__qemu__qemu_start(arch=x86_64, features="debug-boot,debug-dealloc-diag", smp=1)
mcp__qemu__qemu_continue(...)   # times out at 120s internally, boot continues regardless
# wait ~25-35s, then qemu_serial() and grep for FAULT/PANIC/TASK-DROP/B288
```
`debug-dealloc-diag` = kalloc-only error-tag surfacing, zero behavior change, fast
(~25s). `debug-heappoison` = same repro but ~500s (corruption-probe/redzone/
quarantine) — **user has explicitly vetoed this for iteration**, only use it if
truly necessary and expect one boot, not a loop. Always `qemu_list` + `qemu_stop`
stale instances before starting a new one.

### Housekeeping / prior fixes this session (all merged, don't re-investigate)
9 real cross-CPU UAF / logic bugs found + fixed, none confirmed as THE root cause:
- B1325 (PR #3767): corruption-probe MANAGED-flag + huge-page VA fix.
- B1326 (PR #3768): `fd_table`/`mm`/`exe_path` raw `UnsafeCell` foreign-task races
  → pin-lock-and-clone pattern (mirrors existing `mm_pin_lock`/`clone_mm`).
- B1327/B1328 (PR #3770, #3772): ext4 `writeback_idxs` stale-frame UAF read, fixed
  via `try_lock_page`/`unlock_page` pin (mirrors zsmalloc's existing pattern).
- B1329 (PR #3773): `parent_arc` cross-CPU race (has a genuine foreign WRITER via
  `reparent_children`, not just foreign readers).
- B1330 (PR #3774): `cmdline`/`environ` torn-String foreign-task reads.
- B1331 (PR #3776): `rlimits` foreign-task races (`prlimit64`, `sched_setattr`).
- Checked clean, no fix needed: `ctty` (self-only access).
- Found, NOT fixed (different shape, lower priority for this hunt): `fpu_state` —
  `ptrace_fpu::get_fpregs`/`set_fpregs` touch a target task's FPU state with an
  unverified "target parked under ptrace" assumption (missing authorization check,
  not just missing a lock). Needs its own PR.
- Not audited: `sigactions`, `seccomp_filters`, `posix_timers`, `arch_ctx`.
- Ruled out (don't re-chase without new evidence): double-owned/double-mapped buddy
  frame theory (guards that would catch it never fired); ELF-loader BSS-zero
  overrun (can't produce the observed pattern); hardware-watchpoint-catches-an-
  external-writer (exhausted this session, see above).

First command next session: read `crates/kernel/sched/src/live/schedule.rs` (or
wherever `sched::live::current()` lives) and `net`/`sock`'s `InetFileOps`
alloc/free path per "Concrete next steps" item 1 above.
