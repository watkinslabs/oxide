# Session hand-off — 2026-06-01

## TL;DR
Very long autonomous run. Closed Track-K cgroup enforcement + the
scheduler-accounting/cgroup-cpu arc, then cracked **real SMP on BOTH
arches** end-to-end (the user's "don't skip the hard SMP work" ask).
12 PRs this session (F319-F327 + B50 + doc PRs).

## Done this session
- cgroup v2 enforcement: freeze (F319), memory.max (F320), cpu.weight
  (F322), cpu.max (F323) — all hosted-tested.
- scheduler runtime accounting (F321): `cputime`, `update_curr`,
  `Task::load_weight`.
- writable /proc/sys sysctls (F324, R5).
- **SMP, both arches `-smp 2`, verified every push:**
  - F325: fixed x86 SMP=2 boot hang (boot migration smoke spawned
    permanent `loop{hlt}` kthreads that starved boot once real scheduling ran;
    masked by the always-`-smp 1` gate). Periodic `balance_once` from the
    kthread tick; resched-IPI + coredump hooks unconditional.
  - B50: arm PSCI conduit `smc`→`hvc` (QEMU virt has no EL3; SMC at EL1
    is UNDEFINED → BSP faulted). AP starts.
  - F326: arm AP scheduling participation — `ap_main` installs VBAR +
    per-AP GICv3 redistributor (`gicr_base()+aff0*GICR_STRIDE`) + resched
    SGI + per-CPU runqueue; `gic::send_sgi`/`send_resched_ipi`
    (ICC_SGI1R_EL1); balancer wake-IPI generalized off `#[cfg(x86_64)]`.
  - F327: the entry fix — PSCI started the AP MMU-OFF at a high VA
    (gdb: PC=0x200, VBAR=0). Wired Limine's aarch64 SMP request so APs
    come up MMU-ON at our entry (like x86). gdb-verified CPU#1 reaches
    `ap_main` healthy + idles with runqueue installed. **arm gate → -smp 2.**

## State of SMP (Track S)
Both arches boot `-smp 2` to login every push (x86 23s, arm 26s). AP is a
healthy participant (online, VBAR, GIC CPU-interface, per-CPU runqueue,
resched SGI). `balance_once` runs periodically + wakes the destination AP
via IPI/SGI on both arches.

## cgroup v2 controllers: COMPLETE + enforced (Track K1b closed)
pids, memory.max, cpu.weight, cpu.max, freeze, cpuset.cpus — all real,
hosted-tested, enforced on real SMP. (F319/F320/F322/F323/F328/F329.)

## Scheduler/SMP/cgroup DOMAIN: COMPLETE (16 PRs F319-F330+B50)
Real preemptive SMP both arches (-smp 2 every push): AP participation,
per-AP timers, balancer, resched IPI/SGI, CPU affinity. Full cgroup v2
controller surface enforced: pids, memory.max, cpu.weight, cpu.max,
freeze, cpuset.cpus. All hosted-tested + both-arch boot-verified.

## cgroup v2: io.stat now REAL too (F331)
IO_CHARGE_HOOK at the page-cache submit_sync chokepoint → per-cgroup
io_{r,w}bytes/ios; io.stat rolls up the subtree. **LESSON (important):**
`charge_io` MUST use `TREE.try_lock` not `lock` — the cgroup TREE
spinlock does NOT disable preemption (sync/lib.rs `lock()` just spins),
so taking it on a hot/frequent path under F330's SMP preemption
deadlocks (preempted holder + spinning caller). First cut wedged x86
boot 2/2; try_lock (drop sample on contention) → 3/3 clean. ANY future
hot-path TREE access must try_lock or move off the tree lock.

## NEXT
- **io.max throttle / io.weight** (last cgroup enforcement bits): deep +
  hard to verify (needs a measured-io probe under a cap) + marginal for
  systemd. Mind the preemption-lock lesson above. Lower priority.
- least-loaded placement: UNNECESSARY (spawn-local + balance is correct).
- cpuset.mems: cosmetic (single NUMA node).
- **Track L — the big next phase** toward the systemd distro. Concrete
  bounded first step = **L1**: shared-lib musl runtime + system lib tree
  (`/lib`,`/usr/lib`, ld-musl config) + dynamic-link build policy + xtask
  staging of `.so`s. This is kernel/build-side (no external systemd source
  yet) so it's a clean start. Then L2 (cross-build shared deps both
  arches), then D6 (vendor systemd). See TASKS.md L1/L2/D6.

## First task next session
Begin **Track L1**: `git checkout -b F332-shared-musl-runtime`. Audit
docs/29a (userspace platform) + how userspace is currently statically
linked (tools/xtask build of busybox/.c probes), then stage a shared
ld-musl + /lib tree + a dynamic-linked "hello" to prove the loader path.
(io.max throttle is deferred — deep + marginal; the cgroup surface is
otherwise complete + enforced.)

## CRITICAL HARNESS RULES
- **NEVER run `git branch -D`** (any form) — it always prompts; user
  flagged repeatedly. `gh pr merge --delete-branch=true` deletes the
  local branch already. Leave stray local branches; do not clean them.
- **NEVER put a literal `qemu-system…` string in a Bash command** — pkill
  -f / pgrep self-match the wrapper shell. Kill stale qemu by PID from
  `ss -ltnp | grep :2222`/`:1234`.
- Boot gate = backgrounded PLAIN `git push` (run_in_background +
  dangerouslyDisableSandbox); pre-push hook boots BOTH arches `-smp 2`.
  `PUSH_DONE rc=0` = pass.
- Manual SMP gdb: `qemu-system-<arch> ... -smp 2 -s` + `gdb -ex 'set
  architecture aarch64' -ex 'target remote :1234' -ex 'thread apply all
  bt'`. REBUILD the image via `xtask image --arch <a>` or `make SMP=N
  qemu-<a>` first — a bare qemu on a stale `target/oxide-<a>.img` boots
  the OLD kernel (bit me). Serial via `-serial file:`; grep with `-a`.
- Run git cmds standalone (not chained), explicit `git add <paths>`,
  spec-lint clean before commit+PR, lib.rs ≤1000 lines (one-line mod
  decls / net-zero). No CI polling, no AskUserQuestion gating autonomy.
- After merge: `git checkout main && git pull`, `git checkout --
  kernel/blobs/rootfs-*.img`, rm temp `.push*.txt`.
