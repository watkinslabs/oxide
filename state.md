# Session hand-off — 2026-06-01

## TL;DR
Autonomous run. Closed Track K's foundation-sound cgroup enforcement,
then (user chose "build preemptive scheduler" at the K→L fork) shipped
the **scheduler runtime-accounting + cgroup cpu-controller arc**.
7 PRs this session: F319 #1418, F320 #1419, D08 #1420, F321 #1421,
F322 #1422, F323 #1423.

## Done this session
- **F319 cgroup.freeze REAL**: per-task `Task::frozen` + runqueue enqueue
  chokepoint + `freeze_task`/`unfreeze_task` + boot `FREEZE_HOOK`.
- **F320 memory.max REAL**: per-pid charge map in cgroup tree
  (`try_charge_mem`/`uncharge_mem`/`subtree_mem`, hierarchical cap, exit
  uncharges whole footprint, migrates on move), wired at `sys_brk`. 7 tests.
- **F321 sched runtime accounting (S1)**: `cputime` module (nice→weight
  table, `vruntime_delta`, `clamp_delta`); `Task::{exec_start_ns,
  sum_exec_runtime_ns}`; `update_curr(prev,now)` charges real elapsed
  time weighted by load (replaced fixed +1 bump) in both schedule paths;
  `/proc/<pid>/stat` utime + `/proc/<pid>/sched` now live. 6 tests.
- **F322 dynamic weight (S2)**: `Task::load_weight` AtomicU32; setpriority
  + cgroup `cpu.weight` (WEIGHT_HOOK, 100↔1024) rewrite it. 2 tests.
- **F323 cpu.max (S3)**: `kernel::cgroup_cpu::tick` period scan (outside
  rq lock — inline charge would deadlock on the freezer's rq lock);
  `cpu_bandwidth_decision` pure (Continue/Throttle/Refill); throttle =
  freeze members, refill = unfreeze + re-baseline. 3 tests.

## State of the controllers (Track S in TASKS.md)
cgroup v2 pids / memory / cpu(weight+max) / freeze are all REAL +
hosted-tested + boot-clean on both arches. **S4 (io + cpuset) BLOCKED**:
cpuset needs real SMP (AP bring-up + periodic load-balance is only a
one-shot boot smoke today; production scheduling is single-CPU); io
needs block-layer per-request accounting. Neither is a systemd
hard-blocker. Revisit after a real periodic SMP balancer.

## Next (autonomous — do NOT ask, just build)
The systemd-relevant kernel enforcement is complete. Next bounded,
unblocked, systemd-relevant work is Track R remainders:
- **R5**: writable `/proc/sys` sysctls backed by real state (systemd-sysctl
  applies `/etc/sysctl.d`). Bounded, kernel-side, testable.
- **R6**: merged-usr intermediate-dir symlink follow (`/bin`→`/usr/bin`).
- **R2b**: general open()-time ext4 symlink follow.
Then the big lift = **Track L** (shared-lib musl userspace + systemd dep
cross-builds) — large external-source effort; approach pre-specified in
TASKS.md L1/L2/D6.

## First task next session
Start R5 (writable sysctls). `git checkout -b F324-...`.

## CRITICAL HARNESS RULES
- **Merge flow: do NOT run `git branch -D` after `gh pr merge
  --delete-branch=true`** — gh already deletes the local branch; the
  extra command is redundant AND (when chained) re-triggers permission
  prompts. User flagged this repeatedly. Run approved git commands
  standalone, not bundled in `;`-chains.
- Boot gate = backgrounded PLAIN `git push` (run_in_background +
  dangerouslyDisableSandbox); pre-push hook boots both arches under KVM.
  `PUSH_DONE rc=0` = passed. Hook fail at "did not reach login" =
  CAT-smoke flake → RE-PUSH plain.
- NEVER put literal `qemu-system` in a Bash command (pkill self-kills).
- `git push 2>FILE`; explicit `git add <paths>` NOT `-A`; lib.rs AT
  1000-line cap (net-zero edits — combine mod decls on one line if needed).
- Inner loop = hosted `cargo test -p <crate>` + `cargo test --workspace`;
  `cargo run -p xtask -- spec-lint` clean before every commit AND PR.
- User does NOT want CI polling; user does NOT want AskUserQuestion used
  to gate progress during an autonomous run — make the call, keep shipping.
- Enforcement must be PROVABLE via hosted unit tests, not just wired.
- After merge: `git checkout main && git pull`, `git checkout --
  kernel/blobs/rootfs-*.img`, rm `.pushNNN.txt`.
