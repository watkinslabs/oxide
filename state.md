# Session hand-off — 2026-06-01

## TL;DR
Long autonomous run. Closed Track-K cgroup enforcement, then (user: "build
the preemptive scheduler", then "add the blocking SMP multi-CPU runqueues,
don't skip the hard work") built the scheduler-accounting + cgroup-cpu arc
AND cracked the SMP boot bugs on both arches. 9 PRs this session:
F319 #1418, F320 #1419, D08 #1420, F321 #1421, F322 #1422, F323 #1423,
F324 #1425, F325 #1426, B50 #1427.

## Done this session
- **cgroup v2 enforcement** (Track K1b): freeze (F319), memory.max (F320),
  cpu.weight (F322), cpu.max (F323) — all real + hosted-tested.
- **scheduler runtime accounting** (F321): `cputime` module, `update_curr`
  charges real elapsed time, weighted vruntime; `Task::load_weight`.
- **writable /proc/sys sysctls** (F324, R5).
- **x86 SMP=2 boot FIX** (F325): the boot migration smoke spawned permanent
  `loop{hlt}` kthreads that starved boot once real scheduling ran; masked
  for years by the always-`-smp 1` gate. Removed it; moved resched-IPI +
  coredump hooks to unconditional install. **x86 gate now `-smp 2`** (AP +
  balancer exercised every push). Periodic `balance_once` from kthread tick.
- **arm SMP=2 AP-start FIX** (B50): root cause via gdb-on-both-arm-CPUs —
  `psci::cpu_on` used `smc #0`, UNDEFINED at EL1 on QEMU virt (no EL3) →
  BSP faulted (ESR EC=0 at the smc), looped in vector handler. Fixed with
  HVC conduit. VERIFIED `make SMP=2 qemu-arm` → `aps_started=1` + login.

## NEXT (immediate, established work — S4a-arm in TASKS.md)
Make arm `ap_main` a real scheduling participant so the arm gate can flip
to `-smp 2` (it's `-smp 1` now; arm AP currently starts but is inert).
Mirror x86's `oxide_ap_entry_x86`. Concrete steps (gate-safe — arm `-smp 1`
enumerates no APs, so AP-path edits can't break the gating boot):
1. Per-AP GICv3 redistributor discovery: find the AP's own `gicr_va`
   (match `GICR_TYPER` affinity to the AP's MPIDR; redistributors are
   `gicr_base + idx*stride`). The BSP's `gic::enable(gicd, gicr)` only
   wired CPU0's redistributor.
2. In `ap_main` (crates/arch/hal-aarch64/src/smp.rs): `vbar::install_default()`
   + `gic::enable(gicd, ap_gicr)` + `sched::live::install_default_runqueue()`
   + DAIF unmask, then `wfi` loop (so resched SGIs wake it).
3. New `gic` SGI sender (`ICC_SGI1R_EL1` write) for the resched IPI;
   install `set_send_resched_ipi_hook` for arm; make `balance_once`'s
   wake-IPI cover arm (currently `#[cfg(x86_64)]`-only).
4. Verify via gdb-on-arm-SMP that CPU#1 reaches `ap_main` idle (not PC=0)
   AND runs a migrated task; then flip arm gate to `-smp 2` in
   tools/boot-smoke.sh.
Then S4a-timer (per-AP periodic timer + least-loaded placement), then
S4b (cpuset affinity), S4c (io controller).

## First task next session
`git checkout -b F326-arm-ap-participation`; start with per-AP GICv3
redistributor discovery (step 1 above).

## CRITICAL HARNESS RULES
- **Merge flow: NO `git branch -D` after `gh pr merge --delete-branch=true`**
  (gh deletes the local branch; the extra cmd re-triggers permission
  prompts — user flagged this repeatedly). Run git cmds standalone.
- Boot gate = backgrounded PLAIN `git push` (run_in_background +
  dangerouslyDisableSandbox); pre-push hook boots both arches.
  `PUSH_DONE rc=0` = pass. x86 gate `-smp 2`, arm `-smp 1` (boot-smoke.sh).
- **NEVER put a literal `qemu-system…` string in a Bash command** — `pkill
  -f` / pgrep self-match the wrapper shell and kill it. Kill stale qemu by
  PID derived from `ss -ltnp | grep :2222|:1234`.
- Manual SMP debug: `qemu-system-<arch> ... -smp 2 -s` + `gdb -ex 'target
  remote :1234' -ex 'thread apply all bt'`. IMPORTANT: rebuild the disk
  image via `make SMP=N qemu-<arch>` (or xtask qemu) — a bare manual qemu
  on `target/oxide-<arch>.img` can boot a STALE kernel (bit me on arm).
  Read serial via `-serial file:/tmp/x.txt`; grep with `-a` (NUL bytes).
- `git push 2>FILE`; explicit `git add <paths>` NOT `-A`; lib.rs AT
  1000-line cap (net-zero / one-line mod decls).
- Inner loop = hosted `cargo test -p <crate>` + `--workspace`; spec-lint
  clean before every commit AND PR. Enforcement must be hosted-tested.
- User does NOT want CI polling or AskUserQuestion gating an autonomous
  run — make the call, keep shipping verified work.
- After merge: `git checkout main && git pull`, `git checkout --
  kernel/blobs/rootfs-*.img`, rm temp `.push*.txt`.
