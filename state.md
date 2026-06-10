# Session hand-off — SMP core DONE; starting Box B (autonomous /loop)

Driving `smp-distro-plan.md` as a self-paced /loop. Merge on local-green
(= CI-green here: build both arches + hosted tests + spec-lint, all local;
pre-push hook runs SMP=2 smoke). Merge with `--admin` (no CI wait).

## SMP scheduler rework COMPLETE (F425 Phase A/B + Phase C core)
Both arches boot SMP=2 to login with online=2 and APs running real migrated
user tasks. Merged: #1662 Phase A (one switch engine + per-task IRQ fix),
#1664 B1 (rq-lock-across-switch + deferred reap), #1666 B3.1 (x86 AP online),
#1667 B3.2 (per-CPU TSS), #1668 B3.3 (per-CPU syscall slots gs:[8]/[16]),
#1669 B3.4 (x86 AP runs scheduler; root cause was AP on trampoline GDT →
ltr #GP → triple fault; fix load_kernel_gdt_for_ap), #1670 B2 (ttwu
wake-time placement select_task_rq + resched IPI), #1671 B3.5 (arm AP runs
scheduler via AP_IDLE_HOOK), #1672 B4 (affinity relocate on setaffinity),
#1673 B5 (newidle balance + cache-hot guard), #1674 Phase C on_cpu handshake
(closes ttwu-vs-switch-off race). sched miri-clean (89 tests, no UB).

Phase C remaining (irqsave legacy-lock conversion + loom model-checks) is
DEFERRED to plan §E "Deferred robustness" — no active bug (SMP stable across
all stress); sequenced after the distro/vendor work per user priority.

## NEXT (first unchecked box): Box B items 2-3 (cleanups) then Box C/D
Box B item 1 DONE (#1676): syscall coverage checker green (383/384 routed,
0 hard-fail; listns→Box C tracked). Remaining Box B:
2. Drop "Tier 1/2/3" vocab from docs/53 + CLAUDE.md (keep structure).
3. Scrub busybox mentions repo-wide (zero outside vendor/.git).
Then Box C (distro: login-shell, python3 encodings, bash serial echo, Phase
15/16) and Box D (vendor apps — tmux/htop/ripgrep/fd/jq/curl/… via real
vendor cross-builds, staged + verified running). See smp-distro-plan.md.

## DEBUG RECIPES (carry forward)
- SMP=2 boot: `OXIDE_SMP=2 ./tools/boot-smoke.sh x86 300` (BARE command — no
  pkill prefix; it aborts the shell line under set -e). arm: `... arm 400`.
- 5×SMP=2 rep: `bash /tmp/smp2rep.sh` (checks login + online=2).
- Hot-path stress: `MAXBOOTS=12 python3 /tmp/diag-hang-mon.py` (rebuilds ISO,
  hypervisor-monitored boots, dumps regs on hang). SMP=1.
- Crash (qemu exits) = triple fault → hypervisor `info registers -a`
  (-monitor unix:..., diag-hang-mon.py pattern); addr2line against
  target/x86_64-unknown-oxide-kernel/release/oxide-x86_64.
- ISO must be rebuilt: `xtask grub --arch x86_64 --build-only`.
- Multi-line git commit → `-F file`. Merge on local-green via `--admin`.
