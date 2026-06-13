# state — session hand-off

TWO branches in flight, both committed-local + **NOT pushed**. Counters in
`metadata/index.md` (AUTHORITATIVE — read+bump per branch).

**Dev-loop gotchas (cost hours):** x86 boots ALWAYS `OXIDE_QEMU_KVM=1` (TCG
smp>1 reads as a hang); stale qemu holds the disk write-lock → find via
`fuser <img>` + `kill -9` (`pkill -x` misses the 15-char name); `KEEP_LOG`
copies only on smoke EXIT.

## Branch C90-build-namespacing (CURRENT, 14 commits) — build system + structure

A complete per-build artifact system + a big structure de-sprawl. All verified
building, spec-lint clean, no-id paths boot-tested (KVM no-id reaches systemd
Default Target in 4.6s).

- **`xtask --id <slug>`**: every build isolated in ONE folder `target/builds/<id>/`
  (ISO + kernel ELF snapshot + root/home/nvme/ahci images together). No-id ≡ the
  `default` namespace — there is NO "blobs" dir anymore (`kernel/blobs` and the
  whole `kernel/` top-level dir DELETED).
- **`xtask path <kind> --arch <a> [--id <id>]`** = the SINGLE path resolver
  (root-img/home-img/nvme/ahci/iso/elf/build-dir). The smoke scripts
  (run-smokes.sh, accept.py) query it instead of hardcoding.
- **Content-addressed rootfs cache** `target/rootfs-cache/` (FNV of inputs):
  kernel-only iter reuses the image (`cp`, ~0.05s) vs restage (~10s).
- **Incremental kernel**: compiles in shared `target/` then snapshots the ELF
  into the namespace (no fresh CARGO_TARGET_DIR / from-scratch per id).
- **`xtask gc`** (+ `make clean-builds`): reclaims dead `target/builds/<id>` +
  LRU-trims the cache; protects builds with a live `.live` PID marker + the
  `default` namespace. Hard rmtree guard (validate + resolved-parent==root).
- **`--rebuild-vendor[=pkg,…]`** re-runs `vendor/<pkg>/build.sh`.
- **qemu-mcp multi-instance**: `qemu_start(name,…, rebuild_vendor/rebuild_rootfs/
  skip_rootfs/clean_kernel)` builds via `xtask grub --id` + launches off
  `target/builds/<build_id>/`; per-instance free gdb/ssh ports; instance registry
  (`instance_id` on every tool); writes `.live`; `qemu_list`/`qemu_gc`. GDB
  validated (namespaced ELF symbols + free port). FastMCP `instructions=` added
  so the AI client gets the model.
- **Structure**: `terminfo`→`vendor/terminfo`, `vdso`→`crates/kernel/syscalls/vdso`
  (build output gitignored next to its `.S`), `link/`→the two `kernel-bin` crates.
- Reclaimed ~40GB of `target/` cruft this session.

OPEN/optional on C90: (a) flatten the ELF snapshot to one flat
`target/builds/<id>/oxide-<arch>` + delete the transient `grub-stage/` scratch
(proposed, not done); (b) rename `targets/`→`kernel-targets/` (kills the
`target/` clash; only `cmds.rs:97-98` + docs ref it); (c) a LIVE qemu-mcp
2-instance shakeout (wiring verified by inspection, never run live — MCP was
disconnected); (d) PUSH — but C90 touches crates/ so the pre-push smoke fires,
and the `oxide login:` marker depends on the serial-getty fix that lives on
B127, not here (see below) — resolve before pushing.

## Branch B127-smp-load-balance (5 commits) — SMP fix, BLOCKED

The user's actual goal thread. Committed, NOT pushed. Three correct, verified
fixes; one real kernel blocker remains.
- ✅ SMP work distribution (placement_load incl. running task; fork→
  wake_up_new_task→select_task_rq; local-only wakes routed through ttwu).
- ✅ serial login on ttyS0 (/dev/console = video VT, so headless serial had no
  getty — added serial-getty-ttyS0.service). THIS is the `oxide login:` marker
  fix C90 lacks.
- ✅ fork child woken LAST (was runnable on an AP before clone finished init).
- ❌ **BLOCKER — SMP>1 still crashes** non-deterministically under load. Root
  cause (3-agent analysis, file:line in the B127 state): (1) **no x86 cross-CPU
  TLB shootdown** — all user tasks share one page-table tree, every PTE change
  flushes only the LOCAL TLB (`mm-pmm/user_as.rs:626`, `mm-vmm/address_space.rs:
  786/809`), never IPIs others → stale TLB on the other CPU (aarch64 immune,
  `tlbi …is` broadcasts). Fix = `native_flush_tlb_others` IPI. (2) **no IST** for
  any fault vector (`idt.rs:148` all ist=0) → #PF/#DF triple-fault hazard.
  Default qemu SMP kept at 1 until fixed.
- Also unresolved: arm SMP=2 boot stalls at "Queued start job for default target"
  before the getty (every arm run this session).

## First command next session
```
cd /home/nd/oxide2 && git branch --show-current && git log --oneline -3
```
Then decide: finish/push C90 (handle the pre-push smoke vs serial-getty), or do
the B127 x86 TLB-shootdown + IST work (the real SMP blocker, the user's goal).
