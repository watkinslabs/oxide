# Handoff — hwdb sysinit blocker FIXED; boot advances to a post-hwdb wait

Main = `8537de19`. Goal: console login → live-gnome.

## ★ BREAKTHROUGH: the hwdb blocker is FIXED (was gating all 3 goals)
For many sessions sysinit stalled ~90s at `systemd-hwdb-update` (looked like a
userspace "spin"). Real cause: **ext4 committed the journal PER metadata op**
(a full commit + 3 `dev.flush()` barriers each), so every fs-heavy service was
20-90× too slow. Two merged, boot-verified fixes:
- **B679 / PR#2880** — batch per-page writeback into ONE commit (was N commits
  for an N-page flush). 800→332 write-ops for 40 pages.
- **B681 / PR#2883** — jbd2-style **cross-operation running transaction**:
  `begin_batch()` on the root fs (init_from_dev) makes the shadow persist across
  `run_journaled` scopes; ops JOIN one txn; drained by `commit_batch()` on
  fsync/sync/msync/512-block threshold. Per-op undo frame → a failed op rolls
  back without corrupting prior batched ops (data=writeback: file data direct,
  metadata batched; reads stay consistent — resolve_pblock/read_inode are
  shadow-aware). Hosted `tests/batch_mode_image`: 20 creates → 1 commit + failed-
  op rollback proven. Full ext4 suite (37 files) green.

**Boot A/B (x86_64 KVM):** hwdb tid 4135 now runs ONCE (was dozens of spin
samples), no O(n²) writeback, no fs write errors, early sysinit all completes.
hwdb may still exit status=1 (its own logic / missing hwdb.d input) — non-fatal,
sysinit continues.

## NEXT blocker — a SEPARATE post-hwdb 100%-KVM spin (confirmed 2026-07-09)
After hwdb fails+reaps (~82s, debug-boot), a task **busy-spins at 100% CPU**
(`qemu_regs`/gdb cannot async-interrupt = classic KVM spin, same signature hwdb
had). So batching FIXED hwdb but a DIFFERENT service now spins. Services that
"Starting…" but never "Finished" in the window: `systemd-journal-flush`,
`systemd-random-seed`, `systemd-userdbd`, `sys-kernel-config.mount`. The
debug-wakelat boot reached 144s in periodic ~500ms WLBLK waits (tid 4123
journald + init) — so it's slow-progressing, not hard-hung.

Ruled out for THIS spin: the old `tmpfiles↔userdbd` AF_UNIX accept/epoll theory —
that path now looks correct (`UnixRegistry::connect` net/src/unix_sock/listener.rs:151
pushes accept_q + notify_subs; listener poll() returns POLL_IN from non-empty
accept_q net/src/sock/io.rs:207,229; register_subs wires epoll net/src/sock/ops.rs:33,207).

**PINNED (2026-07-09): it is an IDLE-WAIT hang, NOT a spin and NOT a stall.**
Chased two red herrings — ruled BOTH out with evidence:
- NOT a spin: `[KERNIP]` (kernel-mode RIP sampler, added to arch-irq dispatch.rs)
  shows no repeated kernel RIP; `[USERIP]` counts all ≤6. Neither mode spins.
- NOT a commit/undo stall: `[COMMIT n=]` probe showed only **5 commits total**
  (max 9 blocks) — commits are tiny/rare now, NOT near the `[WLTICKGAP]`s. The
  `[WLTICKGAP]` "gaps" of a consistent **~7.5s** are **tickless-idle**: the CPU
  halts until the next ~7.5s timeout because everything is BLOCKED. journald (tid
  4123) sits in epoll_wait (sc232); systemd (init) polls every 500ms. Boot runs
  183-368s, **no login** — a genuine hang waiting on a service that never
  completes. Only 8 WAEXT total (last 12s) → ext4 writeback fine.

Landed alongside: **undo frame O(n²)→O(n log n)** (BTreeMap-keyed, mount.rs/
core.rs) — a real defensive fix (a big op staging many blocks no longer linear-
scans the undo under the state lock) but NOT the boot blocker (it didn't change
the gaps; hwdb's writeback stages only ~tens of metadata blocks, data writes
direct).

**Real blocker = a sysinit oneshot idle-hangs.** Candidates (Starting, never
Finished): systemd-journal-flush, systemd-random-seed, systemd-userdbd,
sys-kernel-config.mount. Late-active tids: 4141 (statx sc332 @234s), 4146 (fstat
sc5 @309s) — a fs walker (tmpfiles?) still doing work, plus the hung oneshot.

**First task (debug-boot won't help — its journal echo STOPS when systemd goes
idle at ~86s):** the live tid is **4141** (a fs walker: `statx` sc332 @234s,
`fstat` sc5 @309s — active for MINUTES, slow-progressing). Trace IT in
debug-wakelat: add a >50ms timing probe to `sys_statx`/`sys_newfstatat` +
the ext4 path-lookup (`lookup_path`/`resolve`) — is EACH statx slow (an ext4
path-resolution / large-dir / synchronous-read cost) or does the service SLEEP
~7.5s BETWEEN statx calls (a userspace retry — then find what it retries on)?
The consistent 7.5s tickless-idle cadence favors the userspace-retry case: the
walker does a statx, blocks 7.5s waiting for something, retries. Identify what
tid 4141 is (map its exe via `[USERIP]` name / /proc) and what it waits on
between statx calls. journald idle-in-epoll is NORMAL, not the bug.

## First command next session
`cd /home/nd/oxide/kernel && git log --oneline -3`  # confirm main @ 8537de19
Then boot: `mcp__qemu__qemu_start arch=x86_64 accel=kvm` → run_until past hwdb →
identify the stuck service.

## Notes
- aarch64: change is arch-neutral (ext4/syscalls), compiles; arm BOOT untestable
  here (no packed arm rootfs image — `images` repo, needs sudo).
- Pre-push hook `make smoke` can't reach login yet (the post-hwdb blocker), so
  ext4-only, boot-A/B-verified pushes used `SKIP_SMOKE=1`.
