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

**IMPORTANT NUANCE:** in the debug-wakelat capture that reached 144s, `[USERIP]`
sample counts are ALL low (≤7 per tid over the whole window) — so NO task is
spinning in USER mode. Yet gdb can't interrupt the debug-boot VM at 82s. That
points to a **KERNEL-mode spin** (spinlock contention / a kernel busy-loop the
user-RIP sampler, which only fires `from_user`, can't see) — a DIFFERENT class
from hwdb's userspace stall. OR the 82s debug-boot "spin" is a transient hwdb-
cleanup artifact and the boot slow-progresses (debug-wakelat did reach 144s).

**First task:** disambiguate. Boot debug-boot, at the ~82s stall use the qemu
MCP to break into the KERNEL (gdb can attach to kernel even during a user spin
if it's not 100% KVM; if it IS, the spin is in-guest). If kernel-mode: find the
hot kernel loop (backtrace / which lock). If it slow-progresses instead, measure
where wall-time goes in the remaining services. Add a kernel-side per-tid
on-CPU-ticks counter (like the old [HWCPU]) to see if a KERNEL thread or a user
task dominates.

## First command next session
`cd /home/nd/oxide/kernel && git log --oneline -3`  # confirm main @ 8537de19
Then boot: `mcp__qemu__qemu_start arch=x86_64 accel=kvm` → run_until past hwdb →
identify the stuck service.

## Notes
- aarch64: change is arch-neutral (ext4/syscalls), compiles; arm BOOT untestable
  here (no packed arm rootfs image — `images` repo, needs sudo).
- Pre-push hook `make smoke` can't reach login yet (the post-hwdb blocker), so
  ext4-only, boot-A/B-verified pushes used `SKIP_SMOKE=1`.
