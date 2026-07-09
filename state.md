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

**IDENTIFIED via live debug-shell (systemctl works over ttyS0):** `list-jobs` =
**0 running / 36 waiting** = a sysinit deadlock. The one "activating" unit is
**systemd-tmpfiles-setup.service** (PID 27, State S sleeping, blocked on userdb
**socket fd 30** = `/run/systemd/userdb/io.systemd.Multiplexer`). **systemd-userdbd
.service is "waiting" (never dispatched)** though its `After=` (userdbd.socket,
system.slice, journald.socket) are ALL satisfied. **`systemctl start
systemd-userdbd.service` → userdbd active + tmpfiles unblocks.** ⇒ NOT a deps/
ordering deadlock, NOT the old GetMemberships-varlink theory — **systemd's main
event loop isn't being woken to dispatch its ready job queue** after the
socket-activation queues userdbd (a manual dbus command injects an event that
wakes it and it runs). Full detail + next-trace in memory
[[desktop-blocker-tmpfiles-userdbd]] (UPDATE 2026-07-09d).

**NARROWED FURTHER (same session) — NOT a kernel epoll-wakeup bug:**
- `sys_epoll_wait` (fs/epoll.rs:413) already re-scans every **20ms** even for
  timeout<0, so systemd's loop re-iterates frequently regardless of targeted
  wakes. AF_UNIX listener→epoll notify is code-verified correct (same
  PollSubscribers; notify bumps gen+wakes) AND systemd DID queue userdbd (it saw
  the connect). So the kernel wake path works.
- **⚠ PROBING PERTURBS IT:** ANY `systemctl` at the deadlock injects a dbus fd
  event that resumes systemd's whole run queue (measured: querying userdbd made
  it go active). So `systemctl start userdbd` "fixing" it was NOT userdbd-
  specific. Prior sessions' systemctl probing was self-defeating. **Diagnose ONLY
  with /proc reads or a kernel-side trace, never systemctl.**
- ⇒ **The stall is systemd's JOB ENGINE not advancing its run queue after hwdb
  FAILS (list-jobs = 0 running / 36 waiting — the whole queue frozen, not just
  userdbd), until an external event re-triggers it.** systemd DID reap hwdb
  (`[wait4 reap] reaped_tid=39`), so SIGCHLD→reap works; but job-completion →
  re-run-queue doesn't re-fire on its own.

**First task (non-perturbing):** kernel-trace pid-1/init's syscalls across the
window where hwdb exits and the queue freezes — gate a probe on `current().tgid==1`
(init/systemd; [USERIP] shows it as name "init", tid 3235774466) in the syscall
dispatch, logging epoll_wait(timeout,nready), clone/fork, and the signalfd
read/rt_sigreturn around the hwdb SIGCHLD. Question: after reaping hwdb, does
systemd stop calling clone (never tries to fork the next service) → job-engine
frozen; or does it loop epoll_wait(20ms)→0 forever. If frozen post-reap, suspect
the SIGCHLD/waitid completion or the child-exit → parent-notify path leaves
systemd's manager without re-enabling its run-queue defer (a subtle exit-signal/
si_code or wait-status detail systemd keys off). Cross-check vs [[hwdb-blocker-ext4
-writeback-commits]] (hwdb now EXITS status=1 fast instead of timing out — the
FAILURE path is newly exercised; the freeze may be specific to handling a FAILED
oneshot's exit). Full detail: memory [[desktop-blocker-tmpfiles-userdbd]] UPDATE
2026-07-09d. `/proc/<pid>/{syscall,wchan,stack}` are stubbed — use status State + fd.

## First command next session
`cd /home/nd/oxide/kernel && git log --oneline -3`  # confirm main @ 8537de19
Then boot: `mcp__qemu__qemu_start arch=x86_64 accel=kvm` → run_until past hwdb →
identify the stuck service.

## Notes
- aarch64: change is arch-neutral (ext4/syscalls), compiles; arm BOOT untestable
  here (no packed arm rootfs image — `images` repo, needs sudo).
- Pre-push hook `make smoke` can't reach login yet (the post-hwdb blocker), so
  ext4-only, boot-A/B-verified pushes used `SKIP_SMOKE=1`.
