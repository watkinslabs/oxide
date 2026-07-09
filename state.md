# Handoff — sysinit blocker = pivot_root (service mount-namespacing); 2/3 fixed

Main = `98750130`. Goal: console login → live-gnome. 10 PRs merged this session.

## ★★ THE REAL SYSINIT BLOCKER: `pivot_root` (found via systemd debug log)
After hwdb was fixed (below), the boot deadlocks in sysinit (`systemctl list-jobs`
= 0 running / 36 waiting). The technique that finally cracked years of fog: boot
with **`systemd.log_level=debug`** on the kernel cmdline → systemd prints its own
job/mount reasoning. It showed the chain `tmpfiles-setup-dev-early → sysusers →
tmpfiles-setup → …` and **`Failed to pivot root to '/run/systemd/mount-rootfs':
Invalid argument`** — every service using mount-namespacing (`ProtectSystem=`,
etc.) can't enter its private rootfs, so it hangs and sysinit deadlocks.
(The userdbd / systemd-event-loop / varlink theories from earlier were RED
HERRINGS — userdbd starts fine; probing with `systemctl` PERTURBS the deadlock.)

**pivot_root had 3 Linux-faithful bugs — FIXED in B683/PR#2890:**
1. new_root resolved by CROSSING into the mount grafted there (→ ambiguous root
   dentry) not the mountpoint dentry `mount_exact_at` needs → "new_root not a
   mount root". Fixed via new `mount::mountpoint_dentry_of`.
2. `MS_REC` propagation was a no-op stub → `make-rslave /` only changed one mount.
   Fixed via `set_propagation_recursive`.
3. propagation-change target had the same crossing bug → silent no-op. Fixed.
Verified: those EINVALs are gone; 8+ more services now Finish.

**REMAINING pivot_root EINVAL (the last piece): `put_old mount is SHARED`.**
Traced precisely: `po_mnt=140 nr_id=140 root_id=120` — the service rootfs mount
(140) is genuinely SHARED when Linux requires it PRIVATE. systemd builds it as a
**detached `open_tree(OPEN_TREE_CLONE|AT_RECURSIVE)` tree** (ops on
`/proc/self/fd/4`) then `move_mount`s it to /run/systemd/mount-rootfs. A detached
clone must be PRIVATE; ours ends up SHARED — either `open_tree(CLONE)` clones the
propagation of the rshared `/` (should reset to private), or `move_mount` grafts
it under shared `/run` and `propagate_mount` shares it (a moved detached tree must
NOT join the dest peer group). **First task: fix open_tree(CLONE)/move_mount so
the detached/moved service-rootfs stays PRIVATE.** Look at the open_tree +
move_mount handlers + `propagate_mount` (vfs/src/mount/propagation.rs) — skip
peer-group sharing for a detached/moved tree, and have `open_tree(OPEN_TREE_CLONE)`
set the clone PRIVATE. Then the `put_old SHARED` EINVAL clears and pivot_root
succeeds → services start → sysinit completes → getty/login.

DEBUG: gated `[PIVOT-EINVAL]`/`[PIVOT-SYSCALL]` (debug-mnt) + `[MNTCREATE]` probes
are IN-TREE to pin this. Boot `features=debug-mnt`; add `systemd.log_level=debug`
to `tools/xtask/src/image_qemu/x86_64.rs:23` cmdline for systemd's view (REVERT
before shipping — I reverted it). Live debug-shell works over ttyS0 via
`qemu_send_serial` BUT any `systemctl` perturbs the deadlock — use `/proc` reads
or kernel traces. `/proc/<pid>/{syscall,wchan,stack}` are stubbed; use status
State + fd.

## hwdb blocker — FIXED (was gating all 3 goals for many sessions)
Sysinit stalled ~90s at `systemd-hwdb-update`. Real cause: **ext4 committed the
journal PER metadata op** (commit + 3 `dev.flush()` each) → every fs-heavy
service 20-90× too slow. Fixes (all merged, boot-verified, hosted-tested):
- **B679/#2880** batch per-page writeback → 1 commit.
- **B681/#2883** jbd2-style cross-op running transaction (fsync/sync/msync/512-blk
  drained; per-op undo rollback).
- **B682/#2886** undo frame O(n²)→O(n log n) + `[KERNIP]` sampler.
hwdb now runs ONCE (was dozens of spin samples). Ruled out (evidence): cacheability
(PAT/MTRR=WB), TLB, AVX/XSAVE (F698), page faults. See memory
[[hwdb-blocker-ext4-writeback-commits]].

## First command next session
`cd /home/nd/oxide/kernel && git log --oneline -3`  # confirm main @ 98750130
Then: fix open_tree(CLONE)/move_mount propagation (make the detached service
rootfs PRIVATE); boot `features=debug-mnt` + `systemd.log_level=debug`; watch the
`put_old SHARED` PIVOT-EINVAL clear → Reached target sysinit → getty/login.

## Notes
- aarch64: all fixes arch-neutral (ext4/vfs-mount/syscalls); compile; arm BOOT
  untestable here (no packed arm rootfs image).
- Pre-push `make smoke` can't reach login yet → ext4/mount-only, boot-A/B-verified
  pushes use `SKIP_SMOKE=1`.
