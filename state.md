# Session hand-off — 2026-05-29

## TL;DR — RESTART CLAUDE (tool-I/O corruption active)
Autonomous production-distro build. **K1 cgroup v2 code COMPLETE**
(branch `F265-cgroup-v2`, all staged via `git add -A`, NOT committed).
8/8 hosted tests pass; x86 + aarch64 + host(debug-cgroup) all BUILD
clean. BUT this session's Bash/Read/grep output is actively corrupting
(garbled trailing bytes, duplicated lines, false-negative greps,
deleted-then-missing logs). **Restart Claude to clear the I/O layer,
then finish the 3 remaining steps below.** `cargo test` + builds were
reliable; trust those, re-verify everything else with fresh tools.

## K1 — 3 things LEFT before commit/PR (do after restart)
1. **Two file-length cap violations** (spec-lint MUST be clean):
   - `kernel/src/procfs/mod.rs` = 1022 lines (cap 1000). Move
     `ProcCgroupInode` (struct + impl, ~22 lines near line 621) into a
     new `kernel/src/procfs/cgroup_file.rs` (or append to the smaller
     `static_files.rs`); `mod` + re-export so
     `crate::procfs::ProcCgroupInode` path still resolves.
   - `tools/xtask/src/main.rs` = 1006 lines (cap 1000). Trim ~6+ lines
     (comments in the rcS/oxide-smokes heredocs) to get under 1000.
   - Re-run `cargo run -p xtask -- spec-lint` → must print
     `spec-lint: clean` (was 24 findings, 2 are these len caps; the
     other 22 are PRE-EXISTING baseline — verify against `git stash`
     if unsure, but they were there before K1).
2. **Validate the gated boot self-test ON BOTH ARCHES** (NOT yet
   confirmed — earlier parallel boots collided on KVM/port and I never
   read a clean pass; my prior "validated" note was premature):
   - `pkill -9 -f qemu-system` first (ALWAYS, between every boot).
   - `./tools/boot-capture.sh x86 'cgroup-selftest: rmdir' 200 /tmp/cg.log`
     then enable the feature: it's wired so
     `make qemu-x86 FEATURES=debug-cgroup` turns it on; boot-capture.sh
     calls plain `make qemu-x86`, so either (a) export
     `QEMU_FEATURES_X86='debug-boot debug-cgroup'` before it, or (b)
     temporarily add debug-cgroup to the in-guest oxide-smokes path
     (already present — `pre-cgroup-smoke`/`post-cgroup-smoke` block).
   - Expect klog lines: `cgroup-selftest: controllers='cpu cpuset io
     memory pids'`, `mkdir='ok'`, `pids.max='11'`, `proc-self='0::/...'`,
     `rmdir='ok'`. Read the log FILE directly (don't trust grep alone).
   - Repeat for arm: `./tools/boot-capture.sh arm ... 400 /tmp/cg-arm.log`
     (ARM TCG is slow — needs ~250-400s; x86 KVM ~30s).
   - IF self-test values are correct: K1 done.
   - IF the in-guest userspace `cat` showed EMPTY earlier but the
     gated self-test shows CORRECT values → the userspace sys_read/fd
     path for these inodes has a separate bug to chase. The gated
     self-test (kernel-side, vfs::mount::lookup + Inode::read) is the
     source of truth.
3. **Commit + PR + merge** (only after 1 & 2 green):
   - `git commit -m "feat(cgroup): F265 cgroup v2 unified hierarchy — K1 of distro roadmap"`
     (NO Co-Authored-By trailer — CI rejects it).
   - `git push -u origin F265-cgroup-v2`
   - `gh pr create` + `gh pr merge --merge --delete-branch=true`
   - `git checkout main && git pull && git branch -D F265-cgroup-v2`

## K1 cgroup v2 — what the code DOES (all saved)
- New crate `crates/kernel/cgroup/` (tree/inode/lib/tests): full v2
  hierarchy, controllers cpu/memory/io/pids/cpuset, all cgroup.* +
  per-controller files, subtree_control delegation, kill/freeze/events,
  pids fork enforcement. 8 hosted tests pass.
- VFS foundational (user rule — add Linux primitives properly):
  `Inode::mkdir`/`rmdir` (crates/kernel/vfs/src/inode.rs); added
  VfsError + Errno `Ebusy/Enospc/Enotempty`; expanded errno_from_vfs.
- `CgroupFs` (vfs::fs::FileSystem) registered in the unified mount
  table at /sys/fs/cgroup by `mount_root` — REQUIRED because open()
  resolves via vfs::mount::lookup (mounts: / dev proc tmp), not devfs
  directly. This was the fix for /sys/fs/cgroup/* → ENOENT.
- Kernel wiring: mount.rs cgroup2→mount_root; namei.rs sys_mkdir/
  mkdirat/rmdir → pseudo_mkdir/pseudo_rmdir (dispatch to Inode::mkdir/
  rmdir on the parent); procfs real /proc/<pid>/cgroup +
  /proc/self/cgroup (ProcCgroupInode); clone.rs fork inherit + pids
  EAGAIN; mod.rs sys_exit → cgroup::on_exit; lib.rs cgroup_kill_hook +
  set_signal_hook + mount_root + debug_cgroup!{cgroup_selftest()}.
- PERMANENT debug-cgroup-gated boot self-test (user rule — gate like
  existing debug-*): cgroup_selftest in lib.rs (oxide-kernel impl +
  host no-op stub), `debug_cgroup!` macro in debug_macros.rs,
  `debug-cgroup` feature in kernel/Cargo.toml (→ cgroup/debug-cgroup,
  added to debug-all). Drives the real VFS path, klogs PASS/FAIL.
- `tools/boot-capture.sh` — reliable full-serial capture (reaps qemu by
  NAME, waits for marker, exits 0). Use instead of boot-smoke.sh for
  in-guest probe validation.

## Boot-test mechanics (root-caused this session)
- Rootfs embedded in kernel via include_bytes! (crates/kernel/ext4/
  src/rootfs.rs) — `make qemu-*` rebuilds + re-embeds; bare
  `xtask rootfs` alone does NOT re-embed into the running kernel.
- Leaked qemu holds /dev/kvm (→slow TCG, timeouts) + tcp:2222
  (→"Could not set up host forwarding"). ALWAYS pkill -9 -f
  qemu-system by name; setsid-group kill leaks the qemu grandchild.
- DON'T run multiple boots in parallel — they collide on KVM/port and
  each one's pkill kills the others. Serialize boots.
- One simple shell cmd per Bash call; no parallel batches (one nonzero
  exit cancels the batch); don't chain git with ; or && to non-git.

## After K1: K1b → K2 → … (see TASKS.md)
K1b controller-enforcement depth (memory.max charge/OOM, cpu.weight/max
in sched, pids counts threads, io→block, cpuset affinity, real freeze).
K2 real mount (MS_BIND/REC/MOVE/propagation, pivot_root). K3 mount-ns.
K4 rtnetlink RTM_GETLINK. Track L shared libs. D6 systemd-musl. D7 drop
busybox. Track P (RPM/dnf, multi-user). Planning PR #1348 already merged.

## Direction
Production drop-in Linux distro on musl. No hacks/stubs/placeholders.
Fix each kernel gap in the SAME PR. Add missing Linux primitives
properly (user rule). Permanent debug gates like existing debug-* (user
rule). Each task = own PR, both-arch boot smoke, spec-lint clean, branch
deleted on merge. Autonomous — don't stop at phase seams. Tool-I/O
corruption is the one genuine blocker → restart Claude to clear it.
