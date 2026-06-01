# Session hand-off

## Headline
**systemd 259 PID1 reaches "Activating default unit: default.target" on oxide** —
it boots through console/chroot/DSR/mount_setup/manager_new, loads its unit
name-map from the staged unit tree, and now EXECUTES its startup transaction.
main clean @ #1479. Next: watch the transaction run (fork+exec services) and
fix the cascade gaps to a getty, then flip default PID1 to systemd.

## F350 fixes merged this session
| PR | Gap (Linux-correct fix) | systemd reaches |
|----|----|----|
| #1471 | /dev/console honors O_NONBLOCK | past first console read |
| #1473 | name_to_handle_at + /proc/<pid> magic symlinks | past running_in_chroot() |
| #1475 | /dev/console poll() readiness | past DSR terminal probe |
| #1476 | build + stage systemd-executor binary | past manager_new() |
| #1478 | **EPOLLET edge-trigger** + signalfd/timerfd/eventfd poll() | sd-event loop blocks (no epoll spin) |
| #1479 | minimal systemd unit tree (target chain + console-shell) | Activating default.target |
(plus #1472 xtask stats recovery, #1474/#1477 doc checkpoints)

## NEXT — F350 #6+: the transaction-execution cascade (one PR each, NO HACKS)
Re-recon (kernel/src/smoke/elf.rs PID1=/lib/systemd/systemd + SYSTEMD_LOG_LEVEL=debug
envp ~L795), boot, watch systemd EXECUTE default.target → sysinit→basic→console-shell.
Known/likely gaps, fix Linux-correct:
1. **ext4 symlink-create EIO** — systemd preset/enable does symlinkat in
   /etc/systemd/system → "I/O error". Implement real symlink-inode create in
   crates/kernel/ext4 (was never implemented; mkdir works, symlink doesn't).
2. **cgroup2 controller files** — systemd starts services into cgroup slices,
   writing cgroup.subtree_control etc. syscall-anal.md flags this as the top
   semantic gap. Make /sys/fs/cgroup a real hierarchy (crates/kernel/cgroup).
3. **service fork+exec via systemd-executor** — double-fork through the executor,
   cgroup attach, stdio=/dev/console. Surfaces exec/stdio paths.
4. **5 unwired syscalls** 142/251/252/314/315 (sched_setattr/ioprio) → ENOSYS
   today (validated). Non-fatal for systemd but real — wire them.
5. "Too many messages being logged to kmsg, ignoring" — systemd's own debug-log
   rate limit (non-fatal); if it hides progress, drop SYSTEMD_LOG_LEVEL.
When systemd reaches a getty/login prompt → flip default PID1 busybox→systemd
(elf.rs) + update the login smoke. THEN distro track: rip busybox→bash+coreutils,
Limine→GRUB, OXIDE distro.

## Diagnosis recipes (proven)
- Recon: elf.rs PID1=/lib/systemd/systemd (line ~639 lookup + ~658 argv) +
  envp SYSTEMD_LOG_LEVEL=debug (build_user_stack ~L795). REVERT before commit.
- PID1 syscall trace: at oxide_syscall_dispatch (kernel/src/syscalls/mod.rs ~L569),
  gate `c.vtid.load(Acquire)==1`, klog nr. SAFE. **NEVER klog in sys_openat
  (wedges boot under SMP — PROVEN).**
- epoll readiness: temp trace in crates/kernel/fs/src/epoll.rs scan_once (fd+ino+
  ev+poll+rdy) — found the EPOLLET spin (mountinfo always-POLLIN + EPOLLET).

## CRITICAL harness rules
- dev shell is `set -e`: guard EVERY pgrep/grep/ss/pkill/[ test ] with `|| true`
  or the whole cmd aborts with NO file created. Pre-boot pkill MUST be
  `pkill -9 -f qemu-system 2>/dev/null || true; sleep 2` — without || true the
  boot compound dies before make.
- Stale qemu squats port 2222 → boot dies "Could not set up host forwarding".
  ALWAYS clear before boot; pkill -9 -f qemu-system-x86_64 only at poll END;
  NEVER `pkill -f qemu` (self-kill).
- Boots: bare `make` in run_in_background; poll output-file in a SEPARATE guarded
  bg cmd; rootfs rebuild runs ~90s BEFORE qemu — wait for systemd log lines, not
  file existence.
- Gate: `git push --dry-run origin <branch>` runs the pre-push hook = both-arch
  boot-smoke WITHOUT pushing; on "PASS on both arches" → SKIP_SMOKE=1 real push +
  `gh pr merge --merge --delete-branch=true` (that ONE cmd deletes local+remote —
  NO separate `git branch -D`).
- spec-lint clean before commit; main.rs (999) + procfs/mod.rs near 1000-cap —
  count after edits. Branch per change; explicit git add. NEVER add
  vendor/*/install-*/lib/pkgconfig. Tree-wide cargo fmt NOT wanted (stash+drop).
- Default PID1 still busybox → login smoke green; flip to systemd only at getty.
- syscall-anal.md (root): validated broadly accurate; 5 unwired syscalls real.
